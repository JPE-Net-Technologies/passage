// tests/auth.token.route.test.ts — POST /token (authorization_code + refresh_token) end-to-end.
//
// `openid-client` is module-mocked so the real federation + grant + token + session default seams
// run end-to-end: /authorize → /callback mints a Passage code, then POST /token redeems it into
// Passage-signed tokens and rotates refresh tokens. Singletons are reset in beforeAll so the
// route's own initialize() calls are the ones observed.
import {describe, it, expect, beforeAll, mock} from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import request from 'supertest';
import {openidClientMock} from './openid-client.mock';

mock.module('openid-client', openidClientMock);

const {localKMS} = await import('../services/kms-local');
const {upstreamOidc} = await import('../services/upstream/oidc-client.service');
const {jwksService} = await import('../services/oidc/jwks.service');
const {sessionService} = await import('../services/oidc/session.service');
const {federationService} = await import('../services/oidc/federation.service');
const {tokenService} = await import('../services/oidc/token.service');
const {grantService} = await import('../services/oidc/grant.service');
const {userInfoService} = await import('../services/oidc/userinfo.service');
const {createApp} = await import('../app');
const {buildTestConfig} = await import('./test-utils');

const oidcProvider = () => ({
  name: 'oidc-x',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: 'oidc-x', client_id: 'broker'},
  OidcConfig: {
    supported_auth_flows: ['authorization_code'],
    issuer: 'http://localhost:3000/oidc-x',
    upstream_issuer: 'http://localhost:8080/realms/mock',
    upstream_client_id: 'broker',
    upstream_scopes: ['openid', 'profile'],
  },
});

// A real PKCE pair: a 43-char verifier and its S256 challenge.
const VERIFIER = 'a'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const decodeJwt = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

let app: any;

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-token-'));
  fs.writeFileSync(path.join(dir, 'template.secrets.yaml'), 'Secrets: []\n');
  localKMS.reset();
  await localKMS.initialize({keystorePath: path.join(dir, 'kms-local.keystore'), secretsPath: path.join(dir, 'template.secrets.yaml')});
  upstreamOidc.reset();
  jwksService.reset();
  sessionService.reset();
  federationService.reset();
  tokenService.reset();
  userInfoService.reset();
  grantService.reset();
  app = await createApp(buildTestConfig({providers: {providers: [oidcProvider() as any]}}));
});

/** Drive /authorize then /callback (with a PKCE challenge) to obtain a redeemable Passage code. */
async function obtainCode(): Promise<string> {
  const begin = await request(app).get('/oidc-x/authorize').query({
    response_type: 'code', client_id: 'downstream', redirect_uri: 'https://app.test/cb',
    scope: 'openid', state: 'dstate', code_challenge: CHALLENGE, code_challenge_method: 'S256',
  }).expect(303);
  const sessionId = new URL(begin.headers.location).searchParams.get('state')!;
  const cb = await request(app).get('/oidc-x/callback').query({state: sessionId, code: 'upstream-code'}).expect(303);
  return new URL(cb.headers.location).searchParams.get('code')!;
}

describe('POST /:provider/token — authorization_code', () => {
  it('redeems a PKCE code into verifiable, re-minted Passage tokens', async () => {
    const code = await obtainCode();
    const res = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'authorization_code', code, redirect_uri: 'https://app.test/cb',
      client_id: 'downstream', code_verifier: VERIFIER,
    }).expect(200);

    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body.token_type).toBe('Bearer');
    expect(typeof res.body.access_token).toBe('string');
    expect(typeof res.body.refresh_token).toBe('string');
    expect(typeof res.body.id_token).toBe('string');
    expect(res.body.scope).toBe('openid');

    // The access token verifies against Passage's own keys, is issued by this provider authority,
    // and carries a broker-minted sub (NOT the upstream 'u-1' from the mock).
    const claims = await tokenService.verify(res.body.access_token);
    expect(claims.iss).toBe('http://localhost:3000/oidc-x');
    expect(claims.sub).not.toBe('u-1');
    expect(decodeJwt(res.body.id_token).sub).toBe(claims.sub);
  });

  it('rejects a code redeemed with the wrong PKCE verifier', async () => {
    const code = await obtainCode();
    const res = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'authorization_code', code, redirect_uri: 'https://app.test/cb',
      client_id: 'downstream', code_verifier: 'b'.repeat(43),
    }).expect(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('400s a malformed token request', async () => {
    const res = await request(app).post('/oidc-x/token').type('form').send({grant_type: 'authorization_code'}).expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('invalid_grant for an unknown code', async () => {
    const res = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'authorization_code', code: 'nope', redirect_uri: 'https://app.test/cb',
      client_id: 'downstream', code_verifier: VERIFIER,
    }).expect(400);
    expect(res.body.error).toBe('invalid_grant');
  });
});

describe('POST /:provider/token — refresh_token', () => {
  it('rotates the refresh token and detects reuse, killing the family', async () => {
    const code = await obtainCode();
    const first = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'authorization_code', code, redirect_uri: 'https://app.test/cb',
      client_id: 'downstream', code_verifier: VERIFIER,
    }).expect(200);
    const rt1 = first.body.refresh_token;

    const refreshed = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'refresh_token', refresh_token: rt1, client_id: 'downstream',
    }).expect(200);
    expect(refreshed.body.refresh_token).not.toBe(rt1); // rotated to a new token
    const rt2 = refreshed.body.refresh_token;

    // Replaying the original (now revoked) token is detected as reuse.
    const reuse = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'refresh_token', refresh_token: rt1, client_id: 'downstream',
    }).expect(400);
    expect(reuse.body.error).toBe('invalid_grant');

    // Reuse revoked the whole family, so the rotated token is dead too.
    const dead = await request(app).post('/oidc-x/token').type('form').send({
      grant_type: 'refresh_token', refresh_token: rt2, client_id: 'downstream',
    }).expect(400);
    expect(dead.body.error).toBe('invalid_grant');
  });
});
