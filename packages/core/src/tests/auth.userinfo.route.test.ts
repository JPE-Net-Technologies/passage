// tests/auth.userinfo.route.test.ts — GET|POST /userinfo end-to-end.
//
// Runs the real default seams: authorize → callback → token mints an access token + remembers the
// user's claims, then /userinfo returns them for a valid Bearer token. Singletons are reset in
// beforeAll so the route's own initialize() calls (incl. userInfoService) are the observed ones.
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
const {userInfoService} = await import('../services/oidc/userinfo.service');
const {grantService} = await import('../services/oidc/grant.service');
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

const VERIFIER = 'a'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');
const decodeJwt = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

let app: any;

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-uinfo-'));
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

/** Run authorize → callback → token and return a fresh Passage access token. */
async function accessToken(): Promise<string> {
  const begin = await request(app).get('/oidc-x/authorize').query({
    response_type: 'code', client_id: 'downstream', redirect_uri: 'https://app.test/cb',
    scope: 'openid', state: 'dstate', code_challenge: CHALLENGE, code_challenge_method: 'S256',
  }).expect(303);
  const sessionId = new URL(begin.headers.location).searchParams.get('state')!;
  const cb = await request(app).get('/oidc-x/callback').query({state: sessionId, code: 'upstream-code'}).expect(303);
  const code = new URL(cb.headers.location).searchParams.get('code')!;
  const tok = await request(app).post('/oidc-x/token').type('form').send({
    grant_type: 'authorization_code', code, redirect_uri: 'https://app.test/cb', client_id: 'downstream', code_verifier: VERIFIER,
  }).expect(200);
  return tok.body.access_token;
}

describe('GET|POST /:provider/userinfo', () => {
  it('returns the user claims (with the minted sub) for a valid access token via GET', async () => {
    const at = await accessToken();
    const res = await request(app).get('/oidc-x/userinfo').set('Authorization', `Bearer ${at}`).expect(200);
    expect(res.body.sub).toBe(decodeJwt(at).sub); // userinfo sub matches the access token's sub
    expect(res.body.sub).not.toBe('u-1');          // never the raw upstream sub
  });

  it('also serves the claims via POST', async () => {
    const at = await accessToken();
    const res = await request(app).post('/oidc-x/userinfo').set('Authorization', `Bearer ${at}`).expect(200);
    expect(res.body.sub).toBe(decodeJwt(at).sub);
  });

  it('401s with a bare Bearer challenge when no token is supplied', async () => {
    const res = await request(app).get('/oidc-x/userinfo').expect(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(res.body.error).toBe('invalid_request');
  });

  it('401s invalid_token for a malformed access token', async () => {
    const res = await request(app).get('/oidc-x/userinfo').set('Authorization', 'Bearer not.a.valid.token').expect(401);
    expect(res.headers['www-authenticate']).toBe('Bearer error="invalid_token"');
    expect(res.body.error).toBe('invalid_token');
  });
});
