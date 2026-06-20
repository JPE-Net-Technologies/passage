// tests/auth.logout.route.test.ts — RP-Initiated Logout end-to-end (GET + POST).
//
// Drives the real default seams (tokenService.verify + clientRegistry) end-to-end: a login mints a
// real id_token used as the id_token_hint, and the registered post_logout_redirect_uri is honored.
// Singletons (incl. logoutService) are reset in beforeAll so the route's own initialize() is observed.
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
const {logoutService} = await import('../services/oidc/logout.service');
const {clientRegistry} = await import('../services/oidc/client-registry.service');
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

const LOGOUT_URI = 'https://app.test/logout';
const VERIFIER = 'a'.repeat(43);
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url');

let app: any;

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-logout-'));
  fs.writeFileSync(path.join(dir, 'template.secrets.yaml'), 'Secrets: []\n');
  localKMS.reset();
  await localKMS.initialize({keystorePath: path.join(dir, 'kms-local.keystore'), secretsPath: path.join(dir, 'template.secrets.yaml')});
  upstreamOidc.reset();
  jwksService.reset();
  sessionService.reset();
  federationService.reset();
  tokenService.reset();
  userInfoService.reset();
  logoutService.reset();
  clientRegistry.reset();
  grantService.reset();
  app = await createApp(buildTestConfig({
    providers: {providers: [oidcProvider() as any]},
    clients: {clients: [{
      client_id: 'downstream', client_type: 'public',
      redirect_uris: ['https://app.test/cb'], post_logout_redirect_uris: [LOGOUT_URI],
    }]},
  }));
});

/** Run authorize → callback → token and return a fresh Passage id_token (for use as id_token_hint). */
async function idTokenHint(): Promise<string> {
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
  return tok.body.id_token;
}

describe('GET|POST /:provider/end_session', () => {
  it('redirects (303) to a registered post_logout_redirect_uri with state, via GET', async () => {
    const idt = await idTokenHint();
    const res = await request(app).get('/oidc-x/end_session').query({
      id_token_hint: idt, post_logout_redirect_uri: LOGOUT_URI, state: 'xyz',
    }).expect(303);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe(LOGOUT_URI);
    expect(loc.searchParams.get('state')).toBe('xyz');
  });

  it('also honors POST (form body)', async () => {
    const idt = await idTokenHint();
    const res = await request(app).post('/oidc-x/end_session').type('form').send({
      id_token_hint: idt, post_logout_redirect_uri: LOGOUT_URI,
    }).expect(303);
    expect(new URL(res.headers.location).origin + new URL(res.headers.location).pathname).toBe(LOGOUT_URI);
  });

  it('confirms (200) when only an id_token_hint is supplied', async () => {
    const idt = await idTokenHint();
    const res = await request(app).get('/oidc-x/end_session').query({id_token_hint: idt}).expect(200);
    expect(res.body.message).toBeTruthy();
  });

  it('400s a post_logout_redirect_uri without an id_token_hint (schema)', async () => {
    const res = await request(app).get('/oidc-x/end_session').query({post_logout_redirect_uri: LOGOUT_URI}).expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('400s an unregistered post_logout_redirect_uri (no redirect)', async () => {
    const idt = await idTokenHint();
    const res = await request(app).get('/oidc-x/end_session').query({
      id_token_hint: idt, post_logout_redirect_uri: 'https://evil.test/lo',
    }).expect(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.headers.location).toBeUndefined();
  });
});
