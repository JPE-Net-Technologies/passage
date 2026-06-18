// tests/auth.federation.route.test.ts — /authorize + /callback federation routes.
//
// `openid-client` is module-mocked with deterministic stand-ins so the real
// federationService default seams run end-to-end (no injection here), and the
// full authorize→callback round-trip is observable via redirect Location headers.
import {describe, it, expect, beforeAll, mock} from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import {openidClientMock} from './openid-client.mock';

mock.module('openid-client', openidClientMock);

const {localKMS} = await import('../services/kms-local');
const {upstreamOidc} = await import('../services/upstream/oidc-client.service');
const {jwksService} = await import('../services/oidc/jwks.service');
const {sessionService} = await import('../services/oidc/session.service');
const {federationService} = await import('../services/oidc/federation.service');
const {createApp} = await import('../app');
const {buildTestConfig} = await import('./test-utils');

const oidcProvider = (over: Record<string, any> = {}, oidcOver: Record<string, any> = {}) => ({
  name: over.name ?? 'oidc-x',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: over.endpoint_url ?? 'oidc-x', client_id: 'downstream'},
  OidcConfig: {
    supported_auth_flows: ['authorization_code'],
    issuer: 'http://localhost:3000/oidc-x',
    upstream_issuer: 'http://localhost:8080/realms/mock',
    upstream_client_id: 'broker',
    upstream_scopes: ['openid', 'profile'],
    ...oidcOver,
  },
});

let app: any;

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-fed-'));
  fs.writeFileSync(path.join(dir, 'template.secrets.yaml'), 'Secrets: []\n');
  localKMS.reset();
  await localKMS.initialize({keystorePath: path.join(dir, 'kms-local.keystore'), secretsPath: path.join(dir, 'template.secrets.yaml')});
  upstreamOidc.reset();
  jwksService.reset();
  sessionService.reset();
  federationService.reset(); // route setup is responsible for (re)initializing it
  app = await createApp(buildTestConfig({
    providers: {
      providers: [
        oidcProvider() as any,
        // a provider with NO issuer → resolveProvider throws FederationError('server_error')
        oidcProvider({name: 'oidc-noiss', endpoint_url: 'oidc-noiss'}, {issuer: undefined}) as any,
        // a provider with an issuer but NO upstream registration → getConfig throws a plain Error,
        // exercising the non-FederationError (server_error fallback) branch
        oidcProvider({name: 'oidc-unreg', endpoint_url: 'oidc-unreg'}, {issuer: 'http://localhost:3000/oidc-unreg', upstream_issuer: undefined}) as any,
      ],
    },
  }));
});

describe('GET /:provider/authorize', () => {
  it('redirects to the upstream provider with PKCE/state/nonce', async () => {
    const res = await request(app)
      .get('/oidc-x/authorize')
      .query({response_type: 'code', client_id: 'c', redirect_uri: 'https://app.test/cb', scope: 'openid profile', state: 'dstate'})
      .expect(302);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe('https://up.test/auth');
    expect(loc.searchParams.get('redirect_uri')).toBe('http://localhost:3000/oidc-x/callback');
    expect(loc.searchParams.get('scope')).toBe('openid profile');
    expect(loc.searchParams.get('code_challenge_method')).toBe('S256');
    expect(loc.searchParams.get('code_challenge')).toBe('chal');
    expect(loc.searchParams.get('nonce')).toBe('nonce');
    // upstream state is the session id, NOT the downstream state
    const upstreamState = loc.searchParams.get('state');
    expect(upstreamState).toBeTruthy();
    expect(upstreamState).not.toBe('dstate');
  });

  it('400s an invalid authorization request (missing scope)', async () => {
    const res = await request(app)
      .get('/oidc-x/authorize')
      .query({response_type: 'code', client_id: 'c', redirect_uri: 'https://app.test/cb'})
      .expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('500s when the provider has no issuer configured (FederationError server_error)', async () => {
    const res = await request(app)
      .get('/oidc-noiss/authorize')
      .query({response_type: 'code', client_id: 'c', redirect_uri: 'https://app.test/cb', scope: 'openid'})
      .expect(500);
    expect(res.body.error).toBe('server_error');
  });

  it('500s on a non-FederationError (unregistered upstream → server_error fallback)', async () => {
    const res = await request(app)
      .get('/oidc-unreg/authorize')
      .query({response_type: 'code', client_id: 'c', redirect_uri: 'https://app.test/cb', scope: 'openid'})
      .expect(500);
    expect(res.body.error).toBe('server_error');
  });
});

describe('GET /:provider/callback', () => {
  it('completes the round-trip and redirects to the downstream client with code + state', async () => {
    // begin to obtain a real session id (the upstream state)
    const begin = await request(app)
      .get('/oidc-x/authorize')
      .query({response_type: 'code', client_id: 'c', redirect_uri: 'https://app.test/cb', scope: 'openid', state: 'dstate'})
      .expect(302);
    const sessionId = new URL(begin.headers.location).searchParams.get('state')!;

    const res = await request(app)
      .get('/oidc-x/callback')
      .query({state: sessionId, code: 'abc'})
      .expect(302);
    const loc = new URL(res.headers.location);
    expect(loc.origin + loc.pathname).toBe('https://app.test/cb');
    expect(loc.searchParams.get('code')).toBeTruthy();
    expect(loc.searchParams.get('state')).toBe('dstate');
  });

  it('400s a callback with no state', async () => {
    const res = await request(app).get('/oidc-x/callback').query({code: 'abc'}).expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('400s a callback for an unknown session', async () => {
    const res = await request(app).get('/oidc-x/callback').query({state: 'nope', code: 'abc'}).expect(400);
    expect(res.body.error).toBe('invalid_request');
  });
});
