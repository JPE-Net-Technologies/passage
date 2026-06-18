// tests/auth.jwks.route.test.ts — the per-provider /jwks endpoint.
//
// `openid-client` is mocked (as in oidc-upstream.test.ts) so route setup runs
// without a live upstream. The jwksService singleton is reset before the app is
// built, so the endpoint depends on setupOidcRoutes initializing it.
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
const {createApp} = await import('../app');
const {buildTestConfig} = await import('./test-utils');

const provider = {
  name: 'oidc-jwks',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: 'oidc-jwks', client_id: 'downstream'},
  OidcConfig: {
    supported_auth_flows: ['authorization_code'],
    issuer: 'http://localhost:3000/oidc-jwks',
    upstream_issuer: 'http://localhost:8080/realms/mock',
    upstream_client_id: 'broker',
  },
};

let app: any;

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-jwks-'));
  fs.writeFileSync(path.join(dir, 'template.secrets.yaml'), 'Secrets: []\n');
  localKMS.reset();
  await localKMS.initialize({keystorePath: path.join(dir, 'kms-local.keystore'), secretsPath: path.join(dir, 'template.secrets.yaml')});
  upstreamOidc.reset();
  jwksService.reset(); // the app's route setup is responsible for (re)initializing it
  app = await createApp(buildTestConfig({providers: {providers: [provider as any]}}));
});

describe('GET /:provider/jwks', () => {
  it('serves the public JWKS with a long cache lifetime', async () => {
    const res = await request(app).get('/oidc-jwks/jwks').expect(200);
    expect(res.headers['cache-control']).toBe('public, max-age=3600');

    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys).toHaveLength(1);
    const key = res.body.keys[0];
    expect(key.use).toBe('sig');
    expect(key.kty).toBe('RSA');
    expect(typeof key.kid).toBe('string');
    expect(key.d).toBeUndefined(); // no private material
  });
});
