// tests/oidc-upstream.test.ts — upstream OIDC federation factory + discovery route.
//
// `openid-client` is mocked so we exercise the factory and route logic deterministically,
// without reaching a live provider. The integration suite under `task test` (docker) is
// what validates against a real Keycloak upstream.
import {describe, it, expect, beforeAll, afterAll, mock} from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';

const FAKE_METADATA = {
  issuer: 'http://localhost:8080/realms/mock',
  authorization_endpoint: 'http://localhost:8080/realms/mock/auth',
  token_endpoint: 'http://localhost:8080/realms/mock/token',
};

// Discovery resolves normally, except for the issuer used to simulate a failing upstream.
mock.module('openid-client', () => ({
  discovery: async (url: URL, clientId: string) => {
    if (url.toString().includes('broken')) {
      throw new Error('simulated discovery failure');
    }
    return {serverMetadata: () => FAKE_METADATA, clientId};
  },
  allowInsecureRequests: Symbol('allowInsecureRequests'),
}));

const {UpstreamOidcFactory, upstreamOidc} = await import('../services/upstream/oidc-client.service');
const {localKMS} = await import('../services/kms-local');
const {createApp} = await import('../app');
const {buildTestConfig} = await import('./test-utils');

type AnyProvider = Record<string, any>;
const provider = (over: AnyProvider = {}): AnyProvider => {
  const {OidcConfig: oidcOver, ...rest} = over;
  return {
    name: 'oidc-full',
    auth_protocol: 'oidc',
    ServerConfig: {endpoint_url: 'oidc-full', client_id: 'downstream-client'},
    ...rest,
    OidcConfig: {
      supported_auth_flows: ['authorization_code'],
      upstream_issuer: 'http://localhost:8080/realms/mock',
      upstream_client_id: 'broker',
      upstream_client_secret_ref: 'UpstreamClientSecret',
      ...oidcOver,
    },
  };
};

let TEST_DIR: string;
let INIT_OPTS: {keystorePath: string; secretsPath: string};

beforeAll(async () => {
  TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-oidc-'));
  const secretsPath = path.join(TEST_DIR, 'template.secrets.yaml');
  fs.writeFileSync(secretsPath,
    'Secrets:\n  - name: UpstreamClientSecret\n    provider: Passage.LocalKms\n    reference: UpstreamClientSecret\n    unencryptedValue: super-secret\n');
  INIT_OPTS = {keystorePath: path.join(TEST_DIR, 'kms-local.keystore'), secretsPath};
});

afterAll(() => fs.rmSync(TEST_DIR, {recursive: true, force: true}));

describe('UpstreamOidcFactory — guards before init', () => {
  it('throws on access before initialization', () => {
    const f = new UpstreamOidcFactory();
    expect(f.isInitialized()).toBe(false);
    expect(() => f.getConfig('x')).toThrow('not initialized');
    expect(() => f.hasProvider('x')).toThrow('not initialized');
    expect(() => f.getProviderNames()).toThrow('not initialized');
  });

  it('requires LocalKMS to be initialized first', async () => {
    localKMS.reset();
    const f = new UpstreamOidcFactory();
    await expect(f.initialize([provider() as any])).rejects.toThrow('LocalKMS must be initialized');
  });
});

describe('UpstreamOidcFactory — registration', () => {
  beforeAll(async () => {
    localKMS.reset();
    await localKMS.initialize(INIT_OPTS);
  });

  it('registers a provider, resolving its client secret from KMS', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider() as any]);
    expect(f.isInitialized()).toBe(true);
    expect(f.hasProvider('oidc-full')).toBe(true);
    expect(f.hasProvider('nope')).toBe(false);
    expect(f.getProviderNames()).toContain('oidc-full');
    expect(f.getConfig('oidc-full').serverMetadata().issuer).toBe(FAKE_METADATA.issuer);
    expect(() => f.getConfig('unknown')).toThrow('Unknown provider');
  });

  it('registers a provider with no secret reference', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider({OidcConfig: {upstream_client_secret_ref: undefined}}) as any]);
    expect(f.hasProvider('oidc-full')).toBe(true);
  });

  it('skips (and logs) a provider missing upstream_client_id', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider({OidcConfig: {upstream_client_id: undefined}}) as any]);
    expect(f.hasProvider('oidc-full')).toBe(false); // registration threw, caught, continues
  });

  it('skips a provider whose secret is absent from KMS', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider({OidcConfig: {upstream_client_secret_ref: 'MissingSecret'}}) as any]);
    expect(f.hasProvider('oidc-full')).toBe(false);
  });

  it('is idempotent and resettable', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider() as any]);
    await f.initialize([provider() as any]); // already-initialized branch
    expect(f.hasProvider('oidc-full')).toBe(true);
    f.reset();
    expect(f.isInitialized()).toBe(false);
  });
});

describe('Discovery route', () => {
  beforeAll(async () => {
    localKMS.reset();
    await localKMS.initialize(INIT_OPTS);
    upstreamOidc.reset();
  });

  it('serves upstream metadata, and 500s when the upstream is unregistered', async () => {
    const config = buildTestConfig({
      providers: {
        providers: [
          provider() as any,
          provider({name: 'oidc-broken', ServerConfig: {endpoint_url: 'oidc-broken', client_id: 'd2'},
            OidcConfig: {upstream_issuer: 'http://broken/realms/x'}}) as any,
        ],
      },
    });
    const app = await createApp(config);

    const ok = await request(app).get('/oidc-full/.well-known/openid-configuration').expect(200);
    expect(ok.body.issuer).toBe(FAKE_METADATA.issuer);

    // The broken provider's discovery failed at registration but its route is still mounted.
    const bad = await request(app).get('/oidc-broken/.well-known/openid-configuration').expect(500);
    expect(bad.body.error).toBeDefined();
  });
});
