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
import {openidClientMock, FAKE_METADATA, lastDiscoveryCall} from './openid-client.mock';

// Shared complete mock; discovery throws for a "broken" issuer to simulate failure.
mock.module('openid-client', openidClientMock);

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
    // discovery() is handed client metadata pinning the upstream id_token alg + the KMS secret
    expect(lastDiscoveryCall.metadata).toEqual({client_secret: 'super-secret', id_token_signed_response_alg: 'RS256'});
  });

  it('registers a provider with no secret reference', async () => {
    const f = new UpstreamOidcFactory();
    await f.initialize([provider({OidcConfig: {upstream_client_secret_ref: undefined}}) as any]);
    expect(f.hasProvider('oidc-full')).toBe(true);
    // no secret resolved → client_secret is undefined, but the alg is still pinned
    expect(lastDiscoveryCall.metadata).toEqual({client_secret: undefined, id_token_signed_response_alg: 'RS256'});
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

  it('serves Passage own discovery doc, and 500s a provider with no issuer', async () => {
    const config = buildTestConfig({
      providers: {
        providers: [
          provider({OidcConfig: {issuer: 'http://localhost:3000/oidc-full'}}) as any,
          // a provider with no Passage issuer → buildDiscoveryDocument throws → 500
          provider({name: 'oidc-noiss', ServerConfig: {endpoint_url: 'oidc-noiss', client_id: 'd2'}}) as any,
        ],
      },
    });
    const app = await createApp(config);

    // Passage's own metadata (NOT the upstream's): issuer-derived endpoints, RS256 advertised.
    const ok = await request(app).get('/oidc-full/.well-known/openid-configuration').expect(200);
    expect(ok.body.issuer).toBe('http://localhost:3000/oidc-full');
    expect(ok.body.token_endpoint).toBe('http://localhost:3000/oidc-full/token');
    expect(ok.body.jwks_uri).toBe('http://localhost:3000/oidc-full/jwks');
    expect(ok.body.id_token_signing_alg_values_supported).toContain('RS256');
    expect(ok.body.code_challenge_methods_supported).toContain('S256');

    const bad = await request(app).get('/oidc-noiss/.well-known/openid-configuration').expect(500);
    expect(bad.body.error).toBeDefined();
  });
});
