// tests/federation.service.test.ts — upstream federation logic (begin + complete).
//
// Every case uses a fresh `new FederationService()` with the openid-client seams,
// the upstream config provider, and the session store all injected as capturing
// spies/stubs — so the params handed to buildAuthorizationUrl / authorizationCodeGrant
// and the session/code objects are fully deterministic. The pure-random defaults
// (pkce verifier/challenge, nonce) are exercised real in a no-injection case; the
// openid-client wrapper + singleton defaults are covered by the route integration test.
import {describe, it, expect} from 'bun:test';
import {FederationService, FederationError} from '../services/oidc/federation.service';
import type {AuthorizationRequestValidated} from '../utils/schemas/oidc.schemas';
import type {AuthorizationSession} from '../types/oidc.types';

const SENTINEL_CONFIG = {marker: 'sentinel'} as any;

const provider = (oidcOver: Record<string, any> = {}): any => ({
  name: 'oidc-x',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: 'oidc-x', client_id: 'c'},
  OidcConfig: {
    supported_auth_flows: ['authorization_code'],
    issuer: 'https://iss.test/oidc-x',
    upstream_scopes: ['openid', 'profile'],
    ...oidcOver,
  },
});

const authRequest = (over: Partial<AuthorizationRequestValidated> = {}): AuthorizationRequestValidated => ({
  response_type: 'code',
  client_id: 'downstream',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid profile',
  state: 'dstate',
  nonce: 'dnonce',
  code_challenge: 'x'.repeat(43),
  code_challenge_method: 'S256',
  ...over,
} as AuthorizationRequestValidated);

const mockTokens = (over: Record<string, any> = {}) => ({
  access_token: 'AT',
  token_type: 'Bearer',
  expires_in: 3600,
  refresh_token: 'RT',
  id_token: 'IDT',
  scope: 'openid',
  claims: () => ({sub: 'u-9'}),
  ...over,
});

const sessionRecord = (over: Partial<AuthorizationSession> = {}): AuthorizationSession => ({
  id: 'sess-1',
  client_id: 'downstream',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid',
  state: 'dstate',
  response_type: 'code',
  upstream_provider: 'oidc-x',
  upstream_nonce: 'unonce',
  upstream_code_verifier: 'uver',
  created_at: 0,
  expires_at: 0,
  ...over,
});

/** Builds a service with capturing spies + a captured record. Override any spy/stub. */
const makeService = (over: Record<string, any> = {}) => {
  const captured: Record<string, any> = {};
  const service = new FederationService();
  const oidc = {
    randomPKCECodeVerifier: () => 'ver-1',
    calculatePKCECodeChallenge: async (v: string) => {
      captured.challengeInput = v;
      return 'chal-1';
    },
    randomNonce: () => 'nonce-1',
    buildAuthorizationUrl: (config: any, params: any) => {
      captured.authConfig = config;
      captured.authParams = params;
      return new URL('https://up.test/auth?x=1');
    },
    authorizationCodeGrant: async (config: any, currentUrl: any, checks: any) => {
      captured.grantConfig = config;
      captured.grantUrl = currentUrl;
      captured.grantChecks = checks;
      return mockTokens(over.tokens) as any;
    },
    fetchUserInfo: async (config: any, accessToken: string, expectedSubject: string) => {
      captured.uiArgs = {config, accessToken, expectedSubject};
      return {sub: expectedSubject} as any;
    },
    ...over.oidc,
  };
  service.initialize({
    oidc: oidc as any,
    upstream: {
      getConfig: (name: string) => {
        captured.getConfigName = name;
        return SENTINEL_CONFIG;
      },
    },
    sessions: {
      createSession: (input: any) => {
        captured.createSessionInput = input;
        return {...input, id: 'sess-1', created_at: 0, expires_at: 0};
      },
      getSession: over.getSession ?? (() => sessionRecord(over.session)),
      createCode: (input: any) => {
        captured.createCodeInput = input;
        return {...input, code: 'code-1', created_at: 0, expires_at: 0, consumed: false};
      },
    },
    // Default registry stub: the authRequest() default client+redirect are registered.
    clients: over.clients ?? {
      getClient: () => ({client_id: 'downstream', client_type: 'public', redirect_uris: ['https://app.test/cb']}),
    },
  });
  return {service, captured};
};

/** Asserts a rejected promise is a FederationError with the given code + message substring. */
async function expectFederationError(promise: Promise<unknown>, code: string, messageSubstring: string) {
  try {
    await promise;
    throw new Error('expected FederationError, but promise resolved');
  } catch (e) {
    expect(e).toBeInstanceOf(FederationError);
    expect((e as FederationError).code).toBe(code as any);
    expect((e as FederationError).message).toContain(messageSubstring);
    expect((e as FederationError).name).toBe('FederationError');
  }
}

describe('FederationService — guards before init', () => {
  it('rejects both operations before initialization', async () => {
    const s = new FederationService();
    expect(s.isInitialized()).toBe(false);
    await expect(s.beginAuthorization({provider: provider(), request: authRequest()})).rejects.toThrow('not initialized');
    await expect(s.completeCallback({provider: provider(), currentUrl: new URL('https://b/cb?state=s')})).rejects.toThrow('not initialized');
  });
});

describe('FederationService — beginAuthorization', () => {
  it('builds the upstream authorization URL and session from the request', async () => {
    const {service, captured} = makeService();
    const {redirectUrl} = await service.beginAuthorization({provider: provider(), request: authRequest()});

    expect(captured.getConfigName).toBe('oidc-x');
    expect(captured.challengeInput).toBe('ver-1'); // challenge computed from the generated verifier
    expect(captured.authConfig).toBe(SENTINEL_CONFIG);
    expect(captured.authParams).toEqual({
      redirect_uri: 'https://iss.test/oidc-x/callback',
      scope: 'openid profile',
      code_challenge: 'chal-1',
      code_challenge_method: 'S256',
      state: 'sess-1', // the session id is the upstream state
      nonce: 'nonce-1',
    });
    expect(captured.createSessionInput).toEqual({
      client_id: 'downstream',
      redirect_uri: 'https://app.test/cb',
      scope: 'openid profile',
      state: 'dstate',
      nonce: 'dnonce',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
      upstream_provider: 'oidc-x',
      upstream_nonce: 'nonce-1',
      upstream_code_verifier: 'ver-1',
    });
    expect(redirectUrl).toBe('https://up.test/auth?x=1');
  });

  it('rejects an unregistered client (direct error, no session created)', async () => {
    const {service, captured} = makeService({clients: {getClient: () => undefined}});
    await expectFederationError(
      service.beginAuthorization({provider: provider(), request: authRequest()}),
      'invalid_request', 'unknown client',
    );
    expect(captured.createSessionInput).toBeUndefined(); // never reached session creation
  });

  it('rejects a redirect_uri not registered for the client', async () => {
    const {service, captured} = makeService({
      clients: {getClient: () => ({client_id: 'downstream', client_type: 'public', redirect_uris: ['https://other.test/cb']})},
    });
    await expectFederationError(
      service.beginAuthorization({provider: provider(), request: authRequest()}),
      'invalid_request', 'redirect_uri not registered',
    );
    expect(captured.createSessionInput).toBeUndefined();
  });

  it('defaults the upstream scope to "openid" when none configured', async () => {
    const undef = makeService();
    await undef.service.beginAuthorization({provider: provider({upstream_scopes: undefined}), request: authRequest()});
    expect(undef.captured.authParams.scope).toBe('openid');

    const empty = makeService();
    await empty.service.beginAuthorization({provider: provider({upstream_scopes: []}), request: authRequest()});
    expect(empty.captured.authParams.scope).toBe('openid');
  });

  it('rejects an unsupported response_type', async () => {
    const {service} = makeService();
    await expectFederationError(
      service.beginAuthorization({provider: provider(), request: authRequest({response_type: 'token'})}),
      'unsupported_response_type', 'response_type',
    );
  });

  it('rejects when the provider has no issuer', async () => {
    const {service} = makeService();
    await expectFederationError(
      service.beginAuthorization({provider: provider({issuer: undefined}), request: authRequest()}),
      'server_error', 'issuer',
    );
  });

  it('rejects when the provider has no OidcConfig at all', async () => {
    const {service} = makeService();
    const bare = {name: 'oidc-x', auth_protocol: 'oidc', ServerConfig: {endpoint_url: 'oidc-x', client_id: 'c'}};
    await expectFederationError(
      service.beginAuthorization({provider: bare as any, request: authRequest()}),
      'server_error', 'issuer',
    );
  });
});

describe('FederationService — completeCallback', () => {
  // Absolute callback URL; the `state` query param locates the session.
  const cbUrl = (state?: string) =>
    new URL('https://broker.test/oidc-x/callback?code=abc' + (state ? `&state=${state}` : ''));

  it('exchanges the code, fetches userinfo, mints a code, and redirects downstream', async () => {
    const {service, captured} = makeService();
    const currentUrl = cbUrl('sess-1');
    const {redirectUrl} = await service.completeCallback({provider: provider(), currentUrl});

    expect(captured.getConfigName).toBe('oidc-x'); // from session.upstream_provider
    expect(captured.grantConfig).toBe(SENTINEL_CONFIG);
    expect(captured.grantUrl).toBe(currentUrl);
    expect(captured.grantChecks).toEqual({expectedState: 'sess-1', expectedNonce: 'unonce', pkceCodeVerifier: 'uver'});

    expect(captured.uiArgs).toEqual({config: SENTINEL_CONFIG, accessToken: 'AT', expectedSubject: 'u-9'});

    expect(captured.createCodeInput).toEqual({
      session_id: 'sess-1',
      subject: 'u-9',
      user_info: {sub: 'u-9'},
      upstream_tokens: {access_token: 'AT', token_type: 'Bearer', expires_in: 3600, refresh_token: 'RT', id_token: 'IDT', scope: 'openid'},
    });

    const u = new URL(redirectUrl);
    expect(u.origin).toBe('https://app.test');
    expect(u.pathname).toBe('/cb');
    expect(u.searchParams.get('code')).toBe('code-1');
    expect(u.searchParams.get('state')).toBe('dstate');
    expect(u.searchParams.get('iss')).toBe('https://iss.test/oidc-x'); // RFC 9207 issuer identification
  });

  it('rejects a callback for a provider with no issuer configured', async () => {
    const {service} = makeService();
    await expectFederationError(
      service.completeCallback({provider: provider({issuer: undefined}), currentUrl: cbUrl('sess-1')}),
      'server_error', 'issuer',
    );
  });

  it('omits the downstream state when the session has none', async () => {
    const {service, captured} = makeService({session: {state: undefined}});
    const {redirectUrl} = await service.completeCallback({provider: provider(), currentUrl: cbUrl('sess-1')});
    const u = new URL(redirectUrl);
    expect(u.searchParams.get('code')).toBe('code-1');
    expect(u.searchParams.has('state')).toBe(false);
    expect(captured.createCodeInput.session_id).toBe('sess-1');
  });

  it('rejects a missing state', async () => {
    const {service} = makeService();
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl()}),
      'invalid_request', 'missing state',
    );
  });

  it('rejects an unknown or expired session', async () => {
    const {service} = makeService({getSession: () => undefined});
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl('gone')}),
      'invalid_request', 'unknown or expired',
    );
  });

  it('maps an upstream code-exchange failure to access_denied', async () => {
    const {service} = makeService({oidc: {authorizationCodeGrant: async () => { throw new Error('boom'); }}});
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl('sess-1')}),
      'access_denied', 'code exchange failed',
    );
  });

  it('rejects when the upstream id_token has no claims', async () => {
    const {service} = makeService({tokens: {claims: () => undefined}});
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl('sess-1')}),
      'access_denied', 'missing sub',
    );
  });

  it('rejects when the upstream id_token claims have no sub', async () => {
    const {service} = makeService({tokens: {claims: () => ({})}});
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl('sess-1')}),
      'access_denied', 'missing sub',
    );
  });

  it('maps a userinfo failure to access_denied', async () => {
    const {service} = makeService({oidc: {fetchUserInfo: async () => { throw new Error('nope'); }}});
    await expectFederationError(
      service.completeCallback({provider: provider(), currentUrl: cbUrl('sess-1')}),
      'access_denied', 'userinfo',
    );
  });
});

// NOTE: the default seams are DIRECT references (= clientNS.randomPKCECodeVerifier, = upstreamOidc, …)
// with no mutable operators, so Stryker generates no mutants for them and they are line-covered by
// construction. The end-to-end default path is exercised by the route integration test, which supplies
// the openid-client functions via mock.module. (A unit test relying on the REAL openid-client cannot run
// in the full suite, since mock.module('openid-client') from sibling tests is process-global.)

describe('FederationService — lifecycle', () => {
  it('is idempotent: the first initialize wins', async () => {
    const captured: Record<string, any> = {};
    const baseOpts = (nonce: string) => ({
      oidc: {
        randomPKCECodeVerifier: () => 'v',
        calculatePKCECodeChallenge: async () => 'c',
        randomNonce: () => nonce,
        buildAuthorizationUrl: (_c: any, params: any) => {
          captured.params = params;
          return new URL('https://up.test/a');
        },
      } as any,
      upstream: {getConfig: () => SENTINEL_CONFIG},
      sessions: {
        createSession: (input: any) => ({...input, id: 'sess', created_at: 0, expires_at: 0}),
        getSession: () => undefined,
        createCode: (input: any) => ({...input, code: 'c', created_at: 0, expires_at: 0, consumed: false}),
      },
      clients: {getClient: () => ({client_id: 'downstream', client_type: 'public', redirect_uris: ['https://app.test/cb']})},
    });
    const s = new FederationService();
    s.initialize(baseOpts('first'));
    s.initialize(baseOpts('second')); // ignored
    await s.beginAuthorization({provider: provider(), request: authRequest()});
    expect(captured.params.nonce).toBe('first');
  });

  it('reset uninitializes the service', async () => {
    const {service} = makeService();
    service.reset();
    expect(service.isInitialized()).toBe(false);
    await expect(service.beginAuthorization({provider: provider(), request: authRequest()})).rejects.toThrow('not initialized');
  });
});
