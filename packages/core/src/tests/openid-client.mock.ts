// tests/openid-client.mock.ts — a single, COMPLETE openid-client mock shared by every
// test file that mocks the module.
//
// Bun's `mock.module` is process-global and the last registration wins, so multiple
// files registering *different* partial mocks clobber each other. Sharing one complete
// mock makes clobbering harmless and keeps every openid-client function defined for all
// suites (discovery for the upstream factory, plus the federation flow functions).
export const FAKE_METADATA = {
  issuer: 'http://localhost:8080/realms/mock',
  authorization_endpoint: 'http://localhost:8080/realms/mock/auth',
  token_endpoint: 'http://localhost:8080/realms/mock/token',
};

/** Deterministic upstream token response for the federation callback. */
export const FAKE_TOKENS = {
  access_token: 'AT',
  token_type: 'Bearer',
  expires_in: 3600,
  refresh_token: 'RT',
  id_token: 'IDT',
  scope: 'openid',
  claims: () => ({sub: 'u-1'}),
};

/** Captures the args of the most recent `discovery()` call, so tests can assert client-metadata pinning. */
export const lastDiscoveryCall: {metadata?: unknown} = {};

/** Factory for `mock.module('openid-client', openidClientMock)`. */
export const openidClientMock = () => ({
  // Upstream discovery (UpstreamOidcFactory). Throws for a "broken" issuer to simulate failure.
  discovery: async (url: URL, clientId: string, metadata?: unknown) => {
    lastDiscoveryCall.metadata = metadata;
    if (url.toString().includes('broken')) {
      throw new Error('simulated discovery failure');
    }
    return {serverMetadata: () => FAKE_METADATA, clientId};
  },
  allowInsecureRequests: Symbol('allowInsecureRequests'),

  // Federation flow functions (deterministic).
  randomPKCECodeVerifier: () => 'ver',
  calculatePKCECodeChallenge: async () => 'chal',
  randomNonce: () => 'nonce',
  buildAuthorizationUrl: (_config: unknown, params: Record<string, string>) =>
    new URL('https://up.test/auth?' + new URLSearchParams(params).toString()),
  authorizationCodeGrant: async () => ({...FAKE_TOKENS}),
  fetchUserInfo: async (_config: unknown, _accessToken: string, sub: string) => ({sub}),
});
