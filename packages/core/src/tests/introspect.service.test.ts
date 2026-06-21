// tests/introspect.service.test.ts — RFC 7662 introspection, exercised with stub seams.
//
// The token verifier and refresh store are injected, so every branch (verify-throws→refresh,
// iss/client scoping, active field-mapping, inactive default) is asserted without booting the real
// token/session singletons. token_type_hint is not a parameter — it is ignored by design.
import {describe, it, expect} from 'bun:test';
import {IntrospectService} from '../services/oidc/introspect.service';
import type {IntrospectTokenVerifier, IntrospectSessionStore} from '../services/oidc/introspect.service';
import type {AccessTokenClaims, RefreshTokenData} from '../types/oidc.types';

const ISS = 'https://iss.test/oidc-x';
const ctx = {expectedIssuer: ISS, callerClientId: 'web'};

const accessClaims = (over: Partial<AccessTokenClaims> = {}): AccessTokenClaims => ({
  iss: ISS, sub: 'sub-1', aud: 'web', client_id: 'web', scope: 'openid profile', jti: 'jti-1',
  iat: 1000, exp: 4600, ...over,
});

const refreshRecord = (over: Partial<RefreshTokenData> = {}): RefreshTokenData => ({
  token: 'RT', family_id: 'fam', subject: 'sub-1', client_id: 'web', scope: 'openid',
  created_at: 1_000_000, expires_at: 5_000_000, revoked: false, ...over,
});

/** A verifier that resolves the given claims, or rejects (mimicking an unverifiable token). */
const verifier = (claims?: AccessTokenClaims): IntrospectTokenVerifier => ({
  verify: async () => {
    if (!claims) {
      throw new Error('invalid token');
    }
    return claims;
  },
});

const store = (rt?: RefreshTokenData): IntrospectSessionStore => ({getRefreshToken: () => rt});

function make(claims?: AccessTokenClaims, rt?: RefreshTokenData): IntrospectService {
  const svc = new IntrospectService();
  svc.initialize({tokens: verifier(claims), sessions: store(rt)});
  return svc;
}

describe('IntrospectService — lifecycle', () => {
  it('throws before initialization', async () => {
    const svc = new IntrospectService();
    expect(svc.isInitialized()).toBe(false);
    await expect(svc.introspect('t', ctx)).rejects.toThrow('not initialized');
  });

  it('is idempotent — the first initialize wins', async () => {
    const svc = new IntrospectService();
    svc.initialize({tokens: verifier(accessClaims()), sessions: store()});
    // A second init whose verifier would yield a DIFFERENT (foreign-client → inactive) verdict; it must
    // be ignored, so the result stays the first verifier's active token. (Distinguishes the guard.)
    svc.initialize({tokens: verifier(accessClaims({client_id: 'spa'})), sessions: store()});
    const res = await svc.introspect('at', ctx);
    expect(res.active).toBe(true);
    expect(res.client_id).toBe('web');
  });

  it('reset clears initialization', () => {
    const svc = make(accessClaims());
    svc.reset();
    expect(svc.isInitialized()).toBe(false);
  });
});

describe('IntrospectService — access tokens', () => {
  it('returns active claims for the caller’s own valid access token', async () => {
    const res = await make(accessClaims()).introspect('at', ctx);
    expect(res).toEqual({
      active: true, sub: 'sub-1', scope: 'openid profile', client_id: 'web',
      aud: 'web', iss: ISS, exp: 4600, iat: 1000, jti: 'jti-1', token_type: 'Bearer',
    });
  });

  it('is inactive when the token was minted by another authority (iss mismatch)', async () => {
    const res = await make(accessClaims({iss: 'https://other.test'})).introspect('at', ctx);
    expect(res).toEqual({active: false});
  });

  it('is inactive when the token belongs to a different client (anti-oracle)', async () => {
    const res = await make(accessClaims({client_id: 'spa'})).introspect('at', ctx);
    expect(res).toEqual({active: false});
  });
});

describe('IntrospectService — refresh tokens', () => {
  it('returns active claims for the caller’s own live refresh token', async () => {
    // verifier rejects (not a JWT) → falls through to the refresh-token lookup.
    const res = await make(undefined, refreshRecord()).introspect('RT', ctx);
    expect(res).toEqual({
      active: true, sub: 'sub-1', scope: 'openid', client_id: 'web',
      iss: ISS, exp: 5000, iat: 1000,
    });
  });

  it('is inactive when the refresh token belongs to a different client', async () => {
    const res = await make(undefined, refreshRecord({client_id: 'spa'})).introspect('RT', ctx);
    expect(res).toEqual({active: false});
  });

  it('is inactive when the store has no live record (unknown/expired/revoked)', async () => {
    const res = await make(undefined, undefined).introspect('nope', ctx);
    expect(res).toEqual({active: false});
  });
});
