// tests/token.service.test.ts — Passage-signed access/ID token issuance + verification.
//
// Claim construction is asserted via an injected signer spy with a pinned clock
// and jti, so every field and the iat/exp arithmetic is deterministic. The real
// jose signer/verifier are exercised once via a sign→verify round-trip.
import {describe, it, expect, beforeAll} from 'bun:test';
import {generateKeyPair, SignJWT, type CryptoKey} from 'jose';
import {TokenService, type TokenSigner, type TokenVerifier, type SigningKeyProvider} from '../services/oidc/token.service';
import {JwksService, jwksService} from '../services/oidc/jwks.service';

let pair: {publicKey: CryptoKey; privateKey: CryptoKey};
let jwksStub: SigningKeyProvider;

beforeAll(async () => {
  pair = await generateKeyPair('RS256');
  jwksStub = {
    getSigningKey: () => ({kid: 'kid-1', alg: 'RS256', privateKey: pair.privateKey}),
    getVerificationKey: () => pair.publicKey,
  };
});

/** A token service wired with a spy signer over the stub key provider. */
const withSigner = () => {
  const captured: {claims?: Record<string, unknown>; header?: unknown; key?: unknown} = {};
  const signer: TokenSigner = async (claims, header, key) => {
    captured.claims = claims;
    captured.header = header;
    captured.key = key;
    return 'signed.jwt';
  };
  const ts = new TokenService();
  ts.initialize({jwks: jwksStub, clock: () => 1000, jti: () => 'jti-1', signer});
  return {ts, captured};
};

describe('TokenService — guards before init', () => {
  it('rejects every operation before initialization', async () => {
    const ts = new TokenService();
    expect(ts.isInitialized()).toBe(false);
    await expect(ts.issueAccessToken({issuer: 'i', subject: 's', client_id: 'c', audience: 'a', lifetime: 1})).rejects.toThrow('not initialized');
    await expect(ts.issueIdToken({issuer: 'i', subject: 's', audience: 'a', lifetime: 1})).rejects.toThrow('not initialized');
    await expect(ts.verify('t')).rejects.toThrow('not initialized');
  });
});

describe('TokenService — access token claims', () => {
  it('builds the standard claim set and signs it with the JWKS key', async () => {
    const {ts, captured} = withSigner();
    const {token, claims} = await ts.issueAccessToken({
      issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1',
      lifetime: 60, scope: 'openid profile', extra: {foo: 'bar'},
    });
    expect(token).toBe('signed.jwt');
    expect(claims.iss).toBe('https://iss');
    expect(claims.sub).toBe('u1');
    expect(claims.aud).toBe('aud1');
    expect(claims.client_id).toBe('c1');
    expect(claims.scope).toBe('openid profile');
    expect(claims.jti).toBe('jti-1');
    expect(claims.iat).toBe(1000);
    expect(claims.exp).toBe(1060); // iat + lifetime
    expect(claims.foo).toBe('bar'); // extra claim merged

    expect(captured.claims).toEqual(claims); // the signed payload is the returned claim set
    expect(captured.header).toEqual({alg: 'RS256', kid: 'kid-1'});
    expect(captured.key).toBe(pair.privateKey);
  });

  it('does not let extra claims override standard claims', async () => {
    const {ts} = withSigner();
    const {claims} = await ts.issueAccessToken({
      issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1',
      lifetime: 60, extra: {iss: 'evil', sub: 'evil', jti: 'evil'},
    });
    expect(claims.iss).toBe('https://iss');
    expect(claims.sub).toBe('u1');
    expect(claims.jti).toBe('jti-1');
  });
});

describe('TokenService — ID token claims', () => {
  it('builds OIDC ID token claims (nonce/auth_time, no client_id)', async () => {
    const {ts, captured} = withSigner();
    const {token, claims} = await ts.issueIdToken({
      issuer: 'https://iss', subject: 'u1', audience: 'c1',
      lifetime: 120, nonce: 'n1', auth_time: 50, claims: {email: 'e@x.test'},
    });
    expect(token).toBe('signed.jwt');
    expect(claims.iss).toBe('https://iss');
    expect(claims.sub).toBe('u1');
    expect(claims.aud).toBe('c1');
    expect(claims.nonce).toBe('n1');
    expect(claims.auth_time).toBe(50);
    expect(claims.iat).toBe(1000);
    expect(claims.exp).toBe(1120);
    expect(claims.email).toBe('e@x.test');
    expect((claims as Record<string, unknown>).client_id).toBeUndefined();
    expect(captured.header).toEqual({alg: 'RS256', kid: 'kid-1'});
  });

  it('does not let extra claims override standard claims', async () => {
    const {ts} = withSigner();
    const {claims} = await ts.issueIdToken({
      issuer: 'https://iss', subject: 'u1', audience: 'c1', lifetime: 1,
      claims: {iss: 'evil', sub: 'evil'},
    });
    expect(claims.iss).toBe('https://iss');
    expect(claims.sub).toBe('u1');
  });
});

describe('TokenService — verification', () => {
  it('round-trips a real signed token through jose', async () => {
    const jwks = new JwksService();
    await jwks.initialize({computeKid: async () => 'kid-rt'});
    const ts = new TokenService();
    ts.initialize({jwks});

    const {token} = await ts.issueAccessToken({
      issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1', lifetime: 3600, scope: 'openid',
    });
    const payload = await ts.verify(token, {audience: 'aud1'});
    expect(payload.iss).toBe('https://iss');
    expect(payload.sub).toBe('u1');
    expect(payload.aud).toBe('aud1');

    const payloadNoAud = await ts.verify(token); // audience check skipped
    expect(payloadNoAud.sub).toBe('u1');
  });

  it('rejects a token with the wrong audience', async () => {
    const jwks = new JwksService();
    await jwks.initialize({computeKid: async () => 'kid-rt'});
    const ts = new TokenService();
    ts.initialize({jwks});
    const {token} = await ts.issueAccessToken({issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1', lifetime: 3600});
    await expect(ts.verify(token, {audience: 'WRONG'})).rejects.toThrow();
  });

  it('rejects an expired token', async () => {
    const jwks = new JwksService();
    await jwks.initialize({computeKid: async () => 'kid-rt'});
    const ts = new TokenService();
    ts.initialize({jwks, clock: () => 1000}); // exp lands in 1970
    const {token} = await ts.issueAccessToken({issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1', lifetime: 1});
    await expect(ts.verify(token)).rejects.toThrow();
  });

  it('delegates to the injected verifier, passing the audience, default algorithms, and a working key resolver', async () => {
    let calls = 0;
    let seenAudience: unknown = 'unset';
    let seenAlgorithms: unknown = 'unset';
    let resolved: unknown;
    const verifier: TokenVerifier = async (_token, getKey, options) => {
      calls++;
      seenAudience = options.audience;
      seenAlgorithms = options.algorithms;
      resolved = getKey({kid: 'kid-1'} as never);
      return {payload: {sub: 'stub-subject'}};
    };
    const ts = new TokenService();
    ts.initialize({jwks: jwksStub, verifier});

    const payload = await ts.verify('any.token', {audience: 'aud-x'});
    expect(calls).toBe(1);
    expect(seenAudience).toBe('aud-x');
    expect(seenAlgorithms).toEqual(['RS256']); // default allow-list passed to the verifier
    expect(resolved).toBe(pair.publicKey); // resolver routes header.kid → JWKS public key
    expect(payload.sub).toBe('stub-subject');
  });

  it('pins the algorithm allow-list: rejects an out-of-list alg, honours an explicit override', async () => {
    const es = await generateKeyPair('ES256');
    const esJwks: SigningKeyProvider = {
      getSigningKey: () => ({kid: 'es', alg: 'ES256', privateKey: es.privateKey}),
      getVerificationKey: () => es.publicKey,
    };
    const ts = new TokenService();
    ts.initialize({jwks: esJwks});
    const token = await new SignJWT({sub: 'u1'}).setProtectedHeader({alg: 'ES256', kid: 'es'}).sign(es.privateKey);

    await expect(ts.verify(token)).rejects.toThrow(); // ES256 not in the default ['RS256'] allow-list
    const payload = await ts.verify(token, {algorithms: ['ES256']}); // explicit override is honoured
    expect(payload.sub).toBe('u1');
  });
});

describe('TokenService — defaults & lifecycle', () => {
  it('defaults to the jwksService singleton when none is injected', async () => {
    await jwksService.initialize({computeKid: async () => 'singleton-kid'});
    const ts = new TokenService();
    ts.initialize(); // pure defaults — signs with the jwksService singleton
    const nowSec = Math.floor(Date.now() / 1000);
    const {token, claims} = await ts.issueAccessToken({
      issuer: 'https://iss', subject: 'u1', client_id: 'c1', audience: 'aud1', lifetime: 3600,
    });
    expect(typeof token).toBe('string');
    // default jti is a real UUID string
    expect(typeof claims.jti).toBe('string');
    expect((claims.jti as string).length).toBeGreaterThan(0);
    // default clock is epoch SECONDS (not millis) — within a few seconds of now
    expect(claims.iat).toBeGreaterThanOrEqual(nowSec - 5);
    expect(claims.iat).toBeLessThanOrEqual(nowSec + 5);
    const payload = await ts.verify(token, {audience: 'aud1'}); // verified via the same singleton
    expect(payload.sub).toBe('u1');
  });

  it('is idempotent: the first initialize wins', async () => {
    const ts = new TokenService();
    ts.initialize({jwks: jwksStub, clock: () => 1000, jti: () => 'jti-1', signer: async () => 'x'});
    ts.initialize({jwks: jwksStub, clock: () => 9999, jti: () => 'jti-1', signer: async () => 'x'}); // ignored
    const {claims} = await ts.issueAccessToken({issuer: 'i', subject: 's', client_id: 'c', audience: 'a', lifetime: 5});
    expect(claims.iat).toBe(1000);
  });

  it('reset uninitializes the service', async () => {
    const ts = new TokenService();
    ts.initialize({jwks: jwksStub, signer: async () => 'x'});
    ts.reset();
    expect(ts.isInitialized()).toBe(false);
    await expect(ts.issueAccessToken({issuer: 'i', subject: 's', client_id: 'c', audience: 'a', lifetime: 1})).rejects.toThrow('not initialized');
  });
});
