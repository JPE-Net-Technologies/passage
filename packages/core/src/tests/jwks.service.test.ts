// tests/jwks.service.test.ts — Passage's own signing key set.
//
// Tests inject a fixed key pair and a pinned kid so the public JWKS is fully
// deterministic, then exercise the real jose seams once (default initialize) so
// generateKeyPair / thumbprint are covered too.
import {describe, it, expect, beforeAll} from 'bun:test';
import {generateKeyPair, type CryptoKey} from 'jose';
import {JwksService, type KeyPairGenerator} from '../services/oidc/jwks.service';

let rsaPair: {publicKey: CryptoKey; privateKey: CryptoKey};
let ecPair: {publicKey: CryptoKey; privateKey: CryptoKey};

beforeAll(async () => {
  rsaPair = await generateKeyPair('RS256');
  ecPair = await generateKeyPair('ES256');
});

const rsaGen = (): KeyPairGenerator => async () => rsaPair;

describe('JwksService — guards before init', () => {
  it('throws on every accessor before initialization', () => {
    const j = new JwksService();
    expect(j.isInitialized()).toBe(false);
    expect(() => j.getPublicJWKS()).toThrow('not initialized');
    expect(() => j.getSigningKey()).toThrow('not initialized');
    expect(() => j.getVerificationKey('x')).toThrow('not initialized');
  });
});

describe('JwksService — RS256 with pinned key + kid', () => {
  const fresh = async () => {
    const j = new JwksService();
    await j.initialize({generateKeyPair: rsaGen(), computeKid: async () => 'kid-fixed'});
    return j;
  };

  it('exposes exactly one public, sig-use, RS256 key with no private material', async () => {
    const jwks = (await fresh()).getPublicJWKS();
    expect(jwks.keys).toHaveLength(1);
    const k = jwks.keys[0];
    expect(k.kid).toBe('kid-fixed');
    expect(k.use).toBe('sig');
    expect(k.alg).toBe('RS256');
    expect(k.key_ops).toEqual(['verify']);
    expect(k.kty).toBe('RSA');
    expect(typeof k.n).toBe('string');
    expect(typeof k.e).toBe('string');
    expect((k as Record<string, unknown>).d).toBeUndefined(); // never expose the private exponent
  });

  it('returns the private signing key for the token service', async () => {
    const signing = (await fresh()).getSigningKey();
    expect(signing.kid).toBe('kid-fixed');
    expect(signing.alg).toBe('RS256');
    expect(signing.privateKey.type).toBe('private');
  });

  it('resolves a public verification key by kid and rejects unknown kids', async () => {
    const j = await fresh();
    expect(j.getVerificationKey('kid-fixed').type).toBe('public');
    expect(() => j.getVerificationKey('nope')).toThrow('Unknown key id');
  });

  it('actually invokes the injected generator with the configured alg', async () => {
    let calls = 0;
    let seenAlg = '';
    const gen: KeyPairGenerator = async (alg) => {
      calls++;
      seenAlg = alg;
      return rsaPair;
    };
    const j = new JwksService();
    await j.initialize({generateKeyPair: gen, computeKid: async () => 'k'});
    expect(calls).toBe(1);
    expect(seenAlg).toBe('RS256');
  });
});

describe('JwksService — honours injected algorithm', () => {
  it('builds an ES256/EC key when alg is overridden', async () => {
    const j = new JwksService();
    await j.initialize({alg: 'ES256', generateKeyPair: async () => ecPair, computeKid: async () => 'ec-kid'});
    const k = j.getPublicJWKS().keys[0];
    expect(k.alg).toBe('ES256');
    expect(k.kty).toBe('EC');
    expect(k.crv).toBe('P-256');
    expect(j.getSigningKey().alg).toBe('ES256');
  });
});

describe('JwksService — lifecycle', () => {
  it('is idempotent: the first initialize wins (no extra keys)', async () => {
    const j = new JwksService();
    await j.initialize({generateKeyPair: rsaGen(), computeKid: async () => 'a'});
    await j.initialize({generateKeyPair: rsaGen(), computeKid: async () => 'b'}); // ignored
    const jwks = j.getPublicJWKS();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe('a');
  });

  it('reset drops keys and uninitializes', async () => {
    const j = new JwksService();
    await j.initialize({generateKeyPair: rsaGen(), computeKid: async () => 'a'});
    j.reset();
    expect(j.isInitialized()).toBe(false);
    expect(() => j.getPublicJWKS()).toThrow('not initialized');

    await j.initialize({generateKeyPair: rsaGen(), computeKid: async () => 'a'});
    expect(j.getPublicJWKS().keys).toHaveLength(1); // not appended to a stale store
  });
});

describe('JwksService — real (uninjected) seams', () => {
  it('generates a real RSA key and computes a thumbprint kid by default', async () => {
    const j = new JwksService();
    await j.initialize();
    const k = j.getPublicJWKS().keys[0];
    expect(k.kty).toBe('RSA');
    expect(typeof k.kid).toBe('string');
    expect(k.kid!.length).toBeGreaterThan(0);
    expect(typeof k.n).toBe('string');
    expect(j.getSigningKey().privateKey.type).toBe('private');
    expect(j.getVerificationKey(k.kid!).type).toBe('public');
  });
});
