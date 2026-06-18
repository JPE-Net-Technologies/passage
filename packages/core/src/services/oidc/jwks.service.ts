// src/services/oidc/jwks.service.ts
// Passage's own JSON Web Key Set — the signing identity used to mint
// Passage-issued access/ID tokens, and the public keys served at /jwks.
//
// Keys are generated in-memory at initialize() time. This is ephemeral by
// design for this increment: a broker restart rotates the signing key, which is
// acceptable before any real client holds a long-lived token. Durable storage is
// a later concern — the internal key store plus the injectable {@link KeyPairGenerator}
// seam are the seam a persistence layer would hook into (e.g. load extractable
// keys from LocalKMS/DB) without changing this public surface.
//
// All non-determinism (key material, key id) is injectable so the service is
// fully pinnable in tests; defaults use jose.
import {generateKeyPair, exportJWK, calculateJwkThumbprint, type CryptoKey} from 'jose';
import {JWKSet, JWK, SigningAlgorithm} from '../../types/oidc.types';

/** Asymmetric key pair source for a given JWA signing algorithm. */
export type KeyPairGenerator = (alg: SigningAlgorithm) => Promise<{publicKey: CryptoKey; privateKey: CryptoKey}>;
/** Key-id (kid) source, given the public JWK. */
export type KidComputer = (publicJwk: JWK) => Promise<string>;

export interface JwksInitOptions {
  /** Signing algorithm. Default: `RS256`. */
  alg?: SigningAlgorithm;
  /** Key pair generator. Default: jose `generateKeyPair`. */
  generateKeyPair?: KeyPairGenerator;
  /** Key id computer. Default: jose RFC 7638 thumbprint. */
  computeKid?: KidComputer;
}

/** Private signing material handed to the token service. */
export interface SigningKey {
  kid: string;
  alg: SigningAlgorithm;
  privateKey: CryptoKey;
}

interface StoredKey {
  kid: string;
  alg: SigningAlgorithm;
  publicJwk: JWK;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

class JwksService {
  private keys: StoredKey[] = [];
  private alg: SigningAlgorithm = 'RS256';
  private generateKeyPairFn: KeyPairGenerator = (alg) => generateKeyPair(alg);
  private computeKid: KidComputer = (jwk) => calculateJwkThumbprint(jwk);
  private initialized = false;

  /** Use the exported {@link jwksService} singleton; the class is exported for tests. */
  constructor() {}

  /** Generate the initial signing key. Idempotent — the first call wins. */
  async initialize(opts: JwksInitOptions = {}): Promise<void> {
    if (this.initialized) {
      return;
    }
    if (opts.alg) {
      this.alg = opts.alg;
    }
    if (opts.generateKeyPair) {
      this.generateKeyPairFn = opts.generateKeyPair;
    }
    if (opts.computeKid) {
      this.computeKid = opts.computeKid;
    }
    await this.rotate();
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  /** Drop all keys and mark uninitialized (for tests / re-bootstrap). */
  reset(): void {
    this.keys = [];
    this.initialized = false;
  }

  /** Public key set for the `/jwks` endpoint — public material only. */
  getPublicJWKS(): JWKSet {
    this.ensureInitialized();
    return {keys: this.keys.map((k) => k.publicJwk)};
  }

  /** Current signing key (private) for the token service. */
  getSigningKey(): SigningKey {
    this.ensureInitialized();
    const key = this.keys[this.keys.length - 1];
    return {kid: key.kid, alg: key.alg, privateKey: key.privateKey};
  }

  /** Public verification key for a given kid. Throws if the kid is unknown. */
  getVerificationKey(kid: string): CryptoKey {
    this.ensureInitialized();
    const key = this.keys.find((k) => k.kid === kid);
    if (!key) {
      throw new Error(`Unknown key id: ${kid}`);
    }
    return key.publicKey;
  }

  /** Generate a fresh key pair and append it to the key store. */
  private async rotate(): Promise<void> {
    const {publicKey, privateKey} = await this.generateKeyPairFn(this.alg);
    const exported = await exportJWK(publicKey);
    const kid = await this.computeKid(exported as JWK);
    const publicJwk: JWK = {
      ...(exported as JWK),
      kid,
      use: 'sig',
      alg: this.alg,
      key_ops: ['verify'],
    };
    this.keys.push({kid, alg: this.alg, publicJwk, publicKey, privateKey});
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('JwksService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const jwksService = new JwksService();

// Class exported for isolated tests.
export {JwksService};
