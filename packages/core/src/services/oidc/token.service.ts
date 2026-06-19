// src/services/oidc/token.service.ts
// Issues and verifies Passage-signed tokens (access tokens + OIDC ID tokens),
// signed with the broker's own key from the JWKS service.
//
// `issuer` and token lifetimes are supplied PER CALL, not at initialize(): Passage
// is a multi-provider broker where each mounted provider path is its own OIDC
// authority (its own issuer + configured lifetimes). initialize() only wires the
// deterministic seams (clock/jti/signer/verifier) and the signing-key provider.
import {SignJWT, jwtVerify, type CryptoKey, type JWTPayload, type JWTVerifyOptions, type JWTHeaderParameters} from 'jose';
import {AccessTokenClaims, IDTokenClaims, SigningAlgorithm} from '../../types/oidc.types';
import {jwksService} from './jwks.service';
import type {SigningKey} from './jwks.service';

/** The slice of the JWKS service the token service depends on. */
export interface SigningKeyProvider {
  getSigningKey(): SigningKey;
  getVerificationKey(kid: string): CryptoKey;
}

/** Epoch SECONDS source (OIDC `iat`/`exp` are in seconds). */
export type Clock = () => number;
/** JWT id (`jti`) source. */
export type JtiGenerator = () => string;
/** Signs a claim set into a compact JWS. */
export type TokenSigner = (claims: Record<string, unknown>, header: {alg: string; kid: string}, key: CryptoKey) => Promise<string>;
/** Resolves the verification key for a token's protected header. */
export type KeyResolver = (header: JWTHeaderParameters) => CryptoKey;
/** Verifies a compact JWS and returns its payload. */
export type TokenVerifier = (token: string, getKey: KeyResolver, options: JWTVerifyOptions) => Promise<{payload: JWTPayload}>;

export interface TokenServiceInitOptions {
  /** Signing-key provider. Default: the {@link jwksService} singleton. */
  jwks?: SigningKeyProvider;
  /** Epoch-seconds clock. Default: derived from {@link Date.now}. */
  clock?: Clock;
  /** `jti` generator. Default: {@link crypto.randomUUID}. */
  jti?: JtiGenerator;
  /** Signer. Default: jose `SignJWT`. */
  signer?: TokenSigner;
  /** Verifier. Default: jose `jwtVerify`. */
  verifier?: TokenVerifier;
}

export interface AccessTokenInput {
  issuer: string;
  subject: string;
  client_id: string;
  audience: string | string[];
  /** Lifetime in seconds. */
  lifetime: number;
  scope?: string;
  /** Extra claims; cannot override the standard claims below. */
  extra?: Record<string, unknown>;
}

export interface IdTokenInput {
  issuer: string;
  subject: string;
  audience: string;
  /** Lifetime in seconds. */
  lifetime: number;
  nonce?: string;
  auth_time?: number;
  /** Extra claims; cannot override the standard claims below. */
  claims?: Partial<IDTokenClaims>;
}

export interface VerifyOptions {
  audience?: string | string[];
  /**
   * Accepted JWS `alg` allow-list (algorithm-confusion defense, per the broker correctness gate
   * §D / RFC 8725). Default `['RS256']`. jose rejects `alg:none` regardless of this list.
   */
  algorithms?: SigningAlgorithm[];
}

const defaultSigner: TokenSigner = (claims, header, key) =>
  new SignJWT(claims as JWTPayload).setProtectedHeader(header).sign(key);

const defaultVerifier: TokenVerifier = (token, getKey, options) =>
  jwtVerify(token, getKey as never, options);

class TokenService {
  private jwks: SigningKeyProvider = jwksService;
  private clock: Clock = () => Math.floor(Date.now() / 1000);
  private jti: JtiGenerator = () => crypto.randomUUID();
  private signer: TokenSigner = defaultSigner;
  private verifier: TokenVerifier = defaultVerifier;
  private initialized = false;

  /** Use the exported {@link tokenService} singleton; the class is exported for tests. */
  constructor() {}

  /** Wire the deterministic seams. Idempotent — the first call wins. */
  initialize(opts: TokenServiceInitOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.jwks) {
      this.jwks = opts.jwks;
    }
    if (opts.clock) {
      this.clock = opts.clock;
    }
    if (opts.jti) {
      this.jti = opts.jti;
    }
    if (opts.signer) {
      this.signer = opts.signer;
    }
    if (opts.verifier) {
      this.verifier = opts.verifier;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.initialized = false;
  }

  /** Issue a Passage-signed JWT access token. */
  async issueAccessToken(input: AccessTokenInput): Promise<{token: string; claims: AccessTokenClaims}> {
    this.ensureInitialized();
    const iat = this.clock();
    const claims: AccessTokenClaims = {
      ...input.extra,
      iss: input.issuer,
      sub: input.subject,
      aud: input.audience,
      client_id: input.client_id,
      scope: input.scope,
      jti: this.jti(),
      iat,
      exp: iat + input.lifetime,
    };
    const token = await this.sign(claims);
    return {token, claims};
  }

  /** Issue a Passage-signed OIDC ID token. */
  async issueIdToken(input: IdTokenInput): Promise<{token: string; claims: IDTokenClaims}> {
    this.ensureInitialized();
    const iat = this.clock();
    const claims: IDTokenClaims = {
      ...input.claims,
      iss: input.issuer,
      sub: input.subject,
      aud: input.audience,
      nonce: input.nonce,
      auth_time: input.auth_time,
      iat,
      exp: iat + input.lifetime,
    };
    const token = await this.sign(claims);
    return {token, claims};
  }

  /** Verify a Passage-signed token's signature, expiry, and (optionally) audience. */
  async verify(token: string, opts: VerifyOptions = {}): Promise<AccessTokenClaims | IDTokenClaims> {
    this.ensureInitialized();
    const result = await this.verifier(
      token,
      (header) => this.jwks.getVerificationKey(header.kid as string),
      {audience: opts.audience, algorithms: opts.algorithms ?? ['RS256']},
    );
    return result.payload as AccessTokenClaims | IDTokenClaims;
  }

  private sign(claims: Record<string, unknown>): Promise<string> {
    const key = this.jwks.getSigningKey();
    return this.signer(claims, {alg: key.alg, kid: key.kid}, key.privateKey);
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('TokenService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const tokenService = new TokenService();

// Class exported for isolated tests.
export {TokenService};
