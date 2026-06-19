// src/services/oidc/userinfo.service.ts
// The OIDC UserInfo endpoint's logic + a minimal claims store. At token issuance the grant
// service remembers the user's claims keyed by the broker-minted subject; /userinfo verifies a
// Bearer access token and returns those claims. The `sub` returned is always the minted one
// (re-mint, never forward — gate §E/§F).
//
// The store is an in-memory Map (dev-only; the Phase 4 pluggable user store replaces it). The
// only seam is the token verifier (default: tokenService.verify, no audience). Logger-free and
// unit-testable to the repo's 100% line + 100% mutation gates.
import {tokenService} from './token.service';
import {AccessTokenClaims, IDTokenClaims, UserInfoResponse} from '../../types/oidc.types';

/** Error carrying an RFC 6750 bearer-token error code, so the thin route maps it to a 401. */
export class UserInfoError extends Error {
  constructor(public readonly code: 'invalid_token', message: string) {
    super(message);
    this.name = 'UserInfoError';
  }
}

/** Verifies a Passage access token and returns its claims. */
export type ClaimsVerifier = (token: string) => Promise<AccessTokenClaims | IDTokenClaims>;

/** Records a subject's claims for later UserInfo retrieval (grant service depends on this slice). */
export interface ClaimsWriter {
  rememberClaims(subject: string, claims: UserInfoResponse): void;
}

/** Full claims store: write + read. The seam a durable Phase 4 user store implements. */
export interface ClaimsStore extends ClaimsWriter {
  getUserInfo(accessToken: string, expectedIssuer: string): Promise<UserInfoResponse>;
}

export interface UserInfoServiceInitOptions {
  /** Access-token verifier. Default: {@link tokenService.verify} (no audience check). */
  verify?: ClaimsVerifier;
}

/**
 * Extract the token from a `Bearer <token>` Authorization header value.
 * Returns undefined when the header is absent or not a non-empty Bearer credential.
 */
export function extractBearerToken(authorization: string | undefined): string | undefined {
  const prefix = 'Bearer ';
  if (!authorization || !authorization.startsWith(prefix)) {
    return undefined;
  }
  return authorization.slice(prefix.length) || undefined;
}

class UserInfoService implements ClaimsStore {
  private store = new Map<string, UserInfoResponse>();
  private verify: ClaimsVerifier = (token) => tokenService.verify(token);
  private initialized = false;

  /** Use the exported {@link userInfoService} singleton; the class is exported for tests. */
  constructor() {}

  initialize(opts: UserInfoServiceInitOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.verify) {
      this.verify = opts.verify;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.store.clear();
    this.initialized = false;
  }

  /** Remember a subject's claims (called at token issuance). */
  rememberClaims(subject: string, claims: UserInfoResponse): void {
    this.ensureInitialized();
    this.store.set(subject, claims);
  }

  /** Verify a Bearer access token and return the stored claims for its subject. */
  async getUserInfo(accessToken: string, expectedIssuer: string): Promise<UserInfoResponse> {
    this.ensureInitialized();
    let claims: AccessTokenClaims | IDTokenClaims;
    try {
      claims = await this.verify(accessToken);
    } catch {
      throw new UserInfoError('invalid_token', 'token verification failed');
    }
    if (claims.iss !== expectedIssuer) {
      throw new UserInfoError('invalid_token', 'token issuer mismatch');
    }
    const stored = this.store.get(claims.sub);
    if (!stored) {
      throw new UserInfoError('invalid_token', 'no stored claims for subject');
    }
    return stored;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('UserInfoService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const userInfoService = new UserInfoService();

// Class exported for isolated tests.
export {UserInfoService};
