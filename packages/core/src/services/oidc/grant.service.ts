// src/services/oidc/grant.service.ts
// The OP-leg token endpoint logic: redeem a one-time Passage authorization code
// (authorization_code grant) or rotate a refresh token (refresh_token grant) into
// freshly minted, Passage-signed access + ID tokens.
//
// This is the "seam" of the broker: the upstream subject captured at /callback is
// RE-MINTED into a broker-controlled, pairwise-pseudonymous `sub` here (never
// forwarded), per the correctness gate §E. PKCE is verified (§A/§G), the code is
// bound to its client_id + redirect_uri (§G), and refresh tokens rotate with
// reuse detection that revokes the whole family (§H).
//
// Logic lives here (not in the route handler) so it is unit-testable to the repo's
// 100% line + 100% mutation gates. All collaborators are injectable seams; the only
// non-determinism owned here is `mintSubject` (clock/id/jti are delegated to the
// session and token services).
import {createHash, timingSafeEqual} from 'node:crypto';
import {sessionService} from './session.service';
import {tokenService} from './token.service';
import type {AccessTokenInput, IdTokenInput} from './token.service';
import {ProviderEntryType} from '../../utils/schemas/config.schemas';
import {TokenRequestValidated} from '../../utils/schemas/oidc.schemas';
import {
  AuthorizationCode,
  AuthorizationSession,
  RefreshTokenData,
  AccessTokenClaims,
  IDTokenClaims,
  TokenResponse,
  TokenErrorCode,
} from '../../types/oidc.types';

/** Error carrying an OAuth token-endpoint error code, so the thin route maps it to a status without logging. */
export class GrantError extends Error {
  constructor(public readonly code: TokenErrorCode, message: string) {
    super(message);
    this.name = 'GrantError';
  }
}

/** Maps an upstream subject to a broker-controlled, per-client (pairwise) subject identifier. */
export type SubjectMapper = (sectorId: string, upstreamSubject: string) => string;

/**
 * Default subject mapping: a deterministic, pairwise-pseudonymous `sub`.
 * Deterministic so the same upstream user maps to a stable downstream `sub` across logins;
 * the separator prevents `(sectorId, upstreamSubject)` pairs from colliding. A persistent
 * secret salt + real sector identifier (host of the redirect URI) land with key persistence
 * and the client registry — see the correctness gate Stage 1 / Phase 3.
 */
export const defaultSubjectMapper: SubjectMapper = (sectorId, upstreamSubject) =>
  createHash('sha256').update(sectorId + '|' + upstreamSubject).digest('base64url');

/** Constant-time string compare that returns false (never throws) on a length mismatch. */
function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** The slice of sessionService the grant flow depends on. */
export interface GrantSessionStore {
  consumeCode(code: string): AuthorizationCode | undefined;
  getSession(id: string): AuthorizationSession | undefined;
  storeRefreshToken(input: {
    subject: string;
    client_id: string;
    scope: string;
    family_id?: string;
    upstream_refresh_token?: string;
  }): RefreshTokenData;
  getRefreshToken(token: string): RefreshTokenData | undefined;
  findRefreshToken(token: string): RefreshTokenData | undefined;
  revokeRefreshToken(token: string): boolean;
  revokeRefreshFamily(familyId: string): number;
}

/** The slice of tokenService the grant flow depends on. */
export interface GrantTokenIssuer {
  issueAccessToken(input: AccessTokenInput): Promise<{token: string; claims: AccessTokenClaims}>;
  issueIdToken(input: IdTokenInput): Promise<{token: string; claims: IDTokenClaims}>;
}

export interface GrantServiceOptions {
  sessions?: GrantSessionStore;  // default: sessionService singleton
  tokens?: GrantTokenIssuer;     // default: tokenService singleton
  mintSubject?: SubjectMapper;   // default: defaultSubjectMapper
}

type AuthCodeRequest = Extract<TokenRequestValidated, {grant_type: 'authorization_code'}>;
type RefreshRequest = Extract<TokenRequestValidated, {grant_type: 'refresh_token'}>;

/** Token lifetimes (seconds) when a provider does not configure its own. */
const DEFAULT_ACCESS_TOKEN_LIFETIME = 3600;
const DEFAULT_ID_TOKEN_LIFETIME = 3600;

class GrantService {
  private sessions: GrantSessionStore = sessionService;
  private tokens: GrantTokenIssuer = tokenService;
  private mintSubject: SubjectMapper = defaultSubjectMapper;
  private initialized = false;

  /** Use the exported {@link grantService} singleton; the class is exported for tests. */
  constructor() {}

  initialize(opts: GrantServiceOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.sessions) {
      this.sessions = opts.sessions;
    }
    if (opts.tokens) {
      this.tokens = opts.tokens;
    }
    if (opts.mintSubject) {
      this.mintSubject = opts.mintSubject;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.initialized = false;
  }

  /** Exchange a validated token request for a Passage {@link TokenResponse}, or throw a {@link GrantError}. */
  async exchange(provider: ProviderEntryType, req: TokenRequestValidated): Promise<TokenResponse> {
    this.ensureInitialized();
    if (req.grant_type === 'authorization_code') {
      return this.authorizationCodeGrant(provider, req);
    }
    if (req.grant_type === 'refresh_token') {
      return this.refreshTokenGrant(provider, req);
    }
    // client_credentials (and any future grant) are not supported by this OP yet.
    throw new GrantError('unsupported_grant_type', `unsupported grant_type: ${req.grant_type}`);
  }

  /**
   * authorization_code: redeem the one-time code, bind it to the originating client_id/redirect_uri,
   * verify PKCE, re-mint the subject, and issue Passage-signed tokens.
   */
  private async authorizationCodeGrant(provider: ProviderEntryType, req: AuthCodeRequest): Promise<TokenResponse> {
    const code = this.sessions.consumeCode(req.code);
    if (!code) {
      throw new GrantError('invalid_grant', 'unknown, expired, or already-used authorization code');
    }
    const session = this.sessions.getSession(code.session_id);
    if (!session) {
      throw new GrantError('invalid_grant', 'authorization session expired');
    }
    // Bind the code to the client_id + redirect_uri it was issued for (gate §G).
    // NOTE(client-auth, Phase 3): the client itself is not yet authenticated (no client registry);
    // these checks bind the code, they do not prove client identity.
    if (req.client_id !== session.client_id) {
      throw new GrantError('invalid_grant', 'client_id does not match the authorization request');
    }
    if (req.redirect_uri !== session.redirect_uri) {
      throw new GrantError('invalid_grant', 'redirect_uri does not match the authorization request');
    }
    this.verifyPkce(session, req.code_verifier);

    const {issuer, accessLifetime, idLifetime} = this.resolveConfig(provider);
    // Re-mint, never forward: the downstream sub is broker-controlled, derived from the upstream sub.
    const subject = this.mintSubject(session.client_id, code.subject);
    const scope = session.scope;

    const access = await this.tokens.issueAccessToken({
      issuer, subject, client_id: session.client_id, audience: session.client_id, lifetime: accessLifetime, scope,
    });
    const id = await this.tokens.issueIdToken({
      issuer, subject, audience: session.client_id, lifetime: idLifetime, nonce: session.nonce,
    });
    const refresh = this.sessions.storeRefreshToken({
      subject, client_id: session.client_id, scope, upstream_refresh_token: code.upstream_tokens.refresh_token,
    });
    return this.tokenResponse(access.token, id.token, refresh.token, accessLifetime, scope);
  }

  /**
   * refresh_token: rotate a live token (revoke it, mint a new one in the same family); on a
   * revoked (already-rotated) token, treat it as reuse and revoke the whole family (gate §H).
   */
  private async refreshTokenGrant(provider: ProviderEntryType, req: RefreshRequest): Promise<TokenResponse> {
    const live = this.sessions.getRefreshToken(req.refresh_token);
    if (!live) {
      const raw = this.sessions.findRefreshToken(req.refresh_token);
      if (raw && raw.revoked) {
        this.sessions.revokeRefreshFamily(raw.family_id);
        throw new GrantError('invalid_grant', 'refresh token reuse detected');
      }
      throw new GrantError('invalid_grant', 'unknown or expired refresh token');
    }

    const {issuer, accessLifetime, idLifetime} = this.resolveConfig(provider);
    this.sessions.revokeRefreshToken(live.token);

    const access = await this.tokens.issueAccessToken({
      issuer, subject: live.subject, client_id: live.client_id, audience: live.client_id, lifetime: accessLifetime, scope: live.scope,
    });
    const id = await this.tokens.issueIdToken({
      issuer, subject: live.subject, audience: live.client_id, lifetime: idLifetime,
    });
    const rotated = this.sessions.storeRefreshToken({
      subject: live.subject, client_id: live.client_id, scope: live.scope,
      family_id: live.family_id, upstream_refresh_token: live.upstream_refresh_token,
    });
    return this.tokenResponse(access.token, id.token, rotated.token, accessLifetime, live.scope);
  }

  /** Verify the PKCE code_verifier against the stored S256 challenge (and defend against downgrade). */
  private verifyPkce(session: AuthorizationSession, codeVerifier: string | undefined): void {
    if (session.code_challenge) {
      if (!codeVerifier) {
        throw new GrantError('invalid_grant', 'code_verifier is required');
      }
      const challenge = createHash('sha256').update(codeVerifier).digest('base64url');
      if (!constantTimeEqual(challenge, session.code_challenge)) {
        throw new GrantError('invalid_grant', 'PKCE verification failed');
      }
      return;
    }
    // No challenge was registered: a code_verifier must not be presented (PKCE downgrade defense, gate §A).
    if (codeVerifier) {
      throw new GrantError('invalid_grant', 'code_verifier sent but no code_challenge was registered');
    }
  }

  /** Resolve this provider's issuer (required) and token lifetimes (with defaults) in one place. */
  private resolveConfig(provider: ProviderEntryType): {issuer: string; accessLifetime: number; idLifetime: number} {
    const cfg = provider.OidcConfig;
    if (!cfg?.issuer) {
      throw new GrantError('server_error', 'provider has no issuer configured');
    }
    return {
      issuer: cfg.issuer,
      accessLifetime: cfg.access_token_lifetime ?? DEFAULT_ACCESS_TOKEN_LIFETIME,
      idLifetime: cfg.id_token_lifetime ?? DEFAULT_ID_TOKEN_LIFETIME,
    };
  }

  private tokenResponse(accessToken: string, idToken: string, refreshToken: string, expiresIn: number, scope: string): TokenResponse {
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      id_token: idToken,
      scope,
    };
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('GrantService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const grantService = new GrantService();

// Class exported for isolated tests.
export {GrantService};
