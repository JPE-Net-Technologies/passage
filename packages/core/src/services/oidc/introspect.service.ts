// src/services/oidc/introspect.service.ts
// Token introspection (RFC 7662): tell an authenticated caller whether a token is active and, if so,
// its claims. Access tokens are stateless JWTs (verified via tokenService); refresh tokens are looked
// up in the session store. Two security properties beyond mere validity:
//   - the token must belong to THIS provider authority (iss match) — Passage is multi-authority; and
//   - it must belong to the AUTHENTICATED caller (client_id match) — otherwise introspection is a
//     token-scanning oracle. A token failing either check is reported as just `{active:false}`, never
//     an error (RFC 7662 §2.2).
//
// Logic lives here (not the route) so it is unit-testable to the repo's 100% line + 100% mutation
// gates; collaborators are injectable seams. `token_type_hint` is intentionally ignored (§2.1 permits
// it): both kinds are always checked, so honouring the hint could only change ordering, not results.
import {sessionService} from './session.service';
import {tokenService} from './token.service';
import {AccessTokenClaims, IDTokenClaims, IntrospectionResponse, RefreshTokenData} from '../../types/oidc.types';

/** The slice of tokenService the introspection flow depends on. */
export interface IntrospectTokenVerifier {
  verify(token: string): Promise<AccessTokenClaims | IDTokenClaims>;
}

/** The slice of sessionService the introspection flow depends on (only LIVE tokens — §"active"). */
export interface IntrospectSessionStore {
  getRefreshToken(token: string): RefreshTokenData | undefined;
}

export interface IntrospectServiceOptions {
  tokens?: IntrospectTokenVerifier;  // default: tokenService singleton
  sessions?: IntrospectSessionStore; // default: sessionService singleton
}

/** The authority + caller a token is introspected against. */
export interface IntrospectContext {
  /** This provider authority's issuer; a token minted by another authority is reported inactive. */
  expectedIssuer: string;
  /** The authenticated caller; only its own tokens are revealed (anti-oracle). */
  callerClientId: string;
}

/** The single inactive response — an unknown/expired/revoked/foreign token reveals nothing else. */
const INACTIVE: IntrospectionResponse = {active: false};

class IntrospectService {
  private tokens: IntrospectTokenVerifier = tokenService;
  private sessions: IntrospectSessionStore = sessionService;
  private initialized = false;

  /** Use the exported {@link introspectService} singleton; the class is exported for tests. */
  constructor() {}

  initialize(opts: IntrospectServiceOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.tokens) {
      this.tokens = opts.tokens;
    }
    if (opts.sessions) {
      this.sessions = opts.sessions;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.initialized = false;
  }

  /** Introspect a token for the authenticated caller. Never throws on a bad token — returns inactive. */
  async introspect(token: string, ctx: IntrospectContext): Promise<IntrospectionResponse> {
    this.ensureInitialized();
    // A verifiable JWT yields its own active/inactive verdict; only a token that is NOT a Passage
    // access token (verify threw → undefined) falls through to the refresh-token lookup.
    const asAccess = await this.introspectAccessToken(token, ctx);
    if (asAccess) {
      return asAccess;
    }
    return this.introspectRefreshToken(token, ctx);
  }

  /** A Passage-signed access token: active iff it verifies, is ours (iss), and is the caller's. */
  private async introspectAccessToken(token: string, ctx: IntrospectContext): Promise<IntrospectionResponse | undefined> {
    let claims: AccessTokenClaims | IDTokenClaims;
    try {
      claims = await this.tokens.verify(token);
    } catch {
      return undefined; // not a verifiable access token — fall through to the refresh-token lookup
    }
    if (claims.iss !== ctx.expectedIssuer || claims.client_id !== ctx.callerClientId) {
      return INACTIVE;
    }
    return {
      active: true,
      sub: claims.sub,
      scope: claims.scope as string | undefined,
      client_id: claims.client_id as string,
      aud: claims.aud,
      iss: claims.iss,
      exp: claims.exp,
      iat: claims.iat,
      jti: claims.jti as string | undefined,
      token_type: 'Bearer',
    };
  }

  /** A refresh token: active iff the store holds a live record for it and it is the caller's. */
  private introspectRefreshToken(token: string, ctx: IntrospectContext): IntrospectionResponse {
    const rt = this.sessions.getRefreshToken(token);
    if (!rt || rt.client_id !== ctx.callerClientId) {
      return INACTIVE;
    }
    return {
      active: true,
      sub: rt.subject,
      scope: rt.scope,
      client_id: rt.client_id,
      iss: ctx.expectedIssuer,
      exp: Math.floor(rt.expires_at / 1000),
      iat: Math.floor(rt.created_at / 1000),
    };
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('IntrospectService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const introspectService = new IntrospectService();

// Class exported for isolated tests.
export {IntrospectService};
