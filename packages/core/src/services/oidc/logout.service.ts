// src/services/oidc/logout.service.ts
// RP-Initiated Logout (OIDC). Passage keeps no OP login session / cookie, so logout has no server
// session to terminate; it validates the request and computes the post-logout redirect:
//   - the id_token_hint must be a Passage-issued token for THIS provider authority (iss check);
//   - the post_logout_redirect_uri must be registered for the client the hint was issued to.
// An unregistered post_logout_redirect_uri is NEVER redirected to (open-redirect defense) — it is a
// direct error. With no post_logout_redirect_uri, logout is a direct confirmation (no redirect).
//
// Logger-free; the only seams are the token verifier + the client registry (both defaulted).
import {tokenService} from './token.service';
import {clientRegistry} from './client-registry.service';
import {AccessTokenClaims, IDTokenClaims} from '../../types/oidc.types';
import {ClientEntryType} from '../../utils/schemas/config.schemas';

/** Error carrying the OAuth code for a bad logout request (the route maps it to a direct 400). */
export class LogoutError extends Error {
  constructor(public readonly code: 'invalid_request', message: string) {
    super(message);
    this.name = 'LogoutError';
  }
}

/** Verifies a Passage-issued token (the id_token_hint) and returns its claims. */
export type LogoutVerifier = (token: string) => Promise<AccessTokenClaims | IDTokenClaims>;

/** The slice of the client registry logout depends on. */
export interface LogoutClientRegistry {
  getClient(clientId: string): ClientEntryType | undefined;
}

export interface LogoutServiceInitOptions {
  verify?: LogoutVerifier;          // default: tokenService.verify
  clients?: LogoutClientRegistry;   // default: clientRegistry
}

export interface EndSessionParams {
  id_token_hint?: string;
  post_logout_redirect_uri?: string;
  state?: string;
  client_id?: string;
  /** This provider authority's issuer — the expected `iss` of the id_token_hint. */
  issuer: string;
}

class LogoutService {
  private verify: LogoutVerifier = (token) => tokenService.verify(token);
  private clients: LogoutClientRegistry = clientRegistry;
  private initialized = false;

  /** Use the exported {@link logoutService} singleton; the class is exported for tests. */
  constructor() {}

  initialize(opts: LogoutServiceInitOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.verify) {
      this.verify = opts.verify;
    }
    if (opts.clients) {
      this.clients = opts.clients;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.initialized = false;
  }

  /**
   * Validate an RP-initiated logout request. Returns `{redirectUrl}` for a registered
   * post_logout_redirect_uri, or `{}` (a direct confirmation) when none is supplied.
   */
  async endSession(params: EndSessionParams): Promise<{redirectUrl?: string}> {
    this.ensureInitialized();
    let claims: AccessTokenClaims | IDTokenClaims | undefined;
    if (params.id_token_hint) {
      try {
        claims = await this.verify(params.id_token_hint);
      } catch {
        throw new LogoutError('invalid_request', 'invalid id_token_hint');
      }
      if (claims.iss !== params.issuer) {
        throw new LogoutError('invalid_request', 'id_token_hint issuer mismatch');
      }
    }
    if (params.post_logout_redirect_uri) {
      if (!claims) {
        throw new LogoutError('invalid_request', 'post_logout_redirect_uri requires id_token_hint');
      }
      const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
      if (params.client_id && params.client_id !== aud) {
        throw new LogoutError('invalid_request', 'client_id does not match id_token_hint');
      }
      const client = this.clients.getClient(aud);
      if (!client || !client.post_logout_redirect_uris?.includes(params.post_logout_redirect_uri)) {
        throw new LogoutError('invalid_request', 'post_logout_redirect_uri not registered');
      }
      const url = new URL(params.post_logout_redirect_uri);
      if (params.state !== undefined) {
        url.searchParams.set('state', params.state);
      }
      return {redirectUrl: url.href};
    }
    return {};
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('LogoutService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const logoutService = new LogoutService();

// Class exported for isolated tests.
export {LogoutService};
