// src/services/oidc/federation.service.ts
// The upstream federation flow: turn a downstream authorization request into a
// redirect to the upstream provider (begin), then turn the upstream's callback
// into a one-time Passage authorization code redirected back to the downstream
// client (complete).
//
// Passage is the OAuth client of the upstream here, so it runs its OWN PKCE +
// state + nonce on the broker→upstream leg, stored on the authorization session.
// The upstream `state` IS the session id, so the callback finds the session.
//
// Logic lives here (not in route handlers) so it is unit-testable to the repo's
// 100% line + 100% Stryker mutation gates. Collaborators are injectable seams.
// The openid-client functions are reached via the live module namespace `clientNS`
// (one `oidc` seam) so test module-mocks are honoured at call time.
import * as clientNS from 'openid-client';
import {upstreamOidc} from '../upstream/oidc-client.service';
import {sessionService} from './session.service';
import {ProviderEntryType} from '../../utils/schemas/config.schemas';
import {AuthorizationRequestValidated} from '../../utils/schemas/oidc.schemas';
import {
  AuthorizationSession,
  AuthorizationCode,
  UserInfoResponse,
  AuthorizationErrorCode,
} from '../../types/oidc.types';

/** Error carrying an OAuth error code, so the thin route maps it to a status without logging. */
export class FederationError extends Error {
  constructor(public readonly code: AuthorizationErrorCode, message: string) {
    super(message);
    this.name = 'FederationError';
  }
}

/** The openid-client functions the flow uses; the module namespace satisfies this. */
export interface OidcClientFns {
  randomPKCECodeVerifier(): string;
  calculatePKCECodeChallenge(verifier: string): Promise<string>;
  randomNonce(): string;
  buildAuthorizationUrl(config: clientNS.Configuration, params: Record<string, string>): URL;
  authorizationCodeGrant(
    config: clientNS.Configuration,
    currentUrl: URL,
    checks: {expectedState: string; expectedNonce: string; pkceCodeVerifier: string},
  ): Promise<clientNS.TokenEndpointResponse & {claims(): clientNS.IDToken | undefined}>;
  fetchUserInfo(config: clientNS.Configuration, accessToken: string, expectedSubject: string): Promise<clientNS.UserInfoResponse>;
}

/** The slice of upstreamOidc this service depends on. */
export interface UpstreamConfigProvider {
  getConfig(providerName: string): clientNS.Configuration;
}

/** The slice of sessionService this service depends on. */
export interface SessionStore {
  createSession(input: Omit<AuthorizationSession, 'id' | 'created_at' | 'expires_at'>): AuthorizationSession;
  getSession(id: string): AuthorizationSession | undefined;
  createCode(input: Omit<AuthorizationCode, 'code' | 'created_at' | 'expires_at' | 'consumed'>): AuthorizationCode;
}

export interface FederationServiceOptions {
  oidc?: Partial<OidcClientFns>;      // override openid-client functions (default: live module namespace)
  upstream?: UpstreamConfigProvider;  // default: upstreamOidc singleton
  sessions?: SessionStore;            // default: sessionService singleton
}

export interface BeginAuthorizationParams {
  provider: ProviderEntryType;
  request: AuthorizationRequestValidated;
}

export interface CompleteCallbackParams {
  provider: ProviderEntryType;
  /** Absolute callback URL including the upstream's query (state, code, iss). */
  currentUrl: URL;
}

class FederationService {
  // openid-client functions are reached at CALL TIME via the live module namespace `clientNS`
  // (see `oidc()` below), so a test module-mock of openid-client is honoured. `overrides` lets
  // tests substitute individual functions without going through the module system.
  private overrides: Partial<OidcClientFns> = {};
  private upstream: UpstreamConfigProvider = upstreamOidc;
  private sessions: SessionStore = sessionService;
  private initialized = false;

  /** Use the exported {@link federationService} singleton; the class is exported for tests. */
  constructor() {}

  initialize(opts: FederationServiceOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.oidc) {
      this.overrides = opts.oidc;
    }
    if (opts.upstream) {
      this.upstream = opts.upstream;
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

  /**
   * Begin a federated login: validate, create an authorization session carrying the
   * upstream-leg PKCE/nonce, and return the upstream authorization URL to redirect to.
   */
  async beginAuthorization(params: BeginAuthorizationParams): Promise<{redirectUrl: string}> {
    this.ensureInitialized();
    const {provider, request} = params;

    if (request.response_type !== 'code') {
      throw new FederationError('unsupported_response_type', 'unsupported response_type');
    }

    const {issuer, scope} = this.resolveProvider(provider);
    const config = this.upstream.getConfig(provider.name);

    const codeVerifier = (this.overrides.randomPKCECodeVerifier ?? clientNS.randomPKCECodeVerifier)();
    const codeChallenge = await (this.overrides.calculatePKCECodeChallenge ?? clientNS.calculatePKCECodeChallenge)(codeVerifier);
    const nonce = (this.overrides.randomNonce ?? clientNS.randomNonce)();

    const session = this.sessions.createSession({
      client_id: request.client_id,
      redirect_uri: request.redirect_uri,
      scope: request.scope,
      state: request.state,
      nonce: request.nonce,
      code_challenge: request.code_challenge,
      code_challenge_method: request.code_challenge_method,
      response_type: request.response_type,
      upstream_provider: provider.name,
      upstream_nonce: nonce,
      upstream_code_verifier: codeVerifier,
    });

    const url = (this.overrides.buildAuthorizationUrl ?? clientNS.buildAuthorizationUrl)(config, {
      redirect_uri: `${issuer}/callback`,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: session.id,
      nonce,
    });

    return {redirectUrl: url.href};
  }

  /**
   * Complete a federated login: exchange the upstream code, fetch userinfo, mint a
   * one-time Passage authorization code, and return the downstream redirect URL.
   */
  async completeCallback(params: CompleteCallbackParams): Promise<{redirectUrl: string}> {
    this.ensureInitialized();
    const {currentUrl} = params;

    const state = currentUrl.searchParams.get('state');
    if (!state) {
      throw new FederationError('invalid_request', 'missing state');
    }
    const session = this.sessions.getSession(state);
    if (!session) {
      throw new FederationError('invalid_request', 'unknown or expired session');
    }

    const config = this.upstream.getConfig(session.upstream_provider);

    let tokens;
    try {
      tokens = await (this.overrides.authorizationCodeGrant ?? clientNS.authorizationCodeGrant)(config, currentUrl, {
        expectedState: session.id,
        expectedNonce: session.upstream_nonce!,
        pkceCodeVerifier: session.upstream_code_verifier!,
      });
    } catch {
      throw new FederationError('access_denied', 'upstream code exchange failed');
    }

    const claims = tokens.claims();
    if (!claims?.sub) {
      throw new FederationError('access_denied', 'upstream id_token missing sub');
    }
    const subject = claims.sub;

    let userInfo: UserInfoResponse;
    try {
      userInfo = (await (this.overrides.fetchUserInfo ?? clientNS.fetchUserInfo)(config, tokens.access_token, subject)) as UserInfoResponse;
    } catch {
      throw new FederationError('access_denied', 'userinfo request failed');
    }

    const code = this.sessions.createCode({
      session_id: session.id,
      subject,
      user_info: userInfo,
      upstream_tokens: {
        access_token: tokens.access_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        scope: tokens.scope,
      },
    });

    const redirect = new URL(session.redirect_uri);
    redirect.searchParams.set('code', code.code);
    if (session.state !== undefined) {
      redirect.searchParams.set('state', session.state);
    }
    return {redirectUrl: redirect.href};
  }

  /**
   * Resolve the per-provider issuer (required) and the upstream scope string in one place,
   * so `OidcConfig` is accessed once. Throws `server_error` if no issuer is configured.
   */
  private resolveProvider(provider: ProviderEntryType): {issuer: string; scope: string} {
    const cfg = provider.OidcConfig;
    if (!cfg?.issuer) {
      throw new FederationError('server_error', 'provider has no issuer configured');
    }
    const scopes = cfg.upstream_scopes;
    return {issuer: cfg.issuer, scope: scopes && scopes.length > 0 ? scopes.join(' ') : 'openid'};
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('FederationService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const federationService = new FederationService();

// Class exported for isolated tests.
export {FederationService};
