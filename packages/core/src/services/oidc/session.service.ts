// src/services/oidc/session.service.ts
// In-memory store for short-lived OIDC authorization state: authorization
// sessions (PKCE/state/nonce), one-time authorization codes, and refresh tokens.
//
// Storage is intentionally an in-process Map — suitable for development and the
// single-instance default. A persistent backend (Redis/DB) is a later concern;
// the public surface here is what a backend would implement.
//
// All non-determinism (time, id generation) is injected via {@link SessionServiceOptions}
// so behaviour is fully pinnable in tests. Defaults are real (wall clock, UUIDs).
import {randomUUID} from 'node:crypto';
import {
  AuthorizationSession,
  AuthorizationCode,
  RefreshTokenData,
} from '../../types/oidc.types';

/** Epoch milliseconds source. */
export type Clock = () => number;
/** Opaque identifier source (session ids, codes, refresh tokens). */
export type IdGenerator = () => string;

export interface SessionServiceOptions {
  /** Epoch-ms clock. Default: {@link Date.now}. */
  clock?: Clock;
  /** Identifier generator. Default: {@link randomUUID}. */
  generateId?: IdGenerator;
  /** Authorization session lifetime (ms). Default: 10 minutes. */
  sessionTtlMs?: number;
  /** Authorization code lifetime (ms). Default: 1 minute. */
  codeTtlMs?: number;
  /** Refresh token lifetime (ms). Default: 30 days. */
  refreshTtlMs?: number;
}

const DEFAULT_SESSION_TTL_MS = 10 * 60 * 1000;
const DEFAULT_CODE_TTL_MS = 60 * 1000;
const DEFAULT_REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Fields the caller supplies; the service stamps id/code/token + timestamps. */
type SessionInput = Omit<AuthorizationSession, 'id' | 'created_at' | 'expires_at'>;
type CodeInput = Omit<AuthorizationCode, 'code' | 'created_at' | 'expires_at' | 'consumed'>;
type RefreshInput = Omit<RefreshTokenData, 'token' | 'created_at' | 'expires_at' | 'revoked'>;

class SessionService {
  private sessions = new Map<string, AuthorizationSession>();
  private codes = new Map<string, AuthorizationCode>();
  private refreshTokens = new Map<string, RefreshTokenData>();

  private clock: Clock = Date.now;
  private generateId: IdGenerator = randomUUID;
  private sessionTtlMs = DEFAULT_SESSION_TTL_MS;
  private codeTtlMs = DEFAULT_CODE_TTL_MS;
  private refreshTtlMs = DEFAULT_REFRESH_TTL_MS;
  private initialized = false;

  /** Use the exported {@link sessionService} singleton; the class is exported for tests. */
  constructor() {}

  /** Wire the store. Idempotent — the first call wins. */
  initialize(opts: SessionServiceOptions = {}): void {
    if (this.initialized) {
      return;
    }
    if (opts.clock) {
      this.clock = opts.clock;
    }
    if (opts.generateId) {
      this.generateId = opts.generateId;
    }
    if (opts.sessionTtlMs !== undefined) {
      this.sessionTtlMs = opts.sessionTtlMs;
    }
    if (opts.codeTtlMs !== undefined) {
      this.codeTtlMs = opts.codeTtlMs;
    }
    if (opts.refreshTtlMs !== undefined) {
      this.refreshTtlMs = opts.refreshTtlMs;
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  /** Clear all state and mark uninitialized (for tests / re-bootstrap). */
  reset(): void {
    this.sessions.clear();
    this.codes.clear();
    this.refreshTokens.clear();
    this.initialized = false;
  }

  // ---------------------------------------------------------------------------
  // Authorization sessions
  // ---------------------------------------------------------------------------

  createSession(input: SessionInput): AuthorizationSession {
    this.ensureInitialized();
    const now = this.clock();
    const session: AuthorizationSession = {
      ...input,
      id: this.generateId(),
      created_at: now,
      expires_at: now + this.sessionTtlMs,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /** Returns the session, or `undefined` if unknown or expired. */
  getSession(id: string): AuthorizationSession | undefined {
    this.ensureInitialized();
    const session = this.sessions.get(id);
    if (!session) {
      return undefined;
    }
    if (this.isExpired(session.expires_at)) {
      return undefined;
    }
    return session;
  }

  // ---------------------------------------------------------------------------
  // Authorization codes (one-time use)
  // ---------------------------------------------------------------------------

  createCode(input: CodeInput): AuthorizationCode {
    this.ensureInitialized();
    const now = this.clock();
    const entry: AuthorizationCode = {
      ...input,
      code: this.generateId(),
      created_at: now,
      expires_at: now + this.codeTtlMs,
      consumed: false,
    };
    this.codes.set(entry.code, entry);
    return entry;
  }

  /**
   * Redeem a code exactly once. Returns the record and marks it consumed;
   * any subsequent call (or an unknown/expired code) returns `undefined`.
   */
  consumeCode(code: string): AuthorizationCode | undefined {
    this.ensureInitialized();
    const entry = this.codes.get(code);
    if (!entry) {
      return undefined;
    }
    if (entry.consumed) {
      return undefined;
    }
    if (this.isExpired(entry.expires_at)) {
      return undefined;
    }
    entry.consumed = true;
    return entry;
  }

  // ---------------------------------------------------------------------------
  // Refresh tokens
  // ---------------------------------------------------------------------------

  storeRefreshToken(input: RefreshInput): RefreshTokenData {
    this.ensureInitialized();
    const now = this.clock();
    const entry: RefreshTokenData = {
      ...input,
      token: this.generateId(),
      created_at: now,
      expires_at: now + this.refreshTtlMs,
      revoked: false,
    };
    this.refreshTokens.set(entry.token, entry);
    return entry;
  }

  /** Returns the token record, or `undefined` if unknown, revoked, or expired. */
  getRefreshToken(token: string): RefreshTokenData | undefined {
    this.ensureInitialized();
    const entry = this.refreshTokens.get(token);
    if (!entry) {
      return undefined;
    }
    if (entry.revoked) {
      return undefined;
    }
    if (this.isExpired(entry.expires_at)) {
      return undefined;
    }
    return entry;
  }

  /** Revoke a refresh token. Returns `true` if a live token was revoked. */
  revokeRefreshToken(token: string): boolean {
    this.ensureInitialized();
    const entry = this.refreshTokens.get(token);
    if (!entry) {
      return false;
    }
    entry.revoked = true;
    return true;
  }

  private isExpired(expiresAt: number): boolean {
    return this.clock() >= expiresAt;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('SessionService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const sessionService = new SessionService();

// Class exported for isolated tests.
export {SessionService};
