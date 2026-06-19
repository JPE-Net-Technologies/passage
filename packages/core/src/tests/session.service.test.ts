// tests/session.service.test.ts — in-memory OIDC session/code/refresh store.
//
// Every test constructs a fresh `new SessionService()` and injects the clock and
// id generator so timestamps and identifiers are fully deterministic. Default
// (uninjected) behaviour is exercised separately so the real wall-clock / UUID
// seams are covered too.
import {describe, it, expect} from 'bun:test';
import {SessionService} from '../services/oidc/session.service';
import type {UserInfoResponse, UpstreamTokens} from '../types/oidc.types';

// Default TTLs (mirrors the constants in session.service.ts).
const SESSION_TTL = 10 * 60 * 1000;
const CODE_TTL = 60 * 1000;
const REFRESH_TTL = 30 * 24 * 60 * 60 * 1000;

const USER_INFO: UserInfoResponse = {sub: 'user-123', email: 'a@b.test', email_verified: true};
const UPSTREAM_TOKENS: UpstreamTokens = {access_token: 'up-at', token_type: 'Bearer'};

const sessionInput = () => ({
  client_id: 'downstream',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid profile',
  state: 'st',
  nonce: 'no',
  response_type: 'code' as const,
  upstream_provider: 'keycloak',
});
const codeInput = () => ({
  session_id: 'sess-1',
  subject: 'user-123',
  user_info: USER_INFO,
  upstream_tokens: UPSTREAM_TOKENS,
});
const refreshInput = () => ({
  subject: 'user-123',
  client_id: 'downstream',
  scope: 'openid',
});

/** Counter-based id generator: id-1, id-2, … */
const counterIds = () => {
  let n = 0;
  return () => `id-${++n}`;
};

describe('SessionService — guards before init', () => {
  it('throws on every accessor before initialization', () => {
    const s = new SessionService();
    expect(s.isInitialized()).toBe(false);
    expect(() => s.createSession(sessionInput())).toThrow('not initialized');
    expect(() => s.getSession('x')).toThrow('not initialized');
    expect(() => s.createCode(codeInput())).toThrow('not initialized');
    expect(() => s.consumeCode('x')).toThrow('not initialized');
    expect(() => s.storeRefreshToken(refreshInput())).toThrow('not initialized');
    expect(() => s.getRefreshToken('x')).toThrow('not initialized');
    expect(() => s.revokeRefreshToken('x')).toThrow('not initialized');
    expect(() => s.findRefreshToken('x')).toThrow('not initialized');
    expect(() => s.revokeRefreshFamily('x')).toThrow('not initialized');
  });
});

describe('SessionService — stamping with default TTLs', () => {
  const NOW = 1_000_000;
  const fresh = () => {
    const s = new SessionService();
    s.initialize({clock: () => NOW, generateId: counterIds()});
    return s;
  };

  it('stamps a session id, created_at, and default expiry', () => {
    const session = fresh().createSession(sessionInput());
    expect(session.id).toBe('id-1');
    expect(session.created_at).toBe(NOW);
    expect(session.expires_at).toBe(NOW + SESSION_TTL);
    expect(session.client_id).toBe('downstream');
    expect(session.scope).toBe('openid profile');
  });

  it('stamps a code, default expiry, and consumed=false', () => {
    const code = fresh().createCode(codeInput());
    expect(code.code).toBe('id-1');
    expect(code.created_at).toBe(NOW);
    expect(code.expires_at).toBe(NOW + CODE_TTL);
    expect(code.consumed).toBe(false);
    expect(code.subject).toBe('user-123');
  });

  it('stamps a refresh token, a generated family id, default expiry, and revoked=false', () => {
    const rt = fresh().storeRefreshToken(refreshInput());
    expect(rt.token).toBe('id-1');
    expect(rt.family_id).toBe('id-2'); // family id generated after the token id when none supplied
    expect(rt.created_at).toBe(NOW);
    expect(rt.expires_at).toBe(NOW + REFRESH_TTL);
    expect(rt.revoked).toBe(false);
  });

  it('reuses a supplied family id without consuming a generated id for it', () => {
    const rt = fresh().storeRefreshToken({...refreshInput(), family_id: 'fam-X'});
    expect(rt.family_id).toBe('fam-X');
    expect(rt.token).toBe('id-1'); // generateId ran exactly once — for the token only
  });
});

describe('SessionService — custom TTLs are honoured', () => {
  const NOW = 5_000;
  const fresh = () => {
    const s = new SessionService();
    s.initialize({
      clock: () => NOW,
      generateId: counterIds(),
      sessionTtlMs: 11,
      codeTtlMs: 22,
      refreshTtlMs: 33,
    });
    return s;
  };

  it('uses the injected session/code/refresh lifetimes', () => {
    const s = fresh();
    expect(s.createSession(sessionInput()).expires_at).toBe(NOW + 11);
    expect(s.createCode(codeInput()).expires_at).toBe(NOW + 22);
    expect(s.storeRefreshToken(refreshInput()).expires_at).toBe(NOW + 33);
  });
});

describe('SessionService — session retrieval & expiry', () => {
  it('returns a live session and undefined for unknown ids', () => {
    let now = 1_000;
    const s = new SessionService();
    s.initialize({clock: () => now, generateId: counterIds(), sessionTtlMs: 100});
    const created = s.createSession(sessionInput());

    expect(s.getSession(created.id)).toEqual(created); // not expired
    expect(s.getSession('missing')).toBeUndefined();

    now = created.expires_at - 1; // still live just before expiry
    expect(s.getSession(created.id)).toEqual(created);

    now = created.expires_at; // expired at the boundary (>=)
    expect(s.getSession(created.id)).toBeUndefined();
  });
});

describe('SessionService — one-time codes', () => {
  it('redeems a code exactly once', () => {
    const s = new SessionService();
    s.initialize({clock: () => 0, generateId: counterIds(), codeTtlMs: 100});
    const created = s.createCode(codeInput());

    const first = s.consumeCode(created.code);
    expect(first).toBeDefined();
    expect(first!.consumed).toBe(true);
    expect(first!.subject).toBe('user-123');

    expect(s.consumeCode(created.code)).toBeUndefined(); // already consumed
    expect(s.consumeCode('missing')).toBeUndefined();
  });

  it('rejects an expired code', () => {
    let now = 0;
    const s = new SessionService();
    s.initialize({clock: () => now, generateId: counterIds(), codeTtlMs: 100});
    const created = s.createCode(codeInput());
    now = created.expires_at;
    expect(s.consumeCode(created.code)).toBeUndefined();
  });
});

describe('SessionService — refresh tokens', () => {
  it('stores, retrieves, and revokes', () => {
    const s = new SessionService();
    s.initialize({clock: () => 0, generateId: counterIds(), refreshTtlMs: 100});
    const rt = s.storeRefreshToken(refreshInput());

    expect(s.getRefreshToken(rt.token)).toEqual(rt); // live
    expect(s.getRefreshToken('missing')).toBeUndefined();

    expect(s.revokeRefreshToken(rt.token)).toBe(true);
    expect(s.getRefreshToken(rt.token)).toBeUndefined(); // revoked
    expect(s.revokeRefreshToken('missing')).toBe(false);
    expect(s.revokeRefreshToken(rt.token)).toBe(true); // idempotent re-revoke of a known token
  });

  it('rejects an expired refresh token', () => {
    let now = 0;
    const s = new SessionService();
    s.initialize({clock: () => now, generateId: counterIds(), refreshTtlMs: 100});
    const rt = s.storeRefreshToken(refreshInput());
    now = rt.expires_at;
    expect(s.getRefreshToken(rt.token)).toBeUndefined();
  });

  it('findRefreshToken returns records regardless of revoked or expired state', () => {
    let now = 0;
    const s = new SessionService();
    s.initialize({clock: () => now, generateId: counterIds(), refreshTtlMs: 100});
    const rt = s.storeRefreshToken(refreshInput());

    expect(s.findRefreshToken(rt.token)).toEqual(rt); // live
    expect(s.findRefreshToken('missing')).toBeUndefined();

    s.revokeRefreshToken(rt.token);
    expect(s.findRefreshToken(rt.token)!.revoked).toBe(true); // revoked is still surfaced (reuse detection)

    now = rt.expires_at; // past expiry
    expect(s.findRefreshToken(rt.token)).toBeDefined(); // expiry does not hide it either
  });

  it('revokeRefreshFamily revokes the whole family and leaves other families live', () => {
    const s = new SessionService();
    s.initialize({clock: () => 0, generateId: counterIds(), refreshTtlMs: 1e9});
    const a1 = s.storeRefreshToken({...refreshInput(), family_id: 'famA'});
    const a2 = s.storeRefreshToken({...refreshInput(), family_id: 'famA'});
    const b1 = s.storeRefreshToken({...refreshInput(), family_id: 'famB'});

    expect(s.revokeRefreshFamily('famA')).toBe(2); // exactly the two famA members
    expect(s.getRefreshToken(a1.token)).toBeUndefined();
    expect(s.getRefreshToken(a2.token)).toBeUndefined();
    expect(s.getRefreshToken(b1.token)).toEqual(b1); // famB untouched
    expect(s.revokeRefreshFamily('famNope')).toBe(0); // unknown family revokes nothing
  });
});

describe('SessionService — lifecycle', () => {
  it('is idempotent: the first initialize wins', () => {
    const s = new SessionService();
    s.initialize({clock: () => 1, generateId: () => 'first'});
    s.initialize({clock: () => 2, generateId: () => 'second'}); // ignored
    const session = s.createSession(sessionInput());
    expect(session.id).toBe('first');
    expect(session.created_at).toBe(1);
  });

  it('reset clears all three stores and uninitializes', () => {
    const s = new SessionService();
    s.initialize({clock: () => 0, generateId: counterIds(), sessionTtlMs: 1e9, codeTtlMs: 1e9, refreshTtlMs: 1e9});
    const session = s.createSession(sessionInput());
    const code = s.createCode(codeInput());
    const rt = s.storeRefreshToken(refreshInput());

    s.reset();
    expect(s.isInitialized()).toBe(false);

    s.initialize({clock: () => 0, generateId: counterIds(), sessionTtlMs: 1e9, codeTtlMs: 1e9, refreshTtlMs: 1e9});
    expect(s.getSession(session.id)).toBeUndefined();
    expect(s.consumeCode(code.code)).toBeUndefined();
    expect(s.getRefreshToken(rt.token)).toBeUndefined();
  });
});

describe('SessionService — real (uninjected) seams', () => {
  it('uses the wall clock and UUID generator by default', () => {
    const s = new SessionService();
    s.initialize();
    const before = Date.now();
    const session = s.createSession(sessionInput());
    const after = Date.now();

    expect(typeof session.id).toBe('string');
    expect(session.id.length).toBeGreaterThan(0);
    expect(session.created_at).toBeGreaterThanOrEqual(before);
    expect(session.created_at).toBeLessThanOrEqual(after);
    expect(session.expires_at).toBe(session.created_at + SESSION_TTL);

    // distinct identifiers
    const session2 = s.createSession(sessionInput());
    expect(session2.id).not.toBe(session.id);
  });
});
