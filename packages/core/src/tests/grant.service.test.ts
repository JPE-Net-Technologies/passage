// tests/grant.service.test.ts — OP-leg token grants (authorization_code + refresh_token).
//
// The flow is exercised with capturing stubs for the session store and token issuer, so every
// value handed to them (re-minted subject, issuer, audience, scope, nonce, lifetimes, refresh
// family) is asserted. A separate pure-defaults case runs the real session/token/jwks singletons
// end-to-end so the uninjected seams (and the default subject mapper) are covered too.
import {describe, it, expect} from 'bun:test';
import {createHash} from 'node:crypto';
import {GrantService, GrantError, defaultSubjectMapper} from '../services/oidc/grant.service';
import type {GrantSessionStore, GrantTokenIssuer} from '../services/oidc/grant.service';
import {sessionService} from '../services/oidc/session.service';
import {tokenService} from '../services/oidc/token.service';
import {jwksService} from '../services/oidc/jwks.service';
import type {AuthorizationCode, AuthorizationSession, RefreshTokenData} from '../types/oidc.types';
import type {TokenRequestValidated} from '../utils/schemas/oidc.schemas';

const s256 = (v: string) => createHash('sha256').update(v).digest('base64url');

const provider = (oidcOver: Record<string, any> = {}): any => ({
  name: 'oidc-x',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: 'oidc-x', client_id: 'c'},
  OidcConfig: {supported_auth_flows: ['authorization_code'], issuer: 'https://iss.test/oidc-x', ...oidcOver},
});

const sessionRecord = (over: Partial<AuthorizationSession> = {}): AuthorizationSession => ({
  id: 'sess-1',
  client_id: 'downstream',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid profile',
  state: 'dstate',
  nonce: 'dnonce',
  code_challenge: s256('verifier-xyz'),
  code_challenge_method: 'S256',
  response_type: 'code',
  upstream_provider: 'oidc-x',
  created_at: 0,
  expires_at: 0,
  ...over,
});

const codeRecord = (over: Partial<AuthorizationCode> = {}): AuthorizationCode => ({
  code: 'CODE',
  session_id: 'sess-1',
  subject: 'upstream-sub-1',
  user_info: {sub: 'upstream-sub-1'},
  upstream_tokens: {access_token: 'up-at', token_type: 'Bearer', refresh_token: 'up-rt'},
  created_at: 0,
  expires_at: 0,
  consumed: false,
  ...over,
});

const refreshRecord = (over: Partial<RefreshTokenData> = {}): RefreshTokenData => ({
  token: 'RT-1',
  family_id: 'fam-1',
  subject: 'minted-sub',
  client_id: 'downstream',
  scope: 'openid profile',
  upstream_refresh_token: 'up-rt',
  created_at: 0,
  expires_at: 0,
  revoked: false,
  ...over,
});

const authReq = (over: Record<string, any> = {}): TokenRequestValidated => ({
  grant_type: 'authorization_code',
  client_id: 'downstream',
  code: 'CODE',
  redirect_uri: 'https://app.test/cb',
  code_verifier: 'verifier-xyz',
  ...over,
} as TokenRequestValidated);

const refreshReq = (over: Record<string, any> = {}): TokenRequestValidated => ({
  grant_type: 'refresh_token',
  client_id: 'downstream',
  refresh_token: 'RT-1',
  ...over,
} as TokenRequestValidated);

type Over = {
  code?: AuthorizationCode | undefined;
  session?: AuthorizationSession | undefined;
  live?: RefreshTokenData | undefined;
  raw?: RefreshTokenData | undefined;
  mintSubject?: (sectorId: string, upstreamSubject: string) => string;
};

/** A grant service over capturing session/token stubs. Override the records each stub returns. */
const makeService = (over: Over = {}) => {
  const captured: Record<string, any> = {};
  const sessions: GrantSessionStore = {
    consumeCode: (code) => { captured.consumedCode = code; return 'code' in over ? over.code : codeRecord(); },
    getSession: (id) => { captured.gotSession = id; return 'session' in over ? over.session : sessionRecord(); },
    storeRefreshToken: (input) => { captured.storedRefresh = input; return refreshRecord({token: 'NEW-RT', family_id: input.family_id ?? 'fam-new'}); },
    getRefreshToken: (t) => { captured.gotRefresh = t; return over.live; },
    findRefreshToken: (t) => { captured.foundRefresh = t; return over.raw; },
    revokeRefreshToken: (t) => { captured.revokedToken = t; return true; },
    revokeRefreshFamily: (f) => { captured.revokedFamily = f; return 2; },
  };
  const tokens: GrantTokenIssuer = {
    issueAccessToken: async (input) => { captured.accessInput = input; return {token: 'ACCESS', claims: {} as any}; },
    issueIdToken: async (input) => { captured.idInput = input; return {token: 'ID', claims: {} as any}; },
  };
  const svc = new GrantService();
  svc.initialize({sessions, tokens, mintSubject: over.mintSubject});
  return {svc, captured};
};

/** Assert a promise rejects with a GrantError carrying the given OAuth error code + message substring. */
async function expectGrantError(promise: Promise<unknown>, code: string, messageSubstring: string) {
  try {
    await promise;
    throw new Error('expected GrantError, but promise resolved');
  } catch (e) {
    expect(e).toBeInstanceOf(GrantError);
    expect((e as GrantError).code).toBe(code as any);
    expect((e as GrantError).message).toContain(messageSubstring);
    expect((e as GrantError).name).toBe('GrantError');
  }
}

describe('GrantService — guards before init', () => {
  it('rejects exchange before initialization', async () => {
    const svc = new GrantService();
    expect(svc.isInitialized()).toBe(false);
    await expect(svc.exchange(provider(), authReq())).rejects.toThrow('not initialized');
  });
});

describe('defaultSubjectMapper', () => {
  it('is deterministic and pairwise; the separator prevents pair collisions', () => {
    expect(defaultSubjectMapper('client-a', 'up-1')).toBe('i3DZ6X9uo3H7sgPhuxvJww_BLgr4llFkXCAE9Rl90Wg');
    // ('ab','c') and ('a','bc') concatenate to 'abc' WITHOUT a separator — must stay distinct
    expect(defaultSubjectMapper('ab', 'c')).not.toBe(defaultSubjectMapper('a', 'bc'));
  });
});

describe('GrantService — authorization_code grant', () => {
  it('redeems a code into re-minted Passage tokens + a new-family refresh token', async () => {
    const {svc, captured} = makeService({mintSubject: (s, u) => `mint:${s}:${u}`});
    const res = await svc.exchange(provider(), authReq());

    expect(captured.consumedCode).toBe('CODE');
    expect(captured.gotSession).toBe('sess-1');
    // re-minted subject (NOT the raw upstream sub) flows into both tokens and the refresh record
    expect(captured.accessInput.subject).toBe('mint:downstream:upstream-sub-1');
    expect(captured.idInput.subject).toBe('mint:downstream:upstream-sub-1');
    expect(captured.storedRefresh.subject).toBe('mint:downstream:upstream-sub-1');
    // issuer / audience / scope / nonce wiring
    expect(captured.accessInput.issuer).toBe('https://iss.test/oidc-x');
    expect(captured.accessInput.client_id).toBe('downstream');
    expect(captured.accessInput.audience).toBe('downstream');
    expect(captured.accessInput.scope).toBe('openid profile');
    expect(captured.accessInput.lifetime).toBe(3600);
    expect(captured.idInput.audience).toBe('downstream');
    expect(captured.idInput.nonce).toBe('dnonce');
    expect(captured.idInput.lifetime).toBe(3600);
    expect(captured.storedRefresh.client_id).toBe('downstream');
    expect(captured.storedRefresh.scope).toBe('openid profile');
    expect(captured.storedRefresh.upstream_refresh_token).toBe('up-rt');
    expect(captured.storedRefresh.family_id).toBeUndefined(); // new family — none supplied
    expect(res).toEqual({
      access_token: 'ACCESS', token_type: 'Bearer', expires_in: 3600,
      refresh_token: 'NEW-RT', id_token: 'ID', scope: 'openid profile',
    });
  });

  it('honours per-provider token lifetimes', async () => {
    const {svc, captured} = makeService();
    const res = await svc.exchange(provider({access_token_lifetime: 7200, id_token_lifetime: 1800}), authReq());
    expect(captured.accessInput.lifetime).toBe(7200);
    expect(captured.idInput.lifetime).toBe(1800);
    expect(res.expires_in).toBe(7200);
  });

  it('rejects an unknown / expired / already-used code', async () => {
    const {svc} = makeService({code: undefined});
    await expectGrantError(svc.exchange(provider(), authReq()), 'invalid_grant', 'already-used');
  });

  it('rejects when the authorization session is gone', async () => {
    const {svc} = makeService({session: undefined});
    await expectGrantError(svc.exchange(provider(), authReq()), 'invalid_grant', 'session expired');
  });

  it('rejects a client_id that does not match the code', async () => {
    const {svc} = makeService();
    await expectGrantError(svc.exchange(provider(), authReq({client_id: 'other'})), 'invalid_grant', 'client_id does not match');
  });

  it('rejects a redirect_uri that does not match the code', async () => {
    const {svc} = makeService();
    await expectGrantError(svc.exchange(provider(), authReq({redirect_uri: 'https://evil.test/cb'})), 'invalid_grant', 'redirect_uri does not match');
  });

  it('rejects when a code_verifier is required but missing', async () => {
    const {svc} = makeService();
    await expectGrantError(svc.exchange(provider(), authReq({code_verifier: undefined})), 'invalid_grant', 'code_verifier is required');
  });

  it('rejects a code_verifier that fails the S256 challenge', async () => {
    const {svc} = makeService();
    await expectGrantError(svc.exchange(provider(), authReq({code_verifier: 'wrong-but-same-ish-verifier'})), 'invalid_grant', 'PKCE verification failed');
  });

  it('treats a length-mismatched stored challenge as a failure, not a crash', async () => {
    const {svc} = makeService({session: sessionRecord({code_challenge: 'short'})});
    await expectGrantError(svc.exchange(provider(), authReq()), 'invalid_grant', 'PKCE verification failed');
  });

  it('rejects a code_verifier when no code_challenge was registered (downgrade defense)', async () => {
    const {svc} = makeService({session: sessionRecord({code_challenge: undefined})});
    await expectGrantError(svc.exchange(provider(), authReq({code_verifier: 'anything'})), 'invalid_grant', 'no code_challenge was registered');
  });

  it('succeeds with no PKCE when none was registered', async () => {
    const {svc, captured} = makeService({session: sessionRecord({code_challenge: undefined})});
    const res = await svc.exchange(provider(), authReq({code_verifier: undefined}));
    expect(res.access_token).toBe('ACCESS');
    expect(captured.accessInput.issuer).toBe('https://iss.test/oidc-x');
  });

  it('server_errors when the provider has no issuer', async () => {
    const {svc} = makeService();
    await expectGrantError(svc.exchange(provider({issuer: undefined}), authReq()), 'server_error', 'no issuer configured');
  });

  it('server_errors when the provider has no OidcConfig at all', async () => {
    const {svc} = makeService();
    const prov = {name: 'x', auth_protocol: 'oidc', ServerConfig: {endpoint_url: 'x', client_id: 'c'}} as any;
    await expectGrantError(svc.exchange(prov, authReq()), 'server_error', 'no issuer configured');
  });
});

describe('GrantService — refresh_token grant', () => {
  it('rotates a live token: revokes the old, mints a new one in the same family', async () => {
    const live = refreshRecord({token: 'OLD-RT', family_id: 'fam-9', subject: 'sub-9', scope: 'openid', upstream_refresh_token: 'up-9'});
    const {svc, captured} = makeService({live});
    const res = await svc.exchange(provider(), refreshReq({refresh_token: 'OLD-RT'}));

    expect(captured.gotRefresh).toBe('OLD-RT');
    expect(captured.revokedToken).toBe('OLD-RT');         // old token revoked
    expect(captured.storedRefresh.family_id).toBe('fam-9'); // rotated into the same family
    expect(captured.storedRefresh.subject).toBe('sub-9');
    expect(captured.storedRefresh.scope).toBe('openid');
    expect(captured.storedRefresh.upstream_refresh_token).toBe('up-9');
    expect(captured.accessInput.subject).toBe('sub-9');
    expect(captured.accessInput.scope).toBe('openid');
    expect(captured.idInput.subject).toBe('sub-9');
    expect(captured.idInput.nonce).toBeUndefined();        // no nonce on refresh-issued id tokens
    expect(res).toEqual({
      access_token: 'ACCESS', token_type: 'Bearer', expires_in: 3600,
      refresh_token: 'NEW-RT', id_token: 'ID', scope: 'openid',
    });
  });

  it('detects reuse of a revoked token and revokes the whole family', async () => {
    const raw = refreshRecord({token: 'OLD-RT', family_id: 'fam-7', revoked: true});
    const {svc, captured} = makeService({live: undefined, raw});
    await expectGrantError(svc.exchange(provider(), refreshReq({refresh_token: 'OLD-RT'})), 'invalid_grant', 'reuse detected');
    expect(captured.foundRefresh).toBe('OLD-RT');
    expect(captured.revokedFamily).toBe('fam-7');
  });

  it('rejects an expired (present, not revoked) token without revoking a family', async () => {
    const raw = refreshRecord({token: 'OLD-RT', family_id: 'fam-7', revoked: false});
    const {svc, captured} = makeService({live: undefined, raw});
    await expectGrantError(svc.exchange(provider(), refreshReq({refresh_token: 'OLD-RT'})), 'invalid_grant', 'unknown or expired');
    expect(captured.revokedFamily).toBeUndefined(); // not reuse → family untouched
  });

  it('rejects an entirely unknown refresh token', async () => {
    const {svc, captured} = makeService({live: undefined, raw: undefined});
    await expectGrantError(svc.exchange(provider(), refreshReq({refresh_token: 'NOPE'})), 'invalid_grant', 'unknown or expired');
    expect(captured.revokedFamily).toBeUndefined();
  });
});

describe('GrantService — unsupported grants & lifecycle', () => {
  it('rejects an unsupported grant_type', async () => {
    const {svc} = makeService();
    const req = {grant_type: 'client_credentials', client_id: 'c'} as any;
    await expectGrantError(svc.exchange(provider(), req), 'unsupported_grant_type', 'unsupported grant_type');
  });

  it('is idempotent (first initialize wins) and resettable', async () => {
    const {svc, captured} = makeService({mintSubject: (s, u) => `mint:${s}:${u}`});
    svc.initialize({mintSubject: () => 'IGNORED'}); // ignored — first init wins
    await svc.exchange(provider(), authReq());
    // the original mapper is still in effect — the second initialize was a no-op
    expect(captured.accessInput.subject).toBe('mint:downstream:upstream-sub-1');
    svc.reset();
    expect(svc.isInitialized()).toBe(false);
    await expect(svc.exchange(provider(), authReq())).rejects.toThrow('not initialized');
  });

  it('falls back to the session + token singletons and the default subject mapper', async () => {
    sessionService.reset();
    sessionService.initialize();
    jwksService.reset();
    await jwksService.initialize();
    tokenService.reset();
    tokenService.initialize();

    const session = sessionService.createSession({
      client_id: 'downstream', redirect_uri: 'https://app.test/cb', scope: 'openid',
      nonce: 'n', code_challenge: s256('verifier-xyz'), code_challenge_method: 'S256',
      response_type: 'code', upstream_provider: 'oidc-x',
    });
    const code = sessionService.createCode({
      session_id: session.id, subject: 'upstream-sub-1',
      user_info: {sub: 'upstream-sub-1'}, upstream_tokens: {access_token: 'at', token_type: 'Bearer'},
    });

    const svc = new GrantService();
    svc.initialize(); // pure defaults — exercises the uninjected seams
    const res = await svc.exchange(provider(), authReq({code: code.code, redirect_uri: 'https://app.test/cb'}));

    expect(res.token_type).toBe('Bearer');
    const claims = await tokenService.verify(res.access_token); // signed by the real token/jwks singletons
    expect(claims.sub).toBe(defaultSubjectMapper('downstream', 'upstream-sub-1')); // default mapper used
    expect(claims.sub).not.toBe('upstream-sub-1'); // never the raw upstream sub
  });
});
