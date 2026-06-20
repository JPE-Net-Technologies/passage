// tests/logout.service.test.ts — RP-Initiated Logout validation.
//
// verify + clients are injected so every branch is deterministic; each error path asserts a
// DISTINCT message substring. The default seams are covered cross-file by the /end_session route test.
import {describe, it, expect} from 'bun:test';
import {LogoutService, LogoutError} from '../services/oidc/logout.service';
import type {LogoutVerifier, LogoutClientRegistry} from '../services/oidc/logout.service';

const ISS = 'https://iss.test/oidc-x';

const registeredClient = (post_logout_redirect_uris?: string[]): LogoutClientRegistry => ({
  getClient: () => ({client_id: 'app', client_type: 'public', redirect_uris: ['https://app.test/cb'], post_logout_redirect_uris} as any),
});

const verifyResolves = (claims: Record<string, unknown>): LogoutVerifier => async () => claims as any;
const verifyRejects: LogoutVerifier = async () => { throw new Error('bad token'); };

/** A logout service with injected verify (default: valid hint for client 'app') + clients (default: 'app' registered). */
const make = (over: {verify?: LogoutVerifier; clients?: LogoutClientRegistry} = {}) => {
  const svc = new LogoutService();
  svc.initialize({
    verify: over.verify ?? verifyResolves({sub: 'u', iss: ISS, aud: 'app'}),
    clients: over.clients ?? registeredClient(['https://app.test/lo']),
  });
  return svc;
};

async function expectLogoutError(promise: Promise<unknown>, messageSubstring: string) {
  try {
    await promise;
    throw new Error('expected LogoutError, but promise resolved');
  } catch (e) {
    expect(e).toBeInstanceOf(LogoutError);
    expect((e as LogoutError).code).toBe('invalid_request');
    expect((e as LogoutError).message).toContain(messageSubstring);
    expect((e as LogoutError).name).toBe('LogoutError');
  }
}

describe('LogoutService — guards', () => {
  it('throws before initialization', async () => {
    const svc = new LogoutService();
    expect(svc.isInitialized()).toBe(false);
    await expect(svc.endSession({issuer: ISS})).rejects.toThrow('not initialized');
  });
});

describe('LogoutService — endSession', () => {
  it('confirms (no redirect) for a valid id_token_hint with no post_logout_redirect_uri', async () => {
    let verified = false;
    const svc = make({verify: async () => { verified = true; return {sub: 'u', iss: ISS, aud: 'app'} as any; }});
    expect(await svc.endSession({id_token_hint: 'idt', issuer: ISS})).toEqual({});
    expect(verified).toBe(true);
  });

  it('confirms without verifying when no id_token_hint is present', async () => {
    let verified = false;
    const svc = make({verify: async () => { verified = true; return {} as any; }});
    expect(await svc.endSession({issuer: ISS})).toEqual({});
    expect(verified).toBe(false);
  });

  it('rejects an invalid id_token_hint', async () => {
    await expectLogoutError(make({verify: verifyRejects}).endSession({id_token_hint: 'bad', issuer: ISS}), 'invalid id_token_hint');
  });

  it('rejects an id_token_hint issued by another authority', async () => {
    const svc = make({verify: verifyResolves({sub: 'u', iss: 'https://other', aud: 'app'})});
    await expectLogoutError(svc.endSession({id_token_hint: 'idt', issuer: ISS}), 'issuer mismatch');
  });

  it('rejects a post_logout_redirect_uri with no id_token_hint', async () => {
    await expectLogoutError(make().endSession({post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS}), 'requires id_token_hint');
  });

  it('rejects a client_id that does not match the id_token_hint audience', async () => {
    await expectLogoutError(
      make().endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', client_id: 'other', issuer: ISS}),
      'client_id does not match',
    );
  });

  it('rejects when the client is unknown', async () => {
    const svc = make({clients: {getClient: () => undefined}});
    await expectLogoutError(svc.endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS}), 'not registered');
  });

  it('rejects when the client has no post_logout_redirect_uris registered', async () => {
    const svc = make({clients: registeredClient(undefined)});
    await expectLogoutError(svc.endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS}), 'not registered');
  });

  it('rejects a post_logout_redirect_uri outside the registered set', async () => {
    const svc = make({clients: registeredClient(['https://app.test/other'])});
    await expectLogoutError(svc.endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS}), 'not registered');
  });

  it('redirects to a registered post_logout_redirect_uri with state (client_id matching the audience)', async () => {
    const r = await make().endSession({
      id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', client_id: 'app', state: 'xyz', issuer: ISS,
    });
    const u = new URL(r.redirectUrl!);
    expect(u.origin + u.pathname).toBe('https://app.test/lo');
    expect(u.searchParams.get('state')).toBe('xyz');
  });

  it('omits state from the redirect when none is supplied', async () => {
    const r = await make().endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS});
    expect(new URL(r.redirectUrl!).searchParams.has('state')).toBe(false);
  });

  it('uses the first audience when the id_token aud is an array', async () => {
    const svc = make({verify: verifyResolves({sub: 'u', iss: ISS, aud: ['app', 'other']})});
    const r = await svc.endSession({id_token_hint: 'idt', post_logout_redirect_uri: 'https://app.test/lo', issuer: ISS});
    expect(new URL(r.redirectUrl!).origin).toBe('https://app.test');
  });
});

describe('LogoutService — lifecycle', () => {
  it('is idempotent (first initialize wins) and resettable', async () => {
    const svc = make({verify: verifyResolves({sub: 'u', iss: ISS, aud: 'app'})});
    svc.initialize({verify: verifyRejects}); // ignored — first init wins
    expect(await svc.endSession({id_token_hint: 'idt', issuer: ISS})).toEqual({}); // first verifier still used
    svc.reset();
    expect(svc.isInitialized()).toBe(false);
    await expect(svc.endSession({issuer: ISS})).rejects.toThrow('not initialized');
  });
});
