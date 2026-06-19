// tests/userinfo.service.test.ts — the claims store + UserInfo retrieval logic.
//
// The verifier is injected so token validity is deterministic; every error path asserts a
// distinct message substring (so the shared 'invalid_token' code can't hide a swapped message).
import {describe, it, expect} from 'bun:test';
import {UserInfoService, UserInfoError, extractBearerToken} from '../services/oidc/userinfo.service';
import type {ClaimsVerifier} from '../services/oidc/userinfo.service';
import {jwksService} from '../services/oidc/jwks.service';
import {tokenService} from '../services/oidc/token.service';
import type {UserInfoResponse} from '../types/oidc.types';

const ISS = 'https://iss.test/oidc-x';
const PROFILE: UserInfoResponse = {sub: 'minted-1', email: 'u@x.test', name: 'U'};

/** A service whose verifier resolves the given claims (or rejects when `verify` throws). */
const make = (verify: ClaimsVerifier) => {
  const svc = new UserInfoService();
  svc.initialize({verify});
  return svc;
};

const resolves = (claims: Record<string, unknown>): ClaimsVerifier => async () => claims as any;
const rejects = (): ClaimsVerifier => async () => { throw new Error('bad token'); };

async function expectUserInfoError(promise: Promise<unknown>, messageSubstring: string) {
  try {
    await promise;
    throw new Error('expected UserInfoError, but promise resolved');
  } catch (e) {
    expect(e).toBeInstanceOf(UserInfoError);
    expect((e as UserInfoError).code).toBe('invalid_token');
    expect((e as UserInfoError).message).toContain(messageSubstring);
    expect((e as UserInfoError).name).toBe('UserInfoError');
  }
}

describe('extractBearerToken', () => {
  it('extracts only a well-formed non-empty Bearer credential', () => {
    expect(extractBearerToken(undefined)).toBeUndefined();
    expect(extractBearerToken('')).toBeUndefined();
    expect(extractBearerToken('Bearer ')).toBeUndefined();   // empty token
    expect(extractBearerToken('Bearertoken')).toBeUndefined(); // missing space
    expect(extractBearerToken('xBearer t')).toBeUndefined();   // not at start
    expect(extractBearerToken('Bearer t')).toBe('t');
    expect(extractBearerToken('Bearer a b')).toBe('a b');      // greedy capture keeps the rest
  });
});

describe('UserInfoService — guards before init', () => {
  it('throws on both operations before initialization', async () => {
    const svc = new UserInfoService();
    expect(svc.isInitialized()).toBe(false);
    expect(() => svc.rememberClaims('s', PROFILE)).toThrow('not initialized');
    await expect(svc.getUserInfo('t', ISS)).rejects.toThrow('not initialized');
  });
});

describe('UserInfoService — getUserInfo', () => {
  it('returns the stored claims for a valid token', async () => {
    const svc = make(resolves({sub: 'minted-1', iss: ISS}));
    svc.rememberClaims('minted-1', PROFILE);
    expect(await svc.getUserInfo('tok', ISS)).toEqual(PROFILE);
  });

  it('rejects a token that fails verification', async () => {
    const svc = make(rejects());
    await expectUserInfoError(svc.getUserInfo('tok', ISS), 'verification failed');
  });

  it('rejects a token whose issuer does not match the authority', async () => {
    const svc = make(resolves({sub: 'minted-1', iss: 'https://other.test'}));
    svc.rememberClaims('minted-1', PROFILE);
    await expectUserInfoError(svc.getUserInfo('tok', ISS), 'issuer mismatch');
  });

  it('rejects a valid token with no stored claims for its subject', async () => {
    const svc = make(resolves({sub: 'unknown', iss: ISS}));
    await expectUserInfoError(svc.getUserInfo('tok', ISS), 'no stored claims');
  });
});

describe('UserInfoService — lifecycle', () => {
  it('reset clears stored claims and uninitializes', async () => {
    const svc = make(resolves({sub: 'minted-1', iss: ISS}));
    svc.rememberClaims('minted-1', PROFILE);
    svc.reset();
    expect(svc.isInitialized()).toBe(false);
    svc.initialize({verify: resolves({sub: 'minted-1', iss: ISS})});
    await expectUserInfoError(svc.getUserInfo('tok', ISS), 'no stored claims'); // store was cleared
  });

  it('is idempotent: the first initialize wins', async () => {
    const svc = new UserInfoService();
    svc.initialize({verify: resolves({sub: 'minted-1', iss: ISS})});
    svc.initialize({verify: rejects()}); // ignored
    svc.rememberClaims('minted-1', PROFILE);
    expect(await svc.getUserInfo('tok', ISS)).toEqual(PROFILE); // still the first verifier
  });

  it('defaults to tokenService.verify when no verifier is injected', async () => {
    jwksService.reset();
    await jwksService.initialize();
    tokenService.reset();
    tokenService.initialize();
    const {token} = await tokenService.issueAccessToken({
      issuer: ISS, subject: 'minted-1', client_id: 'c', audience: 'c', lifetime: 3600,
    });
    const svc = new UserInfoService();
    svc.initialize(); // pure default verify (the real tokenService singleton)
    svc.rememberClaims('minted-1', PROFILE);
    expect(await svc.getUserInfo(token, ISS)).toEqual(PROFILE);
  });
});
