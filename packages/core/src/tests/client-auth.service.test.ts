// tests/client-auth.service.test.ts — downstream client authentication (/token, /revoke).
//
// Pure functions exercised in isolation: extractClientCredentials enforces the single-mechanism
// rule (RFC 6749 §2.3) and parses Basic/post credentials; authenticateClient verifies them against
// the (already-loaded) client record with an injected secret resolver, so no real KMS is needed.
// One case drives the default resolver through a booted LocalKMS to cover the uninjected seam.
import {describe, it, expect, beforeAll, afterAll} from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  extractClientCredentials,
  authenticateClient,
  ClientAuthError,
} from '../services/oidc/client-auth.service';
import {localKMS} from '../services/kms-local';
import type {ClientEntryType} from '../utils/schemas/config.schemas';

const publicClient: ClientEntryType = {
  client_id: 'spa',
  client_type: 'public',
  redirect_uris: ['https://app.test/cb'],
};

const confidentialClient: ClientEntryType = {
  client_id: 'web',
  client_type: 'confidential',
  redirect_uris: ['https://web.test/cb'],
  client_secret_ref: 'WebSecret',
};

/** base64 a `id:secret` pair into a Basic header value. */
const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

/** Run `fn`, asserting it throws a ClientAuthError with the given code, message substring, and usedBasic flag. */
function expectClientAuthError(fn: () => void, code: string, messageSubstring: string, usedBasic: boolean) {
  try {
    fn();
    throw new Error('expected ClientAuthError, but no error was thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(ClientAuthError);
    expect((e as ClientAuthError).code).toBe(code as any);
    expect((e as ClientAuthError).message).toContain(messageSubstring);
    expect((e as ClientAuthError).usedBasic).toBe(usedBasic);
  }
}

describe('ClientAuthError', () => {
  it('exposes its name and defaults usedBasic to false', () => {
    const e = new ClientAuthError('invalid_client', 'nope');
    expect(e.name).toBe('ClientAuthError');
    expect(e.usedBasic).toBe(false);
  });
});

describe('extractClientCredentials', () => {
  it('reads client_secret_post from the body (no Basic header)', () => {
    const creds = extractClientCredentials(undefined, {client_id: 'web', client_secret: 's3cret'});
    expect(creds).toEqual({client_id: 'web', client_secret: 's3cret', usedBasic: false});
  });

  it('reads client_secret_basic from the Authorization header', () => {
    const creds = extractClientCredentials(basic('web', 's3cret'), {});
    expect(creds).toEqual({client_id: 'web', client_secret: 's3cret', usedBasic: true});
  });

  it('splits the Basic value on the first colon only (secret may contain colons)', () => {
    const creds = extractClientCredentials(basic('web', 'a:b:c'), {});
    expect(creds.client_secret).toBe('a:b:c');
  });

  it('URL-decodes the Basic client_id and secret (RFC 6749 §2.3.1)', () => {
    const header = `Basic ${Buffer.from('we%20b:s%3Acret').toString('base64')}`;
    const creds = extractClientCredentials(header, {});
    expect(creds.client_id).toBe('we b');
    expect(creds.client_secret).toBe('s:cret');
  });

  it('ignores a non-Basic Authorization header and falls back to the body', () => {
    const creds = extractClientCredentials('Bearer abc', {client_id: 'spa'});
    expect(creds).toEqual({client_id: 'spa', client_secret: undefined, usedBasic: false});
  });

  it('treats non-string body credentials as absent', () => {
    const creds = extractClientCredentials(undefined, {client_id: 123, client_secret: {x: 1}});
    expect(creds).toEqual({client_id: undefined, client_secret: undefined, usedBasic: false});
  });

  it('accepts a body client_id that matches the Basic client_id', () => {
    const creds = extractClientCredentials(basic('web', 's3cret'), {client_id: 'web'});
    expect(creds.client_id).toBe('web');
  });

  it('rejects a malformed Basic header (no colon) as invalid_request', () => {
    const header = `Basic ${Buffer.from('nocolon').toString('base64')}`;
    expectClientAuthError(() => extractClientCredentials(header, {}), 'invalid_request', 'malformed Basic', true);
  });

  it('rejects Basic + body client_secret (multiple mechanisms, RFC 6749 §2.3)', () => {
    expectClientAuthError(
      () => extractClientCredentials(basic('web', 's3cret'), {client_secret: 'other'}),
      'invalid_request', 'multiple client authentication mechanisms', true,
    );
  });

  it('rejects a body client_id that differs from the Basic client_id', () => {
    expectClientAuthError(
      () => extractClientCredentials(basic('web', 's3cret'), {client_id: 'other'}),
      'invalid_request', 'client_id mismatch', true,
    );
  });
});

describe('authenticateClient', () => {
  const resolve = (ref: string) => (ref === 'WebSecret' ? 's3cret' : undefined);

  it('accepts a public client that presents no secret', () => {
    expect(() => authenticateClient(publicClient, {client_id: 'spa', usedBasic: false}, resolve)).not.toThrow();
  });

  it('rejects a public client that presents a secret', () => {
    expectClientAuthError(
      () => authenticateClient(publicClient, {client_id: 'spa', client_secret: 'x', usedBasic: true}, resolve),
      'invalid_client', 'public client must not present a client secret', true,
    );
  });

  it('accepts a confidential client with the correct secret', () => {
    expect(() => authenticateClient(confidentialClient, {client_id: 'web', client_secret: 's3cret', usedBasic: true}, resolve)).not.toThrow();
  });

  it('rejects a confidential client with the wrong secret', () => {
    expectClientAuthError(
      () => authenticateClient(confidentialClient, {client_id: 'web', client_secret: 'wrong', usedBasic: false}, resolve),
      'invalid_client', 'invalid client credentials', false,
    );
  });

  it('rejects a confidential client that presents no secret', () => {
    expectClientAuthError(
      () => authenticateClient(confidentialClient, {client_id: 'web', usedBasic: false}, resolve),
      'invalid_client', 'client authentication required', false,
    );
  });

  it('server_error (distinct message) when a confidential client has no client_secret_ref configured', () => {
    const misconfigured: ClientEntryType = {...confidentialClient, client_secret_ref: undefined};
    expectClientAuthError(
      () => authenticateClient(misconfigured, {client_id: 'web', client_secret: 's3cret', usedBasic: false}, resolve),
      'server_error', 'no client_secret_ref', false,
    );
  });

  it('server_error (distinct message) when the configured secret cannot be resolved', () => {
    const unknownRef: ClientEntryType = {...confidentialClient, client_secret_ref: 'Missing'};
    expectClientAuthError(
      () => authenticateClient(unknownRef, {client_id: 'web', client_secret: 's3cret', usedBasic: false}, resolve),
      'server_error', 'secret not found: Missing', false,
    );
  });
});

describe('authenticateClient — default KMS resolver', () => {
  let dir: string;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-client-auth-'));
    fs.writeFileSync(
      path.join(dir, 'template.secrets.yaml'),
      'Secrets:\n  - name: WebSecret\n    provider: Passage.LocalKms\n    reference: WebSecret\n    unencryptedValue: "s3cret"\n',
    );
    localKMS.reset();
    await localKMS.initialize({
      keystorePath: path.join(dir, 'kms-local.keystore'),
      secretsPath: path.join(dir, 'template.secrets.yaml'),
    });
  });

  afterAll(() => {
    localKMS.reset();
    fs.rmSync(dir, {recursive: true, force: true});
  });

  it('resolves the secret through localKMS when no resolver is injected', () => {
    expect(() => authenticateClient(confidentialClient, {client_id: 'web', client_secret: 's3cret', usedBasic: true})).not.toThrow();
  });
});
