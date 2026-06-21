// src/services/oidc/client-auth.service.ts
// Downstream client authentication for the token-issuing endpoints (/token, /revoke).
// Confidential clients authenticate with a registered secret presented via HTTP Basic
// (`client_secret_basic`) or in the request body (`client_secret_post`); public clients use
// `none` and are PKCE-protected by the grant flow. This is the gate that makes a confidential
// client's secret meaningful (RFC 6749 §2.3 / §3.2.1, RFC 7009 §2.1).
//
// Pure functions + an error class (no singleton state): the only collaborators are the
// already-loaded client record and a secret resolver (localKMS.getSecret), the latter injectable
// so the unit tests never boot the real KMS. Logger-free and unit-testable to the repo's
// 100% line + 100% mutation gates.
import {localKMS} from '../kms-local';
import {constantTimeEqual} from '../../utils/constant-time';
import {ClientEntryType} from '../../utils/schemas/config.schemas';

export type ClientAuthErrorCode = 'invalid_client' | 'invalid_request' | 'server_error';

/**
 * Error carrying an OAuth client-authentication error code so the thin route maps it to a status
 * (and a `WWW-Authenticate` challenge) without logging. `usedBasic` records whether the client
 * presented credentials via the Authorization header, which drives the 401 + `WWW-Authenticate:
 * Basic` response per RFC 6749 §5.2.
 */
export class ClientAuthError extends Error {
  constructor(
    public readonly code: ClientAuthErrorCode,
    message: string,
    public readonly usedBasic: boolean = false,
  ) {
    super(message);
    this.name = 'ClientAuthError';
  }
}

/** Credentials extracted from a token-endpoint request: the asserted client_id and optional secret. */
export interface ClientCredentials {
  client_id?: string;
  client_secret?: string;
  /** True when the credentials arrived via the HTTP Basic Authorization header. */
  usedBasic: boolean;
}

/** Resolves a `client_secret_ref` to its plaintext secret (or undefined if unknown). */
export type SecretResolver = (ref: string) => string | undefined;

/** The request body fields client authentication reads (client_secret_post). */
interface CredentialBody {
  client_id?: unknown;
  client_secret?: unknown;
}

/**
 * Parse an HTTP Basic Authorization header into a client_id/secret pair, or return undefined if no
 * Basic header is present. Throws {@link ClientAuthError} (`invalid_request`) on a malformed header.
 *
 * Per RFC 6749 §2.3.1 the userid (client_id) and password (client_secret) are
 * `application/x-www-form-urlencoded`-encoded, so both halves are URL-decoded; the value is split
 * on the FIRST colon only, since a secret may itself contain colons.
 */
const BASIC_PREFIX = 'Basic ';

function parseBasicHeader(header: string): {client_id: string; client_secret: string} | undefined {
  if (!header.startsWith(BASIC_PREFIX)) {
    return undefined;
  }
  const decoded = Buffer.from(header.slice(BASIC_PREFIX.length), 'base64').toString('utf8');
  const sep = decoded.indexOf(':');
  if (sep === -1) {
    throw new ClientAuthError('invalid_request', 'malformed Basic authorization header', true);
  }
  return {
    client_id: decodeURIComponent(decoded.slice(0, sep)),
    client_secret: decodeURIComponent(decoded.slice(sep + 1)),
  };
}

/**
 * Extract client credentials from a token-endpoint request, enforcing that the client uses at most
 * one authentication mechanism (RFC 6749 §2.3): Basic and a body `client_secret` MUST NOT both be
 * present, and when Basic supplies a client_id any body `client_id` MUST match it. The client_id is
 * taken from Basic when present, otherwise from the body.
 */
export function extractClientCredentials(
  authorizationHeader: string | undefined,
  body: CredentialBody,
): ClientCredentials {
  const basic = authorizationHeader ? parseBasicHeader(authorizationHeader) : undefined;
  const bodyClientId = typeof body.client_id === 'string' ? body.client_id : undefined;
  const bodySecret = typeof body.client_secret === 'string' ? body.client_secret : undefined;

  if (basic) {
    if (bodySecret !== undefined) {
      throw new ClientAuthError('invalid_request', 'multiple client authentication mechanisms', true);
    }
    if (bodyClientId !== undefined && bodyClientId !== basic.client_id) {
      throw new ClientAuthError('invalid_request', 'client_id mismatch between Basic header and body', true);
    }
    return {client_id: basic.client_id, client_secret: basic.client_secret, usedBasic: true};
  }

  return {client_id: bodyClientId, client_secret: bodySecret, usedBasic: false};
}

/**
 * Authenticate an (already-loaded) client against presented credentials. Returns on success and
 * throws {@link ClientAuthError} on failure:
 * - public clients (`none`) MUST NOT present a secret;
 * - confidential clients MUST present the secret registered for their `client_secret_ref`;
 * - a confidential client whose secret cannot be resolved is an operator misconfiguration
 *   (`server_error`), not a client error, so it is never reported as `invalid_client`.
 */
export function authenticateClient(
  client: ClientEntryType,
  creds: ClientCredentials,
  resolveSecret: SecretResolver = localKMS.getSecret.bind(localKMS),
): void {
  if (client.client_type === 'public') {
    if (creds.client_secret !== undefined) {
      throw new ClientAuthError('invalid_client', 'public client must not present a client secret', creds.usedBasic);
    }
    return;
  }

  // Confidential client: a registered secret must be presented and must match.
  if (creds.client_secret === undefined) {
    throw new ClientAuthError('invalid_client', 'client authentication required', creds.usedBasic);
  }
  if (!client.client_secret_ref) {
    throw new ClientAuthError('server_error', `confidential client ${client.client_id} has no client_secret_ref`, creds.usedBasic);
  }
  const expected = resolveSecret(client.client_secret_ref);
  if (expected === undefined) {
    throw new ClientAuthError('server_error', `secret not found: ${client.client_secret_ref}`, creds.usedBasic);
  }
  if (!constantTimeEqual(creds.client_secret, expected)) {
    throw new ClientAuthError('invalid_client', 'invalid client credentials', creds.usedBasic);
  }
}
