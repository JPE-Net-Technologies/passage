/**
 * OIDC Zod Schemas
 * Runtime validation schemas for OpenID Connect protocol
 */

import { z } from 'zod';

// =============================================================================
// Enum Schemas
// =============================================================================

export const ResponseTypeSchema = z.enum([
    'code',
    'token',
    'id_token',
    'code id_token',
    'code token',
    'id_token token',
    'code id_token token'
]);

export const ResponseModeSchema = z.enum(['query', 'fragment', 'form_post']);

export const GrantTypeSchema = z.enum([
    'authorization_code',
    'implicit',
    'refresh_token',
    'client_credentials',
    'password'
]);

export const CodeChallengeMethodSchema = z.enum(['plain', 'S256']);

export const PromptSchema = z.enum(['none', 'login', 'consent', 'select_account']);

export const TokenEndpointAuthMethodSchema = z.enum([
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'none'
]);

export const SigningAlgorithmSchema = z.enum([
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512'
]);

// =============================================================================
// Authorization Request Schema
// =============================================================================

export const AuthorizationRequestSchema = z.object({
    // Required
    response_type: ResponseTypeSchema,
    client_id: z.string().min(1, 'client_id is required'),
    redirect_uri: z.string().url('redirect_uri must be a valid URL'),
    scope: z.string().min(1, 'scope is required').refine(
        (scope) => scope.split(' ').includes('openid'),
        'scope must include "openid" for OIDC requests'
    ),

    // Recommended
    state: z.string().optional(),
    nonce: z.string().optional(),

    // PKCE (RFC 7636)
    code_challenge: z.string().optional(),
    code_challenge_method: CodeChallengeMethodSchema.optional(),

    // Optional
    response_mode: ResponseModeSchema.optional(),
    prompt: PromptSchema.optional(),
    max_age: z.coerce.number().int().nonnegative().optional(),
    ui_locales: z.string().optional(),
    id_token_hint: z.string().optional(),
    login_hint: z.string().optional(),
    acr_values: z.string().optional(),
}).refine(
    (data) => {
        // If code_challenge is present, code_challenge_method should be too
        if (data.code_challenge && !data.code_challenge_method) {
            return false;
        }
        return true;
    },
    {
        message: 'code_challenge_method is required when code_challenge is provided',
        path: ['code_challenge_method']
    }
).refine(
    (data) => {
        // S256 code_challenge should be base64url encoded SHA256 (43 chars)
        if (data.code_challenge_method === 'S256' && data.code_challenge) {
            return data.code_challenge.length === 43;
        }
        return true;
    },
    {
        message: 'code_challenge for S256 must be 43 characters (base64url-encoded SHA256)',
        path: ['code_challenge']
    }
);

export type AuthorizationRequestInput = z.input<typeof AuthorizationRequestSchema>;
export type AuthorizationRequestValidated = z.output<typeof AuthorizationRequestSchema>;

// =============================================================================
// Token Request Schemas (Discriminated Union)
// =============================================================================

const BaseTokenRequestSchema = z.object({
    client_id: z.string().min(1, 'client_id is required'),
    client_secret: z.string().optional(),
});

export const AuthorizationCodeTokenRequestSchema = BaseTokenRequestSchema.extend({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1, 'code is required'),
    redirect_uri: z.string().url('redirect_uri must be a valid URL'),
    code_verifier: z.string().min(43).max(128).optional(),
});

export const RefreshTokenRequestSchema = BaseTokenRequestSchema.extend({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1, 'refresh_token is required'),
    scope: z.string().optional(),
});

export const ClientCredentialsTokenRequestSchema = BaseTokenRequestSchema.extend({
    grant_type: z.literal('client_credentials'),
    scope: z.string().optional(),
});

/**
 * Discriminated union for token requests based on grant_type
 */
export const TokenRequestSchema = z.discriminatedUnion('grant_type', [
    AuthorizationCodeTokenRequestSchema,
    RefreshTokenRequestSchema,
    ClientCredentialsTokenRequestSchema,
]);

export type TokenRequestInput = z.input<typeof TokenRequestSchema>;
export type TokenRequestValidated = z.output<typeof TokenRequestSchema>;

// =============================================================================
// Token Response Schema
// =============================================================================

export const TokenResponseSchema = z.object({
    access_token: z.string(),
    token_type: z.literal('Bearer'),
    expires_in: z.number().int().positive(),
    refresh_token: z.string().optional(),
    scope: z.string().optional(),
    id_token: z.string().optional(),
});

export type TokenResponseType = z.infer<typeof TokenResponseSchema>;

// =============================================================================
// Token Error Response Schema
// =============================================================================

export const TokenErrorCodeSchema = z.enum([
    'invalid_request',
    'invalid_client',
    'invalid_grant',
    'unauthorized_client',
    'unsupported_grant_type',
    'invalid_scope',
    'server_error'
]);

export const TokenErrorResponseSchema = z.object({
    error: TokenErrorCodeSchema,
    error_description: z.string().optional(),
    error_uri: z.string().url().optional(),
});

export type TokenErrorResponseType = z.infer<typeof TokenErrorResponseSchema>;

// =============================================================================
// UserInfo Response Schema
// =============================================================================

export const AddressClaimSchema = z.object({
    formatted: z.string().optional(),
    street_address: z.string().optional(),
    locality: z.string().optional(),
    region: z.string().optional(),
    postal_code: z.string().optional(),
    country: z.string().optional(),
});

export const UserInfoResponseSchema = z.object({
    // Required
    sub: z.string().min(1, 'sub is required'),

    // Standard claims
    name: z.string().optional(),
    given_name: z.string().optional(),
    family_name: z.string().optional(),
    middle_name: z.string().optional(),
    nickname: z.string().optional(),
    preferred_username: z.string().optional(),
    profile: z.string().url().optional(),
    picture: z.string().url().optional(),
    website: z.string().url().optional(),
    email: z.string().email().optional(),
    email_verified: z.boolean().optional(),
    gender: z.string().optional(),
    birthdate: z.string().optional(),
    zoneinfo: z.string().optional(),
    locale: z.string().optional(),
    phone_number: z.string().optional(),
    phone_number_verified: z.boolean().optional(),
    address: AddressClaimSchema.optional(),
    updated_at: z.number().int().optional(),
}).passthrough(); // Allow additional custom claims

export type UserInfoResponseType = z.infer<typeof UserInfoResponseSchema>;

// =============================================================================
// ID Token Claims Schema
// =============================================================================

export const IDTokenClaimsSchema = z.object({
    // Required
    iss: z.string().min(1),
    sub: z.string().min(1),
    aud: z.union([z.string(), z.array(z.string())]),
    exp: z.number().int(),
    iat: z.number().int(),

    // Conditionally required
    nonce: z.string().optional(),
    auth_time: z.number().int().optional(),

    // Optional
    acr: z.string().optional(),
    amr: z.array(z.string()).optional(),
    azp: z.string().optional(),
    at_hash: z.string().optional(),
    c_hash: z.string().optional(),

    // Standard claims that can be included
    name: z.string().optional(),
    email: z.string().email().optional(),
    email_verified: z.boolean().optional(),
    picture: z.string().url().optional(),
}).passthrough();

export type IDTokenClaimsType = z.infer<typeof IDTokenClaimsSchema>;

// =============================================================================
// JWKS Schema
// =============================================================================

export const JWKSchema = z.object({
    kty: z.enum(['RSA', 'EC', 'oct', 'OKP']),
    use: z.enum(['sig', 'enc']).optional(),
    key_ops: z.array(z.enum([
        'sign', 'verify', 'encrypt', 'decrypt',
        'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'
    ])).optional(),
    alg: z.string().optional(),
    kid: z.string().optional(),

    // RSA fields
    n: z.string().optional(),
    e: z.string().optional(),

    // EC fields
    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),
});

export const JWKSetSchema = z.object({
    keys: z.array(JWKSchema),
});

export type JWKType = z.infer<typeof JWKSchema>;
export type JWKSetType = z.infer<typeof JWKSetSchema>;

// =============================================================================
// Authorization Session Schema (for internal storage validation)
// =============================================================================

export const AuthorizationSessionSchema = z.object({
    id: z.string().min(1),
    client_id: z.string().min(1),
    redirect_uri: z.string().url(),
    scope: z.string().min(1),
    state: z.string().optional(),
    nonce: z.string().optional(),
    code_challenge: z.string().optional(),
    code_challenge_method: CodeChallengeMethodSchema.optional(),
    response_type: ResponseTypeSchema,
    upstream_provider: z.string().min(1),
    created_at: z.number().int(),
    expires_at: z.number().int(),
});

export type AuthorizationSessionType = z.infer<typeof AuthorizationSessionSchema>;

// =============================================================================
// Logout Request Schema
// =============================================================================

export const LogoutRequestSchema = z.object({
    id_token_hint: z.string().optional(),
    post_logout_redirect_uri: z.string().url().optional(),
    state: z.string().optional(),
    client_id: z.string().optional(),
}).refine(
    (data) => {
        // post_logout_redirect_uri requires id_token_hint per spec
        if (data.post_logout_redirect_uri && !data.id_token_hint) {
            return false;
        }
        return true;
    },
    {
        message: 'id_token_hint is required when post_logout_redirect_uri is provided',
        path: ['id_token_hint']
    }
);

export type LogoutRequestType = z.infer<typeof LogoutRequestSchema>;