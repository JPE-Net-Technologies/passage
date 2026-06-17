/**
 * OIDC Type Definitions
 * Core TypeScript interfaces for OpenID Connect protocol implementation
 */

// =============================================================================
// Discovery Document
// =============================================================================

/**
 * OpenID Connect Discovery Document (RFC 8414)
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export interface OIDCDiscoveryDocument {
    // Required fields
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    response_types_supported: string[];
    subject_types_supported: SubjectType[];
    id_token_signing_alg_values_supported: SigningAlgorithm[];

    // Recommended fields
    userinfo_endpoint?: string;
    registration_endpoint?: string;
    scopes_supported?: string[];
    claims_supported?: string[];

    // Optional fields
    response_modes_supported?: ResponseMode[];
    grant_types_supported?: GrantType[];
    acr_values_supported?: string[];
    token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
    token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
    code_challenge_methods_supported?: CodeChallengeMethod[];

    // Logout endpoints
    end_session_endpoint?: string;

    // Additional metadata
    service_documentation?: string;
    ui_locales_supported?: string[];
    claims_locales_supported?: string[];
    claims_parameter_supported?: boolean;
    request_parameter_supported?: boolean;
    request_uri_parameter_supported?: boolean;
    require_request_uri_registration?: boolean;
}

// =============================================================================
// Authorization Request/Response
// =============================================================================

/**
 * OAuth2/OIDC Authorization Request parameters
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */
export interface AuthorizationRequest {
    // Required
    response_type: ResponseType;
    client_id: string;
    redirect_uri: string;
    scope: string;

    // Recommended
    state?: string;
    nonce?: string;

    // PKCE (RFC 7636)
    code_challenge?: string;
    code_challenge_method?: CodeChallengeMethod;

    // Optional
    response_mode?: ResponseMode;
    prompt?: Prompt;
    max_age?: number;
    ui_locales?: string;
    id_token_hint?: string;
    login_hint?: string;
    acr_values?: string;
}

/**
 * Stored authorization session (server-side state)
 */
export interface AuthorizationSession {
    id: string;
    client_id: string;
    redirect_uri: string;
    scope: string;
    state?: string;
    nonce?: string;
    code_challenge?: string;
    code_challenge_method?: CodeChallengeMethod;
    response_type: ResponseType;
    upstream_provider: string;
    created_at: number;
    expires_at: number;
}

/**
 * Authorization code (one-time use)
 */
export interface AuthorizationCode {
    code: string;
    session_id: string;
    subject: string;
    user_info: UserInfoResponse;
    upstream_tokens: UpstreamTokens;
    created_at: number;
    expires_at: number;
    consumed: boolean;
}

// =============================================================================
// Token Request/Response
// =============================================================================

/**
 * Base token request fields
 */
interface BaseTokenRequest {
    client_id: string;
    client_secret?: string;
}

/**
 * Authorization code grant token request
 */
export interface AuthorizationCodeTokenRequest extends BaseTokenRequest {
    grant_type: 'authorization_code';
    code: string;
    redirect_uri: string;
    code_verifier?: string;
}

/**
 * Refresh token grant request
 */
export interface RefreshTokenRequest extends BaseTokenRequest {
    grant_type: 'refresh_token';
    refresh_token: string;
    scope?: string;
}

/**
 * Client credentials grant request
 */
export interface ClientCredentialsTokenRequest extends BaseTokenRequest {
    grant_type: 'client_credentials';
    scope?: string;
}

/**
 * Union type for all token request types
 */
export type TokenRequest =
    | AuthorizationCodeTokenRequest
    | RefreshTokenRequest
    | ClientCredentialsTokenRequest;

/**
 * Successful token response
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
 */
export interface TokenResponse {
    access_token: string;
    token_type: 'Bearer';
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
}

/**
 * Token error response
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export interface TokenErrorResponse {
    error: TokenErrorCode;
    error_description?: string;
    error_uri?: string;
}

// =============================================================================
// UserInfo
// =============================================================================

/**
 * UserInfo endpoint response
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
export interface UserInfoResponse {
    // Required
    sub: string;

    // Standard claims
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    phone_number_verified?: boolean;
    address?: AddressClaim;
    updated_at?: number;

    // Allow additional custom claims
    [key: string]: unknown;
}

/**
 * Address claim structure
 */
export interface AddressClaim {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
}

// =============================================================================
// JWKS (JSON Web Key Set)
// =============================================================================

/**
 * JSON Web Key Set
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 */
export interface JWKSet {
    keys: JWK[];
}

/**
 * JSON Web Key
 */
export interface JWK {
    // Common fields
    kty: KeyType;
    use?: KeyUse;
    key_ops?: KeyOperation[];
    alg?: string;
    kid?: string;

    // RSA public key fields
    n?: string;
    e?: string;

    // EC public key fields
    crv?: string;
    x?: string;
    y?: string;

    // Symmetric key (should not be exposed publicly)
    k?: string;

    // Certificate fields
    x5c?: string[];
    x5t?: string;
    'x5t#S256'?: string;
    x5u?: string;
}

// =============================================================================
// ID Token Claims
// =============================================================================

/**
 * OIDC ID Token claims
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
export interface IDTokenClaims {
    // Required
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;

    // Conditionally required
    nonce?: string;
    auth_time?: number;

    // Optional
    acr?: string;
    amr?: string[];
    azp?: string;
    at_hash?: string;
    c_hash?: string;

    // Standard claims (can be included in ID token)
    name?: string;
    email?: string;
    email_verified?: boolean;
    picture?: string;

    // Custom claims
    [key: string]: unknown;
}

/**
 * Access token claims (JWT format)
 */
export interface AccessTokenClaims {
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;
    jti?: string;
    client_id: string;
    scope?: string;
    [key: string]: unknown;
}

// =============================================================================
// Upstream Provider Types
// =============================================================================

/**
 * Tokens received from upstream provider
 */
export interface UpstreamTokens {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    id_token?: string;
    scope?: string;
}

/**
 * Refresh token storage
 */
export interface RefreshTokenData {
    token: string;
    subject: string;
    client_id: string;
    scope: string;
    upstream_refresh_token?: string;
    created_at: number;
    expires_at: number;
    revoked: boolean;
}

// =============================================================================
// Enums and Literal Types
// =============================================================================

export type ResponseType = 'code' | 'token' | 'id_token' | 'code id_token' | 'code token' | 'id_token token' | 'code id_token token';
export type ResponseMode = 'query' | 'fragment' | 'form_post';
export type GrantType = 'authorization_code' | 'implicit' | 'refresh_token' | 'client_credentials' | 'password';
export type SubjectType = 'public' | 'pairwise';
export type Prompt = 'none' | 'login' | 'consent' | 'select_account';
export type CodeChallengeMethod = 'plain' | 'S256';
export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none';
export type SigningAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';
export type KeyType = 'RSA' | 'EC' | 'oct' | 'OKP';
export type KeyUse = 'sig' | 'enc';
export type KeyOperation = 'sign' | 'verify' | 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey' | 'deriveKey' | 'deriveBits';

export type TokenErrorCode =
    | 'invalid_request'
    | 'invalid_client'
    | 'invalid_grant'
    | 'unauthorized_client'
    | 'unsupported_grant_type'
    | 'invalid_scope'
    | 'server_error';

export type AuthorizationErrorCode =
    | 'invalid_request'
    | 'unauthorized_client'
    | 'access_denied'
    | 'unsupported_response_type'
    | 'invalid_scope'
    | 'server_error'
    | 'temporarily_unavailable';

// =============================================================================
// OIDC Error Types
// =============================================================================

/**
 * OIDC/OAuth2 error response structure
 */
export interface OIDCError {
    error: TokenErrorCode | AuthorizationErrorCode;
    error_description?: string;
    error_uri?: string;
    state?: string;
}