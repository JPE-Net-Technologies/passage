# OIDC Routes Implementation Plan

This document outlines the implementation tasks for setting up core OIDC routes in Passage.

## Overview

Passage acts as an **identity broker** that federates authentication with upstream OIDC providers. This implementation
will:

- Expose standard OIDC endpoints to downstream clients
- Federate to upstream providers (Keycloak, Auth0, etc.)
- Issue Passage-signed tokens after validating upstream tokens

**Key Decision**: Build custom OIDC handlers using `jose` library (transitive dependency) instead of using
`oidc-provider` directly, as it provides full control over the federation logic.

---

## File Structure

### New Files to Create

```
src/
├── services/
│   └── oidc/
│       ├── jwks.service.ts        # JWKS key management
│       ├── token.service.ts       # Token issuance and validation
│       ├── discovery.service.ts   # Discovery document generation
│       └── session.service.ts     # Authorization session management
├── routes/
│   └── oidc/
│       ├── discovery.handler.ts   # /.well-known/openid-configuration
│       ├── authorize.handler.ts   # /authorize endpoint
│       ├── token.handler.ts       # /token endpoint
│       ├── userinfo.handler.ts    # /userinfo endpoint
│       ├── jwks.handler.ts        # /jwks endpoint
│       └── logout.handler.ts      # /logout endpoint
├── utils/
│   └── schemas/
│       └── oidcSchemas.ts         # OIDC-specific Zod schemas
└── types/
    └── oidc.types.ts              # TypeScript interfaces for OIDC
```

### Files to Modify

| File                                   | Modification                                |
|----------------------------------------|---------------------------------------------|
| `src/routes/auth.routes.ts`            | Complete `setupOidcProviderRoutes()` implementation |
| `src/routes.ts`                        | Integrate auth routes mounting              |
| `src/server.ts`                        | Add OIDC service initialization             |
| `src/utils/schemas/providersConfig.ts` | Extend schema for upstream provider config  |

---

## Implementation Tasks

### Phase 1: Foundation (Schema and Types)

- [ ] **1.1 Create OIDC Type Definitions** (`src/types/oidc.types.ts`)
    - `OIDCDiscoveryDocument` interface
    - `AuthorizationRequest` interface
    - `TokenRequest` / `TokenResponse` interfaces
    - `UserInfoResponse` interface
    - `JWKSet` interface

- [ ] **1.2 Create OIDC Zod Schemas** (`src/utils/schemas/oidcSchemas.ts`)
    - `AuthorizationRequestSchema` - validates authorize endpoint params
    - `TokenRequestSchema` - discriminated union for grant types
    - `UserInfoResponseSchema`

- [ ] **1.3 Extend Provider Config Schema** (`src/utils/schemas/providersConfig.ts`)
    - Add `upstream_issuer` to OidcConfig
    - Add `upstream_client_id` to OidcConfig
    - Add `upstream_client_secret_ref` to OidcConfig (KMS reference)

---

### Phase 2: Core Services

- [ ] **2.1 Implement JWKS Service** (`src/services/oidc/jwks.service.ts`)
    - Singleton pattern with deferred initialization
    - Load/generate RSA or EC keys
    - `getPublicJWKS()` - returns public keys for endpoint
    - `getSigningKey(alg)` - returns private key for signing
    - Key rotation support

- [ ] **2.2 Implement Discovery Service** (`src/services/oidc/discovery.service.ts`)
    - `generateDiscoveryDocument(provider, baseUrl)` - builds standard OIDC discovery
    - Dynamic endpoint URLs based on provider config

- [ ] **2.3 Implement Session Service** (`src/services/oidc/session.service.ts`)
    - In-memory storage (Map) for development
    - `createAuthorizationSession(request)` - stores PKCE, state, nonce
    - `createAuthorizationCode(sessionId, userInfo)` - one-time use codes
    - `consumeAuthorizationCode(code)` - validates and deletes code
    - `storeRefreshToken()` / `validateRefreshToken()`

- [ ] **2.4 Implement Token Service** (`src/services/oidc/token.service.ts`)
    - Depends on: JWKS Service, Session Service
    - `issueAccessToken(claims)` - JWT signed with JWKS key
    - `issueIdToken(claims)` - OIDC ID token
    - `issueRefreshToken(subject, scopes)`
    - `validateToken(token)` - verify signature, expiry, audience

- [ ] **2.5 Implement Upstream Provider Service** (`src/services/upstream/provider.service.ts`)
    - `fetchDiscovery(issuerUrl)` - cache upstream discovery docs
    - `exchangeCode(provider, code, redirectUri)` - exchange auth code
    - `fetchUserInfo(provider, accessToken)` - get user claims
    - `validateUpstreamToken(token, provider)`

---

### Phase 3: Route Handlers

- [ ] **3.1 Discovery Endpoint** (`src/routes/oidc/discovery.handler.ts`)
    - GET `/.well-known/openid-configuration`
    - Returns JSON discovery document
    - Uses Discovery Service

- [ ] **3.2 JWKS Endpoint** (`src/routes/oidc/jwks.handler.ts`)
    - GET `/jwks`
    - Returns public keys only
    - Cache-Control headers (max-age=3600)

- [ ] **3.3 Authorization Endpoint** (`src/routes/oidc/authorize.handler.ts`)
    - GET `/authorize`
    - Validate request params with Zod schema
    - Create authorization session (store PKCE)
    - Redirect to upstream provider
    - Handle callback from upstream

- [ ] **3.4 Token Endpoint** (`src/routes/oidc/token.handler.ts`)
    - POST `/token`
    - Handle `authorization_code` grant
    - Handle `refresh_token` grant
    - PKCE validation
    - Issue Passage tokens after upstream validation

- [ ] **3.5 UserInfo Endpoint** (`src/routes/oidc/userinfo.handler.ts`)
    - GET/POST `/userinfo`
    - Extract and validate bearer token
    - Return user claims

- [ ] **3.6 Logout Endpoint** (`src/routes/oidc/logout.handler.ts`)
    - GET/POST `/logout`
    - Handle `id_token_hint`, `post_logout_redirect_uri`, `state`
    - Invalidate sessions
    - Optional upstream logout

---

### Phase 4: Route Integration

- [ ] **4.1 Complete `setupOidcProviderRoutes()`** (`src/routes/auth.routes.ts`)
    - Create Express Router
    - Mount all OIDC handlers under provider's endpoint_url
    - Return router for mounting

- [ ] **4.2 Update Main Routes** (`src/routes.ts`)
    - Uncomment/add `setupOidcRoutes(app)` call
    - Ensure proper mounting order

- [ ] **4.3 Bootstrap Integration** (`src/server.ts`)
    - Initialize JWKS Service before routes
    - Initialize Session Service
    - Log initialization status

---

### Phase 5: Testing

- [ ] **5.1 Service Unit Tests**
    - `src/tests/services/jwks.service.test.ts`
    - `src/tests/services/token.service.test.ts`
    - `src/tests/services/discovery.service.test.ts`
    - `src/tests/services/session.service.test.ts`

- [ ] **5.2 Endpoint Integration Tests** (`src/tests/auth.oidc.test.ts`)
    - Discovery endpoint returns valid document
    - JWKS endpoint returns public keys
    - Authorize endpoint validates params and redirects
    - Token endpoint issues valid JWTs
    - UserInfo endpoint requires valid token

---

## Implementation Order

| Order | Task                   | Dependencies  |
|-------|------------------------|---------------|
| 1     | 1.1 OIDC Types         | None          |
| 2     | 1.2 OIDC Schemas       | 1.1           |
| 3     | 1.3 Provider Schema    | None          |
| 4     | 2.1 JWKS Service       | 1.1, KMS      |
| 5     | 2.2 Discovery Service  | 1.1           |
| 6     | 2.3 Session Service    | 1.1, 1.2      |
| 7     | 2.4 Token Service      | 2.1, 2.3      |
| 8     | 2.5 Upstream Service   | 1.1           |
| 9     | 3.1 Discovery Handler  | 2.2           |
| 10    | 3.2 JWKS Handler       | 2.1           |
| 11    | 3.3 Authorize Handler  | 2.3, 2.5      |
| 12    | 3.4 Token Handler      | 2.4, 2.3, 2.5 |
| 13    | 3.5 UserInfo Handler   | 2.4, 2.5      |
| 14    | 3.6 Logout Handler     | 2.3           |
| 15    | 4.1 setupOidcProviderRoutes    | 3.1-3.6       |
| 16    | 4.2 Routes Integration | 4.1           |
| 17    | 4.3 Bootstrap          | 2.1, 2.3      |
| 18    | 5.1-5.2 Tests          | All above     |

---

## Critical Files Reference

| File                                   | Purpose                                                     |
|----------------------------------------|-------------------------------------------------------------|
| `src/routes/auth.routes.ts`            | Main file to modify - contains `setupOidcProviderRoutes()` stub     |
| `src/services/kms-local.ts`            | Pattern reference for singleton service design              |
| `src/utils/schemas/providersConfig.ts` | Schema to extend                                            |
| `src/tests/test-utils.ts`              | Test utilities with `TestDataBuilders`, `MockProviderUtils` |
| `src/routes/health.routes.ts`          | Pattern reference for inline route handlers                 |

---

## Notes

- **Storage**: Initial implementation uses in-memory Maps. Production needs Redis/database abstraction.
- **Keys**: JWKS Service must integrate with or extend LocalKMS for key storage.
- **Clients**: No client model exists yet. Initial implementation can use config-based client definitions.
- **PKCE**: Required for public clients, recommended for all clients.
