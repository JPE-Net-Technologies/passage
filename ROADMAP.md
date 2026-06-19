# Passage Roadmap

This document outlines the vision and planned evolution of Passage from an identity platform to a complete authentication-centric application runtime.

---

## Vision

Passage is the **core identity layer** around which an ecosystem of declarative, sidecar functions and add-on packages can be composed. Think Firebase Functions riding alongside Firebase Auth - but installable, self-hosted, and entirely configuration-driven.

**Distribution model:** Passage ships as the installable package **`@passage/core`** plus a set of runnable **presets** under `examples/`. You `bun add @passage/core`, inject your config, and mount the app — or copy a preset as a starting point and own it outright. Forking the core remains possible as a last-resort escape hatch, but it is not the path we expect or optimize for.

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   Nightly   │  │  Post-Auth  │  │   Cleanup   │  Add-on  │
│  │   Workers   │  │  Callbacks  │  │  Functions  │ Packages │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│         └────────────────┼────────────────┘                  │
│                          ▼                                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   PASSAGE CORE                         │  │
│  │         Identity Platform + Function Runtime           │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Current State

### Phase 1: Foundation (In Progress)

- [x] Express.js + TypeScript + Bun runtime
- [x] YAML-based declarative configuration with Zod validation
- [x] Component-based middleware architecture
- [x] Local KMS for secrets management
- [x] Structured logging system
- [x] Docker Compose development environment (Keycloak, Postgres, MongoDB)
- [x] OIDC type definitions and validation schemas
- [x] **Package-first distribution**: bun-workspace monorepo — `@passage/core` (config injected, no cwd coupling) + runnable presets under `examples/`
- [x] **100% line/statement coverage** gate on the core (`bunfig.toml`), plus **100% Stryker mutation** on the logger-free OIDC services
- [x] Core OIDC services (JWKS, Token, Session, Discovery)
- [x] OIDC route handlers (`/authorize`, `/callback`, `/token`, `/userinfo`, `/jwks`, discovery)
- [x] Upstream provider federation (discovery + auth-code exchange + userinfo)

---

## Near-Term Roadmap

### Quick Wins (high-leverage, easy to test)

Small additions that mostly reuse substrate already built (client registry,
`sessionService.revokeRefreshFamily`, the request schemas, the security config) — each is a
thin route/service slice with a clear unit + E2E test, and each closes a visible gap:

- **RP-Initiated Logout** (`/end_session`) — `LogoutRequestSchema` already exists, and the
  client registry makes `post_logout_redirect_uri` validation a one-liner. Clears the session;
  best-effort upstream propagation.
- **Token Revocation** (RFC 7009, `/revoke`) — reuses `revokeRefreshFamily`.
- **Token Introspection** (RFC 7662, `/introspect`) — reuses `tokenService.verify` / refresh lookup.
- **Mix-up defense** — add the RFC 9207 `iss` parameter to the downstream authorization response.
- **Per-client policy enforcement** — `pkce_required` + `allowed_scopes` at `/authorize` (registry
  fields already defined; enforcement was deferred from Increment 6).
- **Config-driven CORS** — wire the existing `security.cors` config (currently hardcoded in middleware).
- **Advertise new endpoints** in discovery (`end_session_endpoint`, `revocation_endpoint`,
  `introspection_endpoint`) as each lands.

### Phase 2: Core OIDC Implementation ✓ (complete)

Identity broker functionality (all shipped at 100% line + mutation):

- **JWKS Service** - Key generation, rotation, public key exposure
- **Token Service** - JWT issuance, validation, refresh token management
- **Session Service** - Authorization session state, PKCE validation
- **Discovery Service** - Dynamic OIDC discovery document generation
- **Upstream Federation** - Exchange tokens with Keycloak, Auth0, Okta, Azure AD

### Phase 3: Client Management (in progress)

Declarative client registration. **Landed:** the registry + exact `redirect_uri` / `client_id`
validation at `/authorize`. **Remaining:** client authentication at `/token`
(`client_secret_basic`/`_post`, `none`), and `allowed_grants` / `allowed_scopes` / `pkce_required`
enforcement (see Quick Wins).

```yaml
# config/clients.yaml
clients:
  - client_id: "my-spa"
    client_type: public
    redirect_uris:
      - "http://localhost:3000/callback"
      - "https://app.example.com/callback"
    allowed_scopes: ["openid", "profile", "email"]
    pkce_required: true

  - client_id: "backend-service"
    client_type: confidential
    client_secret_ref: "BackendServiceSecret"  # KMS reference
    allowed_grants: ["client_credentials"]
    allowed_scopes: ["api:read", "api:write"]
```

### Phase 4: Storage Abstraction

Today every stateful store (authorization sessions, one-time codes, refresh-token families, the
claims store, the client registry) is an in-memory `Map` behind a narrow consumer interface.
Consumers are already decoupled; the next step is to make the **backend pluggable** and ship
durable adapters. This is a *correctness* requirement, not just scale: a single-instance
in-memory store cannot guarantee one-time code use or refresh-token reuse detection across
restarts/instances (broker correctness gate §11.5).

- **`StorageAdapter` contract** - one injectable backend spanning sessions / codes / refresh
  families / claims / client registry, selectable at `createApp` (the same adapter pattern as
  email/secrets/observability — see below).
- **Redis** - natural fit for the ephemeral, single-use, replay-cache stores.
- **PostgreSQL / SQLite** - durable client registry, users, refresh families, audit.
- **MongoDB** - document-based user profiles (already in the dev compose).
- **Key persistence** - persist JWKS signing keys with overlapping-`kid` rotation (gate Stage 1)
  so issued tokens stay verifiable across restarts/instances; ties into LocalKMS.
- **User store backends** - In-Memory / PostgreSQL / MongoDB / LDAP-AD / Upstream-Only (stateless).

---

## Medium-Term Roadmap

### Phase 5: Passage Functions

Declarative, sidecar function runtime that plugs into Passage core.

#### Function Types

```yaml
# config/functions.yaml
functions:
  # Scheduled workers (cron-style)
  - name: "nightly-session-cleanup"
    type: scheduled
    schedule: "0 2 * * *"  # 2 AM daily
    handler: "./functions/cleanup-sessions.ts"
    timeout: 300s

  # Event-driven hooks
  - name: "post-registration-sync"
    type: event
    trigger: "user.registered"
    handler: "./functions/sync-to-crm.ts"
    retry:
      attempts: 3
      backoff: exponential

  # Auth flow interceptors
  - name: "enrich-token-claims"
    type: interceptor
    stage: "pre-token-issue"
    handler: "./functions/add-custom-claims.ts"

  # HTTP endpoints (custom APIs)
  - name: "user-preferences-api"
    type: http
    path: "/api/preferences"
    methods: ["GET", "POST"]
    handler: "./functions/preferences.ts"
    auth_required: true
```

#### Event Triggers

| Event | Description |
|-------|-------------|
| `user.registered` | New user created |
| `user.authenticated` | Successful login |
| `user.logout` | Session terminated |
| `token.issued` | Access/ID token generated |
| `token.refreshed` | Token refresh completed |
| `session.expired` | Session TTL reached |
| `provider.callback` | Upstream provider returned |

#### Function Context

Functions receive rich context from Passage core:

```typescript
// functions/post-login.ts
import { PassageFunction, AuthContext } from '@passage/functions';

export default PassageFunction({
  async handler(ctx: AuthContext) {
    const { user, session, provider, claims } = ctx;

    // Sync to external system
    await crm.updateLastLogin(user.sub, new Date());

    // Add custom claims to token
    return {
      claims: {
        ...claims,
        crm_id: await crm.getCustomerId(user.email)
      }
    };
  }
});
```

### Phase 6: Scheduled Workers

Built-in worker primitives:

- **Nightly Jobs** - Cleanup, aggregation, reports
- **Token Revocation Sweeps** - Clear expired refresh tokens
- **Session Pruning** - Remove stale sessions
- **Audit Log Rotation** - Archive and compress old logs
- **Provider Health Checks** - Monitor upstream availability

```yaml
workers:
  - name: "token-cleanup"
    schedule: "*/15 * * * *"  # Every 15 minutes
    handler: builtin:token-cleanup
    config:
      expired_threshold: 7d

  - name: "audit-export"
    schedule: "0 0 * * 0"  # Weekly
    handler: "./workers/export-audit-logs.ts"
    config:
      destination: "s3://audit-logs-bucket"
```

---

## Long-Term Vision

### Phase 7: Add-on Packages

A package ecosystem for common identity patterns:

#### Official Packages

| Package | Description |
|---------|-------------|
| `@passage/mfa-totp` | TOTP-based multi-factor authentication |
| `@passage/mfa-webauthn` | Passkey/WebAuthn support |
| `@passage/rbac` | Role-based access control |
| `@passage/abac` | Attribute-based access control (OPA integration) |
| `@passage/audit` | Comprehensive audit logging |
| `@passage/rate-limit` | Advanced rate limiting with Redis |
| `@passage/geo-block` | Geographic access restrictions |
| `@passage/session-redis` | Redis-backed session storage |
| `@passage/impersonation` | Admin user impersonation |
| `@passage/magic-link` | Passwordless email authentication |
| `@passage/email` | Transactional email adapter (Resend / SES / Cloudflare / Postmark / SMTP) |
| `@passage/webhooks` | Reliable outbound event delivery to downstream apps (Svix-style) |
| `@passage/consent` | OAuth consent screen for third-party clients |
| `@passage/scim` | SCIM 2.0 provisioning server (just-in-time + timely deprovisioning) |

#### Package Configuration

```yaml
# config/packages.yaml
packages:
  - name: "@passage/mfa-totp"
    enabled: true
    config:
      issuer: "MyApp"
      required_for_roles: ["admin", "finance"]

  - name: "@passage/rbac"
    enabled: true
    config:
      roles_source: "./config/roles.yaml"
      default_role: "user"

  - name: "@passage/audit"
    enabled: true
    config:
      storage: mongodb
      retention_days: 90
      pii_masking: true
```

### Phase 8: Advanced Integrations

Deep integrations for enterprise scenarios:

- **SCIM Provisioning** - Automatic user sync from HR systems
- **SAML 2.0 SP/IdP** - Full SAML support for legacy enterprise
- **Certificate Authentication** - mTLS client certificate auth
- **Hardware Security Modules** - HSM integration for key storage
- **Secrets Manager Integration** - AWS Secrets Manager, HashiCorp Vault, Azure Key Vault
- **OIDC Conformance Harness** - run the official OpenID conformance suite in CI
- **Observability** - OpenTelemetry traces/metrics adapter (same injectable-adapter pattern)

### Phase 9: Multi-Tenancy

SaaS-ready identity isolation:

```yaml
tenants:
  - id: "tenant-a"
    domain: "auth.tenant-a.com"
    providers: ["azure-ad"]
    branding:
      logo: "https://..."
      primary_color: "#1a73e8"

  - id: "tenant-b"
    domain: "auth.tenant-b.com"
    providers: ["okta", "google"]
    branding:
      logo: "https://..."
```

### Phase 10: Deployment Flexibility

Multiple runtime modes:

| Mode | Use Case |
|------|----------|
| **Standalone** | Traditional deployment, own process |
| **Embedded** | Import as library, mount in existing Express app |
| **Sidecar** | Kubernetes sidecar container |
| **Edge** | Cloudflare Workers / Deno Deploy / Vercel Edge |
| **Serverless** | AWS Lambda / Google Cloud Functions |

### Phase 11: Management Dashboard

An admin UI (**Next.js** — same stack as the docs, one frontend toolchain) over the declarative
core: manage clients, providers, and keys; browse/revoke users and sessions; view the audit log;
trigger key rotation; diff live config. A thin operability layer over the same validated config +
stores — never a second source of truth.

### Phase 12: End-to-End Test Harness

Browser-level coverage to complement the unit + 100% mutation gate:

- **Auth-flow E2E** (Playwright) — drive a real login through `/authorize` → upstream (Keycloak
  from the dev compose) → `/callback` → `/token` → a sample downstream app, asserting the re-minted
  token and `/userinfo`.
- **Dashboard UI tests** (Playwright) — client/provider CRUD, session revocation, key rotation.
- Runs against the docker-compose stack in CI; the natural home for the OIDC conformance suite.

### Phase 13: Declarative Admin & Infrastructure-as-Code

The "Terraform of dev practices" made literal — manage Passage's declarative resources as code:

- **Passage Terraform provider** — `terraform apply` your client/provider registry.
- **Config-as-code CLI** — validate, diff, and push config; GitOps-friendly.
- **Drift checks** — CI gate that the running broker matches declared config.

---

## Philosophy

### Why This Architecture?

**1. Auth is the hardest solved problem**

Every application needs authentication. Most teams either:
- Cobble together libraries and hope for the best
- Pay for SaaS and accept vendor lock-in
- Deploy Keycloak and struggle with its complexity

Passage provides a middle path: production-ready auth you actually own.

**2. Functions belong with identity**

Post-authentication workflows (sync to CRM, send welcome email, provision resources) are tightly coupled to auth events. Running them as sidecar functions eliminates:
- Webhook reliability issues
- Event ordering problems
- Distributed transaction complexity

**3. Packages over plugins**

Plugin systems are brittle. Package ecosystems are composable. Each `@passage/*` package is:
- Independently versioned
- Declaratively configured
- Optional (tree-shakeable)
- Fork-friendly (vendor if needed)

**4. Configure first; fork only as an escape hatch**

Keycloak has 500+ configuration options. That's not flexibility, that's complexity.

Passage's answer is the opposite of "just fork it": clean, declarative YAML validated by Zod, composed by an installable core (`@passage/core`) you depend on rather than copy. Start from a preset, inject your config, and add `@passage/*` packages for capabilities. Forking the core is a deliberate last resort for the rare case the seams don't reach — the architecture keeps it *safe*, but distribution is package-first, not fork-first.

---

## Contributing

This roadmap is aspirational. Contributions welcome:

- **Phase 1-4**: Core identity features
- **Phase 5-6**: Function runtime design
- **Phase 7+**: Package ecosystem architecture

See `CONTRIBUTING.md` for guidelines.
