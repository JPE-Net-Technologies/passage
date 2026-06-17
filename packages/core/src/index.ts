// @passage/core — public API surface.
//
// Import this to embed Passage in your own app or build a deployment preset:
//   import { createApp, localKMS } from '@passage/core';
//   import { loadAppConfig } from '@passage/core/config';
//
// Config is always injected (see AppConfig) — core never reads your filesystem.

// App factory + injected config shape
export {createApp} from './app';
export type {AppConfig} from './app';

// Route + middleware building blocks
export {setupRoutes} from './routes';
export {setupOidcRoutes} from './routes/auth.routes';
export {setupMiddleware} from './middleware';
export {default as MiddlewareComponent} from './middleware/middlewareComponent';

// Services
export {localKMS, LocalKMS, SecretsConfigSchema, SecretEntrySchema} from './services/kms-local';
export type {KmsInitOptions, SecretEntry, SecretsConfig} from './services/kms-local';
export {upstreamOidc, UpstreamOidcFactory, client} from './services/upstream/oidc-client.service';

// Configuration schemas + inferred types
export {
  ProviderEntrySchema,
  ProvidersConfig,
  SecurityConfigSchema,
} from './utils/schemas/config.schemas';
export type {
  ProviderEntryType,
  ProvidersConfigType,
  SecurityConfigType,
} from './utils/schemas/config.schemas';

// OIDC type definitions + validation schemas
export * from './types/oidc.types';
export * from './utils/schemas/oidc.schemas';

// Utilities
export {ENV} from './utils/config';
export {logger} from './utils/logger';
export {gracefulShutdown, registerShutdownHandler} from './utils/gracefulShutdown';
export {RegexPatterns} from './utils/regex';
