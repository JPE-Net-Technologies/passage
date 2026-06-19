// src/services/upstream/oidc-client.service.ts
// Factory for managing upstream OIDC provider configurations
import * as client from 'openid-client';
import {ProviderEntryType} from '../../utils/schemas/config.schemas';
import {localKMS} from '../kms-local';
import {logger} from '../../utils/logger';
import {ENV} from '../../utils/config';

// Re-export openid-client for route handlers to use directly
export {client};

// Development mode: allow HTTP for local Keycloak
const isDev = ENV === 'development';

class UpstreamOidcFactory {
  private configs: Map<string, client.Configuration> = new Map();
  private initialized = false;

  /** Use the exported {@link upstreamOidc} singleton; the class is exported for tests. */
  constructor() {}

  /**
   * Initialize upstream OIDC clients for all configured providers.
   * Fetches discovery documents and caches configurations.
   * Must be called after LocalKMS is initialized (for client secrets).
   */
  async initialize(providers: ProviderEntryType[]): Promise<void> {
    if (this.initialized) {
      logger.debug('UpstreamOidcFactory already initialized');
      return;
    }

    if (!localKMS.isInitialized()) {
      throw new Error('LocalKMS must be initialized before UpstreamOidcFactory');
    }

    logger.info('Initializing UpstreamOidcFactory');

    const oidcProviders = providers.filter(p =>
      p.auth_protocol === 'oidc' && p.OidcConfig?.upstream_issuer
    );

    for (const provider of oidcProviders) {
      try {
        await this.registerProvider(provider);
      } catch (error: any) {
        logger.error(`Failed to register upstream provider: ${provider.name}`, {
          message: error?.message,
          cause: error?.cause?.message,
          status: error?.status,
          code: error?.code,
          issuer: provider.OidcConfig?.upstream_issuer
        });
      }
    }

    this.initialized = true;
    logger.info('UpstreamOidcFactory initialized', {
      providerCount: this.configs.size
    });
  }

  /**
   * Get the client configuration for a provider.
   * Use this with openid-client functions directly:
   *   const config = factory.getConfig('keycloak');
   *   const authUrl = client.buildAuthorizationUrl(config, params);
   */
  getConfig(providerName: string): client.Configuration {
    this.ensureInitialized();
    const config = this.configs.get(providerName);
    if (!config) {
      throw new Error(`Unknown provider: ${providerName}`);
    }
    return config;
  }

  /**
   * Check if a provider is registered.
   */
  hasProvider(providerName: string): boolean {
    this.ensureInitialized();
    return this.configs.has(providerName);
  }

  /**
   * Get all registered provider names.
   */
  getProviderNames(): string[] {
    this.ensureInitialized();
    return Array.from(this.configs.keys());
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Reset the factory (for testing).
   */
  reset(): void {
    this.configs.clear();
    this.initialized = false;
  }

  /**
   * Register a provider by fetching its discovery document.
   */
  private async registerProvider(provider: ProviderEntryType): Promise<void> {
    const oidcConfig = provider.OidcConfig;
    if (!oidcConfig?.upstream_issuer || !oidcConfig?.upstream_client_id) {
      throw new Error(`Provider ${provider.name} missing upstream_issuer or upstream_client_id`);
    }

    logger.debug(`Registering upstream provider: ${provider.name}`, {
      issuer: oidcConfig.upstream_issuer
    });

    // Resolve client secret from KMS if referenced
    let clientSecret: string | undefined;
    if (oidcConfig.upstream_client_secret_ref) {
      clientSecret = localKMS.getSecret(oidcConfig.upstream_client_secret_ref);
      if (!clientSecret) {
        throw new Error(`Secret not found: ${oidcConfig.upstream_client_secret_ref}`);
      }
    }

    // Discover issuer metadata and create configuration
    // In development, allow HTTP (Keycloak runs on http://localhost:8080)
    // Pin the upstream id_token signing algorithm (RP-leg algorithm-confusion defense, per the
    // broker correctness gate §D). Passing client metadata constrains verification to RS256 rather
    // than trusting whatever the upstream advertises. Per-provider override is a future follow-up.
    const config = await client.discovery(
      new URL(oidcConfig.upstream_issuer),
      oidcConfig.upstream_client_id,
      {client_secret: clientSecret, id_token_signed_response_alg: 'RS256'},
      undefined,  // client_auth_method (use default)
      isDev ? {execute: [client.allowInsecureRequests]} : undefined
    );

    this.configs.set(provider.name, config);
    logger.info(`Registered upstream provider: ${provider.name}`);
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('UpstreamOidcFactory not initialized. Call initialize() first.');
    }
  }
}

// Export singleton instance
export const upstreamOidc = new UpstreamOidcFactory();

// Export class for testing
export {UpstreamOidcFactory};
