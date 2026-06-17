import {Application} from "express";
import {ProviderEntryType, ProvidersConfigType} from "../utils/schemas/config.schemas";
import {upstreamOidc} from "../services/upstream/oidc-client.service";
import {logger} from "../utils/logger";


/**
 * Attaches a route-system for the specified OIDC provider.
 * @param app Express application
 * @param provider OIDC provider configuration
 */
function attachOidcProvider(app: Application, provider: ProviderEntryType) {
  const basePath = `/${provider.ServerConfig.endpoint_url}`;
  logger.debug(`Setting up OIDC routes for provider: ${provider.name} at ${basePath}`);

  // Discovery Endpoint - returns the upstream provider's metadata
  app.get(`${basePath}/.well-known/openid-configuration`, (req, res) => {
    try {
      const config = upstreamOidc.getConfig(provider.name);
      // serverMetadata() returns the OIDC discovery document (AuthorizationServer)
      res.json(config.serverMetadata());
    } catch (error: any) {
      logger.error(`Discovery error for ${provider.name}:`, error);
      res.status(500).json({error: error.message});
    }
  });

  // TODO Authorization Endpoint
  // TODO Token Endpoint
  // TODO UserInfo Endpoint
  // TODO JWKS Endpoint
  // TODO OPT. Introspection Endpoint
  // TODO OPT. Revocation Endpoint
  // TODO OPT. End Session Endpoint
  // TODO OPT. Registration Endpoint
  // TODO OPT. Device Authorization Endpoint

  logger.debug(`Routes for provider ${provider.name} set up`);
}


/**
 * Sets up routes for all providers scoped in the configuration.
 * @param app Express application
 */
export async function setupOidcRoutes(app: Application, providersConfig: ProvidersConfigType) {
  const oidcProviders = providersConfig.providers.filter(p => p.auth_protocol === 'oidc');

  // Nothing to federate — skip upstream initialization entirely. This keeps core usable
  // with no providers configured (and means the KMS need not be initialized).
  if (oidcProviders.length === 0) {
    logger.debug('No OIDC providers configured; skipping OIDC route setup');
    return;
  }

  // Initialize upstream OIDC factory (fetches discovery docs)
  await upstreamOidc.initialize(oidcProviders);
  logger.debug(`Initialized upstream OIDC factory for ${oidcProviders.length} providers`);

  // Build routes for each OIDC provider
  for (const provider of oidcProviders) {
    attachOidcProvider(app, provider);
  }
}
