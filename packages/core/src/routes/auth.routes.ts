import {Application, Response} from "express";
import {ProviderEntryType, ProvidersConfigType} from "../utils/schemas/config.schemas";
import {upstreamOidc} from "../services/upstream/oidc-client.service";
import {jwksService} from "../services/oidc/jwks.service";
import {sessionService} from "../services/oidc/session.service";
import {federationService, FederationError} from "../services/oidc/federation.service";
import {tokenService} from "../services/oidc/token.service";
import {grantService, GrantError} from "../services/oidc/grant.service";
import {buildDiscoveryDocument} from "../services/oidc/discovery.service";
import {AuthorizationRequestSchema, TokenRequestSchema} from "../utils/schemas/oidc.schemas";
import {logger} from "../utils/logger";

/** Map an OAuth error code to an HTTP status (server_error ⇒ 500, client errors ⇒ 400). */
const statusFor = (code: string): number => (code === 'server_error' ? 500 : 400);

/** Send an OAuth error response; a FederationError/GrantError carries its own code, anything else is a server_error. */
function sendOAuthError(res: Response, error: unknown): void {
  const code = error instanceof FederationError || error instanceof GrantError ? error.code : 'server_error';
  res.status(statusFor(code)).json({error: code});
}


/**
 * Attaches a route-system for the specified OIDC provider.
 * @param app Express application
 * @param provider OIDC provider configuration
 */
function attachOidcProvider(app: Application, provider: ProviderEntryType) {
  const basePath = `/${provider.ServerConfig.endpoint_url}`;
  logger.debug(`Setting up OIDC routes for provider: ${provider.name} at ${basePath}`);

  // Discovery Endpoint - returns Passage's OWN OIDC metadata for this provider authority
  // (the endpoints downstream clients use), NOT the upstream provider's metadata.
  app.get(`${basePath}/.well-known/openid-configuration`, (req, res) => {
    try {
      res.json(buildDiscoveryDocument(provider));
    } catch (error: any) {
      logger.error(`Discovery error for ${provider.name}:`, error);
      res.status(500).json({error: error.message});
    }
  });

  // JWKS Endpoint - Passage's own public signing keys (for verifying issued tokens)
  app.get(`${basePath}/jwks`, (req, res) => {
    res.set('Cache-Control', 'public, max-age=3600');
    res.json(jwksService.getPublicJWKS());
  });

  // Authorization Endpoint - begin federated login (redirect to the upstream provider)
  app.get(`${basePath}/authorize`, async (req, res) => {
    const parsed = AuthorizationRequestSchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({error: 'invalid_request', error_description: parsed.error.issues[0].message});
      return;
    }
    try {
      const {redirectUrl} = await federationService.beginAuthorization({provider, request: parsed.data});
      res.redirect(303, redirectUrl); // 303 (not 302/307) so the next hop is a GET — correctness gate §16.22
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  // Callback Endpoint - upstream returns here; mint a Passage code and redirect to the downstream client
  app.get(`${basePath}/callback`, async (req, res) => {
    // TODO(open-redirect, Phase 3): the downstream client_id/redirect_uri are NOT validated against a
    // client registry yet. We only redirect to session.redirect_uri captured at /authorize. Phase 3 must
    // validate client_id + redirect_uri against registered clients before trusting them.
    const currentUrl = new URL(`${req.protocol}://${req.get('host')}${req.originalUrl}`);
    try {
      const {redirectUrl} = await federationService.completeCallback({provider, currentUrl});
      res.redirect(303, redirectUrl); // 303 (not 302/307) so the next hop is a GET — correctness gate §16.22
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  // Token Endpoint - redeem an authorization code or rotate a refresh token into Passage-signed tokens.
  app.post(`${basePath}/token`, async (req, res) => {
    // TODO(client-auth, Phase 3): the client is not authenticated (no client registry). The grant binds
    // the code to its client_id/redirect_uri but does not verify a client secret.
    const parsed = TokenRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({error: 'invalid_request'});
      return;
    }
    try {
      const tokens = await grantService.exchange(provider, parsed.data);
      res.set('Cache-Control', 'no-store').json(tokens); // RFC 6749 §5.1 — token responses must not be cached
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  // TODO UserInfo Endpoint
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

  // Initialize Passage's own signing keys (served at each provider's /jwks).
  await jwksService.initialize();

  // Initialize the authorization-session store + the federation flow service.
  sessionService.initialize();
  federationService.initialize();

  // Initialize the token issuer + the grant flow that the /token endpoint consumes.
  tokenService.initialize();
  grantService.initialize();

  // Build routes for each OIDC provider
  for (const provider of oidcProviders) {
    attachOidcProvider(app, provider);
  }
}
