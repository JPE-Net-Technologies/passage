import {Application, Request, Response} from "express";
import {ProviderEntryType, ProvidersConfigType, ClientsConfigType} from "../utils/schemas/config.schemas";
import {upstreamOidc} from "../services/upstream/oidc-client.service";
import {jwksService} from "../services/oidc/jwks.service";
import {sessionService} from "../services/oidc/session.service";
import {federationService, FederationError} from "../services/oidc/federation.service";
import {tokenService} from "../services/oidc/token.service";
import {grantService, GrantError} from "../services/oidc/grant.service";
import {clientRegistry} from "../services/oidc/client-registry.service";
import {extractClientCredentials, authenticateClient, ClientAuthError} from "../services/oidc/client-auth.service";
import {userInfoService, UserInfoError, extractBearerToken} from "../services/oidc/userinfo.service";
import {logoutService, LogoutError} from "../services/oidc/logout.service";
import {buildDiscoveryDocument} from "../services/oidc/discovery.service";
import {AuthorizationRequestSchema, TokenRequestSchema, LogoutRequestSchema} from "../utils/schemas/oidc.schemas";
import {logger} from "../utils/logger";

/** Map an OAuth error code to an HTTP status (server_error ⇒ 500, client errors ⇒ 400). */
const statusFor = (code: string): number => (code === 'server_error' ? 500 : 400);

/** Send an OAuth error response; a FederationError/GrantError/LogoutError carries its own code, anything else is a server_error. */
function sendOAuthError(res: Response, error: unknown): void {
  // A failed client authentication is an HTTP-status concern: invalid_client is 401, and when the
  // client attempted HTTP Basic the response carries a WWW-Authenticate challenge (RFC 6749 §5.2).
  if (error instanceof ClientAuthError) {
    if (error.code === 'invalid_client') {
      if (error.usedBasic) {
        res.set('WWW-Authenticate', 'Basic');
      }
      res.status(401).json({error: 'invalid_client'});
      return;
    }
    res.status(statusFor(error.code)).json({error: error.code});
    return;
  }
  const code = error instanceof FederationError || error instanceof GrantError || error instanceof LogoutError ? error.code : 'server_error';
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

  // Callback Endpoint - upstream returns here; mint a Passage code and redirect to the downstream client.
  // The redirect target is session.redirect_uri, which was validated against the client registry at
  // /authorize (federationService.beginAuthorization), so it is a registered URI — no open redirect.
  app.get(`${basePath}/callback`, async (req, res) => {
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
    const parsed = TokenRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({error: 'invalid_request'});
      return;
    }
    try {
      // Authenticate the downstream client before issuing tokens: confidential clients must present a
      // registered secret (Basic or post), public clients use `none`. The grant separately binds the
      // code to its client_id/redirect_uri (gate §G); this proves client identity (RFC 6749 §3.2.1).
      const client = clientRegistry.getClient(parsed.data.client_id);
      if (!client) {
        throw new ClientAuthError('invalid_client', 'unknown client');
      }
      authenticateClient(client, extractClientCredentials(req.headers.authorization, req.body));
      // Per-client grant policy: a client may be restricted to a subset of grant types.
      if (client.allowed_grants && !client.allowed_grants.includes(parsed.data.grant_type)) {
        throw new GrantError('unauthorized_client', `grant_type ${parsed.data.grant_type} not allowed for this client`);
      }
      const tokens = await grantService.exchange(provider, parsed.data);
      res.set('Cache-Control', 'no-store').json(tokens); // RFC 6749 §5.1 — token responses must not be cached
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  // UserInfo Endpoint - return the authenticated user's claims for a valid Bearer access token.
  // OIDC Core §5.3 requires both GET and POST; the access token is read from the Authorization header.
  const userInfoHandler = async (req: Request, res: Response) => {
    const token = extractBearerToken(req.headers.authorization);
    if (!token) {
      res.status(401).set('WWW-Authenticate', 'Bearer').json({error: 'invalid_request'});
      return;
    }
    try {
      res.json(await userInfoService.getUserInfo(token, provider.OidcConfig!.issuer!));
    } catch (error) {
      const code = (error as UserInfoError).code;
      res.status(401).set('WWW-Authenticate', `Bearer error="${code}"`).json({error: code});
    }
  };
  app.get(`${basePath}/userinfo`, userInfoHandler);
  app.post(`${basePath}/userinfo`, userInfoHandler);

  // Revocation Endpoint (RFC 7009) - authenticate the client, then revoke a refresh token (and its
  // whole family). An unknown/foreign token is a silent no-op, but a 200 is only reached once the
  // client has been authenticated (RFC 7009 §2.1).
  app.post(`${basePath}/revoke`, (req, res) => {
    const token = req.body.token; // body is always an object (express.urlencoded is mounted)
    if (!token) {
      res.status(400).json({error: 'invalid_request'});
      return;
    }
    try {
      const creds = extractClientCredentials(req.headers.authorization, req.body);
      const client = creds.client_id ? clientRegistry.getClient(creds.client_id) : undefined;
      if (!client) {
        throw new ClientAuthError('invalid_client', 'unknown or unidentified client', creds.usedBasic);
      }
      authenticateClient(client, creds);
      grantService.revoke(token);
      res.status(200).end();
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  // End Session Endpoint (RP-Initiated Logout) - validate the request, then redirect to a registered
  // post_logout_redirect_uri or return a confirmation. OIDC requires both GET and POST.
  const endSessionHandler = async (req: Request, res: Response) => {
    const source = req.method === 'POST' ? req.body : req.query;
    const parsed = LogoutRequestSchema.safeParse(source);
    if (!parsed.success) {
      res.status(400).json({error: 'invalid_request', error_description: parsed.error.issues[0].message});
      return;
    }
    try {
      const {redirectUrl} = await logoutService.endSession({...parsed.data, issuer: provider.OidcConfig!.issuer!});
      if (redirectUrl) {
        res.redirect(303, redirectUrl);
      } else {
        res.status(200).json({message: 'logged out'});
      }
    } catch (error) {
      sendOAuthError(res, error);
    }
  };
  app.get(`${basePath}/end_session`, endSessionHandler);
  app.post(`${basePath}/end_session`, endSessionHandler);

  // TODO OPT. Introspection Endpoint
  // TODO OPT. Registration Endpoint
  // TODO OPT. Device Authorization Endpoint

  logger.debug(`Routes for provider ${provider.name} set up`);
}


/**
 * Sets up routes for all providers scoped in the configuration.
 * @param app Express application
 */
export async function setupOidcRoutes(app: Application, providersConfig: ProvidersConfigType, clientsConfig: ClientsConfigType) {
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

  // Initialize the authorization-session store, the downstream client registry (consumed by the
  // federation flow to validate client_id/redirect_uri), and the federation flow service.
  sessionService.initialize();
  clientRegistry.initialize(clientsConfig.clients);
  federationService.initialize();

  // Initialize the token issuer + the grant flow that the /token endpoint consumes, plus the
  // claims store the grant flow writes to and the /userinfo endpoint reads from.
  tokenService.initialize();
  userInfoService.initialize();
  logoutService.initialize();
  grantService.initialize();

  // Build routes for each OIDC provider
  for (const provider of oidcProviders) {
    attachOidcProvider(app, provider);
  }
}
