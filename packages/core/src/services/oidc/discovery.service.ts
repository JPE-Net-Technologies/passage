// src/services/oidc/discovery.service.ts
// Builds Passage's OWN OIDC discovery document for a provider authority — the metadata a
// downstream client reads to find Passage's /authorize, /token, /jwks endpoints. This is NOT
// the upstream provider's metadata. Endpoints are derived from the provider's configured
// `issuer` (the same value Passage signs tokens with and uses for the upstream redirect_uri),
// per the per-provider-authority model. See the broker correctness gate §L.
//
// A pure function (no state, no seams) so it is trivially unit-testable to the repo's
// 100% line + 100% mutation gates.
import {ProviderEntryType} from '../../utils/schemas/config.schemas';
import {OIDCDiscoveryDocument} from '../../types/oidc.types';

/** Build the discovery document for a provider authority. Throws if the provider has no issuer. */
export function buildDiscoveryDocument(provider: ProviderEntryType): OIDCDiscoveryDocument {
  const issuer = provider.OidcConfig?.issuer;
  if (!issuer) {
    throw new Error('provider has no issuer configured');
  }
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: ['openid'],
    response_modes_supported: ['query'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
  };
}
