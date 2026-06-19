// tests/discovery.service.test.ts — Passage's own OIDC discovery document builder.
//
// A pure function: the happy path asserts the whole document exactly (killing every
// field/endpoint/literal mutant), and the two no-issuer paths cover the guard.
import {describe, it, expect} from 'bun:test';
import {buildDiscoveryDocument} from '../services/oidc/discovery.service';

const provider = (oidcOver: Record<string, any> = {}): any => ({
  name: 'oidc-x',
  auth_protocol: 'oidc',
  ServerConfig: {endpoint_url: 'oidc-x', client_id: 'c'},
  OidcConfig: {supported_auth_flows: ['authorization_code'], issuer: 'https://iss.test/oidc-x', ...oidcOver},
});

describe('buildDiscoveryDocument', () => {
  it('builds Passage own discovery doc with issuer-derived endpoints', () => {
    expect(buildDiscoveryDocument(provider())).toEqual({
      issuer: 'https://iss.test/oidc-x',
      authorization_endpoint: 'https://iss.test/oidc-x/authorize',
      token_endpoint: 'https://iss.test/oidc-x/token',
      userinfo_endpoint: 'https://iss.test/oidc-x/userinfo',
      jwks_uri: 'https://iss.test/oidc-x/jwks',
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: ['openid'],
      response_modes_supported: ['query'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('throws when the provider has an OidcConfig but no issuer', () => {
    expect(() => buildDiscoveryDocument(provider({issuer: undefined}))).toThrow('no issuer configured');
  });

  it('throws when the provider has no OidcConfig at all', () => {
    const prov = {name: 'x', auth_protocol: 'oidc', ServerConfig: {endpoint_url: 'x', client_id: 'c'}} as any;
    expect(() => buildDiscoveryDocument(prov)).toThrow('no issuer configured');
  });
});
