import {z} from "zod";
import {RegexPatterns} from "../regex";

export const ProviderEntrySchema = z.object({
  name: z.string(),
  auth_protocol: z.string({error: "Invalid/Missing provider type"}).regex(RegexPatterns.ensureSupportedAuthProtocol),
  ServerConfig: z.object({
    endpoint_url: z.string(),
    client_id: z.string(),
  }).loose(),
  TestConfig: z.object({
    keycloak_realm: z.string(),
  }).loose().optional(),
  OidcConfig: z.object({
    // Supported OAuth2/OIDC flows
    supported_auth_flows: z.array(z.string()),

    // Upstream provider configuration (for federation)
    upstream_issuer: z.string().url().optional(),
    upstream_client_id: z.string().optional(),
    upstream_client_secret_ref: z.string().optional(), // KMS secret reference

    // Scopes to request from upstream provider
    upstream_scopes: z.array(z.string()).optional(),

    // Token configuration
    access_token_lifetime: z.number().int().positive().optional(),
    id_token_lifetime: z.number().int().positive().optional(),
    refresh_token_lifetime: z.number().int().positive().optional(),
  }).loose().optional()
}).loose();

export type ProviderEntryType = z.infer<typeof ProviderEntrySchema>;
export const ProvidersConfig = z.object({
  providers: z.array(ProviderEntrySchema),
}).loose();

export type ProvidersConfigType = z.infer<typeof ProvidersConfig>;

export const SecurityConfigSchema = z.object({
  cors: z.object({
    origins: z.array(z.string()).default(['http://localhost:3000']),
    credentials: z.boolean().default(true)
  }),
  rateLimit: z.object({
    windowMs: z.number().default(15 * 60 * 1000), // 15 minutes
    max: z.number().default(100), // limit each IP to 100 requests per windowMs
    standardHeaders: z.boolean().default(true),
    legacyHeaders: z.boolean().default(false)
  }),
  headers: z.object({
    contentSecurityPolicy: z.boolean().default(true),
    hsts: z.object({
      maxAge: z.number().default(31536000),
      includeSubDomains: z.boolean().default(true),
      preload: z.boolean().default(true)
    }),
  }),
});

export type SecurityConfigType = z.infer<typeof SecurityConfigSchema>;
