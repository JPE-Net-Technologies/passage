// config-loader.ts — exposed as the optional `@passage/core/config` subpath.
//
// A convenience for presets/deployments that keep their config as YAML on disk. Core
// itself never calls these: it receives an already-validated `AppConfig`. Everything here
// is parameterized by an explicit `configDir`, so there is no `process.cwd()` coupling.
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import {
  ProvidersConfig,
  ProvidersConfigType,
  SecurityConfigSchema,
  SecurityConfigType,
  ClientsConfig,
  ClientsConfigType,
} from './utils/schemas/config.schemas';
import {ENV} from './utils/config';
import {logger} from './utils/logger';
import type {AppConfig} from './app';

/** YAML filename prefix per environment: `template.*` in dev, `production.*` otherwise. */
export const configFilePrefix = (): 'production' | 'template' =>
  ENV === 'production' ? 'production' : 'template';

function readYaml(filePath: string): unknown {
  if (!fs.existsSync(filePath)) {
    logger.warn(`Config file not found`, {path: filePath});
    return undefined;
  }
  logger.debug(`Loading config`, {path: filePath});
  return yaml.load(fs.readFileSync(filePath, 'utf8'));
}

/** Resolve the absolute path of a config file within `configDir` for the current env. */
export function configPath(configDir: string, name: 'security' | 'providers' | 'secrets' | 'clients'): string {
  return path.join(configDir, `${configFilePrefix()}.${name}.yaml`);
}

export function loadSecurityConfig(configDir: string): SecurityConfigType {
  return SecurityConfigSchema.parse(readYaml(configPath(configDir, 'security')));
}

export function loadProvidersConfig(configDir: string): ProvidersConfigType {
  return ProvidersConfig.parse(readYaml(configPath(configDir, 'providers')));
}

/** Load the client registry; an absent clients file yields an empty registry. */
export function loadClientsConfig(configDir: string): ClientsConfigType {
  return ClientsConfig.parse(readYaml(configPath(configDir, 'clients')) ?? {clients: []});
}

/** Load and validate the full `AppConfig` from a config directory. */
export function loadAppConfig(configDir: string): AppConfig {
  return {
    security: loadSecurityConfig(configDir),
    providers: loadProvidersConfig(configDir),
    clients: loadClientsConfig(configDir),
  };
}
