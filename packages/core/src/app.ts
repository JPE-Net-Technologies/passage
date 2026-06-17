import express from 'express';

import {ENV as env} from './utils/config';
import type {SecurityConfigType, ProvidersConfigType} from './utils/schemas/config.schemas';
import {setupMiddleware} from './middleware';
import {setupRoutes} from './routes';
import {logger} from './utils/logger';

/**
 * Fully-resolved, validated configuration injected into the app. Core never reads this
 * from disk — the caller (a preset, a test, or an embedding app) supplies it. Build one
 * by hand or via the `@passage/core/config` loader.
 */
export interface AppConfig {
  security: SecurityConfigType;
  providers: ProvidersConfigType;
}

export async function createApp(config: AppConfig) {
  const app = express();

  // Trust proxy (important for rate limiting behind reverse proxy)
  // See more -> https://stackoverflow.com/a/23426060
  app.set('trust proxy', 1);

  // Set up middleware and routes (automatic harness to mount middleware and routes)
  setupMiddleware(app);
  await setupRoutes(app, config);

  logger.info('Passage server instance created...', {
    env, pid: env == "development" ? process.pid : undefined,
  })

  return app;
}
