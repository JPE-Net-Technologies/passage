// examples/keycloak-basic — a runnable Passage deployment preset.
//
// This is the "own it" layer: it owns the config directory, the KMS keystore location,
// and the process lifecycle, then composes @passage/core. Copy this example as the
// starting point for your own deployment.
import path from 'node:path';
import {
  createApp,
  localKMS,
  logger,
  gracefulShutdown,
} from '@passage/core';
import {loadAppConfig, configPath} from '@passage/core/config';

const PRESET_ROOT = path.join(import.meta.dir, '..');
const CONFIG_DIR = path.join(PRESET_ROOT, 'config');

async function bootstrap() {
  try {
    // Initialize the local KMS against THIS preset's keystore + secrets (injected paths —
    // core never guesses the working directory).
    await localKMS.initialize({
      keystorePath: path.join(PRESET_ROOT, 'kms-local.keystore'),
      secretsPath: configPath(CONFIG_DIR, 'secrets'),
    });
    logger.info('Local KMS initialized');

    // Load + validate this preset's YAML config, then build the app.
    const config = loadAppConfig(CONFIG_DIR);
    const app = await createApp(config);

    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => {
      logger.info(`🚀 Passage (keycloak-basic preset) running on port ${PORT}`, {
        env: process.env.NODE_ENV || 'development',
        pid: process.pid,
      });
    });

    setupGracefulShutdown(server);
    return server;
  } catch (error: any) {
    logger.error('Failed to start server', {message: error?.message, stack: error?.stack});
    process.exit(1);
  }
}

function setupGracefulShutdown(server: {close: (cb: () => void) => void}) {
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);
    server.close(async () => {
      logger.info('HTTP server closed');
      try {
        await gracefulShutdown();
        logger.info('Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during shutdown', error);
        process.exit(1);
      }
    });
    setTimeout(() => {
      logger.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

bootstrap().then(() => logger.info('Server started'));
