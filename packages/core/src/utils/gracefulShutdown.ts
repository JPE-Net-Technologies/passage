import { logger } from './logger';

const shutdownHandlers: Array<() => Promise<void>> = [];

export function registerShutdownHandler(handler: () => Promise<void>) {
  shutdownHandlers.push(handler);
}

export async function gracefulShutdown() {
  logger.info('Running shutdown handlers...');
  
  for (const handler of shutdownHandlers) {
    try {
      await handler();
    } catch (error) {
      logger.error('Error in shutdown handler', error);
    }
  }
}
