import express from 'express';
import CommonMiddleware from './middleware/commonMiddleware';
import ErrorHandlerMiddleware from './middleware/errorHandlerMiddleware';
import {SecurityConfigSchema, type SecurityConfigType} from './utils/schemas/config.schemas';

/**
 * Setup middleware for the application, loaded in order of declaration.
 * @param app Express application
 * @param security Security settings (CORS/rate-limit) for the config-driven middleware. Optional so
 *   external embedders calling setupMiddleware directly keep working; falls back to schema defaults.
 */
export function setupMiddleware(app: express.Application, security?: SecurityConfigType) {
  const securityConfig = security ?? SecurityConfigSchema.parse({cors: {}, rateLimit: {}, headers: {hsts: {}}});
  new CommonMiddleware(securityConfig).mount(app);
  new ErrorHandlerMiddleware().mount(app);
  // Add more middleware here to mount
}
