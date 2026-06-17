import express from 'express';
import CommonMiddleware from './middleware/commonMiddleware';
import ErrorHandlerMiddleware from './middleware/errorHandlerMiddleware';

/**
 * Setup middleware for the application, loaded in order of declaration.
 * @param app Express application
 */
export function setupMiddleware(app: express.Application) {
  new CommonMiddleware().mount(app);
  new ErrorHandlerMiddleware().mount(app);
  // Add more middleware here to mount
}
