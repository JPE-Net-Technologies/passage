import express, { Request, Response, NextFunction } from 'express';
import MiddlewareComponent from "./middlewareComponent";

export default class ErrorHandlerMiddleware extends MiddlewareComponent {
    constructor() { super(); }

    mount(app: express.Application): boolean {
        app.use(errorHandler);
        return true;
    }
}

export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  // Log the error for debugging
  console.error('Error:', err.message);
  console.error('Stack:', err.stack);

  // Default error response
  let statusCode = 500;
  let message = 'Internal Server Error';

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    message = 'Unauthorized';
  } else if (err.message) {
    message = err.message;
  }

  // Send error response
  res.status(statusCode).json({
    error: {
      message,
      status: statusCode,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
}
