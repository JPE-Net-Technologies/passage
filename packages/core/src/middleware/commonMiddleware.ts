/**
 * @file src/middleware/commonMiddleware.ts
 * @description Common middleware functions for the application (e.g CORS, helmet, etc.)
 */
import MiddlewareComponent from "./middlewareComponent";
import express from "express";
import {logger} from "../utils/logger";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import {rateLimit} from "express-rate-limit";
import {SecurityConfigType} from "../utils/schemas/config.schemas";

/**
 * Compression predicate: honour the `x-no-compression` opt-out header, otherwise defer to
 * compression's default heuristic. Extracted so it is directly unit-testable.
 */
export function shouldCompress(req: express.Request, res: express.Response): boolean {
  if (req.headers['x-no-compression']) {
    return false;
  }
  return compression.filter(req, res);
}

export default class CommonMiddleware extends MiddlewareComponent {
    constructor(private readonly security: SecurityConfigType) { super(); }

    mount(app: express.Application): boolean {
      // Rate limiting — per-IP, from config. Mounted first so it guards every downstream route
      // (notably the brute-forceable /token, /authorize, /callback, /revoke). `validate:false`
      // silences express-rate-limit's dev trust-proxy check; trust proxy is set in createApp.
      app.use(rateLimit({
        windowMs: this.security.rateLimit.windowMs,
        limit: this.security.rateLimit.max,
        standardHeaders: this.security.rateLimit.standardHeaders,
        legacyHeaders: this.security.rateLimit.legacyHeaders,
        validate: false,
      }));

      // CORS — origins/credentials from config (no longer hardcoded).
      app.use(cors({
        origin: this.security.cors.origins,
        credentials: this.security.cors.credentials,
        methods: ['GET', 'POST', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
      }));

      // Compression
      app.use(compression({
        filter: shouldCompress,
        threshold: 1024
      }));

      // Security headers
      app.use(helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
          },
        },
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true
        }
      }));

      app.use(express.text({limit: '10mb'}));
      app.use(express.json({ limit: '10mb' }));
      app.use(express.urlencoded({ extended: true, limit: '10mb' }));
      // ---
      logger.info(`CommonMiddleware mounted at ${new Date().toISOString()}`);
      return true;
    }
}
