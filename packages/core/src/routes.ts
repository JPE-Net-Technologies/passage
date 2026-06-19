import { Application } from 'express';
import type {AppConfig} from './app';
import healthRoutes from './routes/health.routes';
import {setupOidcRoutes} from "./routes/auth.routes";

export async function setupRoutes(app: Application, config: AppConfig) {
  // Health check (no auth required)
  app.use('/health', healthRoutes);

  // OAuth2/OIDC endpoints
  await setupOidcRoutes(app, config.providers, config.clients)

  app.get('/', (req, res) => {
    res.json({
      message: 'Passage',
      version: '1.0.0',
      status: 'running',
      timestamp: new Date().toISOString()
    });
  });
}
