import { Router, Request, Response } from 'express';

/**
 * Health / probe endpoints. Kept deliberately lean and dependency-free: every branch is
 * deterministic and unit-testable. As real subsystems (datastore, upstream providers, key
 * material) are added, extend {@link snapshot} and the readiness logic with honest checks
 * rather than the simulated placeholders this boilerplate previously shipped.
 */
const router = Router();

export interface HealthSnapshot {
  status: 'healthy';
  timestamp: string;
  uptime: number;
  memory: {
    usedMB: number;
    totalMB: number;
  };
}

/** Build a point-in-time health snapshot from the current process. */
export function snapshot(): HealthSnapshot {
  const mem = process.memoryUsage();
  return {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      usedMB: Math.round(mem.heapUsed / 1024 / 1024),
      totalMB: Math.round(mem.heapTotal / 1024 / 1024),
    },
  };
}

// GET /health — basic health snapshot.
router.get('/', (_req: Request, res: Response) => {
  res.status(200).json(snapshot());
});

// GET /health/live — Kubernetes liveness probe (if we can respond, we're alive).
router.get('/live', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// GET /health/ready — Kubernetes readiness probe.
router.get('/ready', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ready', timestamp: new Date().toISOString() });
});

// GET /health/startup — Kubernetes startup probe.
router.get('/startup', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'started', timestamp: new Date().toISOString() });
});

export default router;
