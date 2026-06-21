// tests/common-middleware.route.test.ts — config-driven CORS + rate limiting (CommonMiddleware).
//
// Exercises the security config wired into middleware end-to-end: the per-IP rate limiter (from
// security.rateLimit) and CORS origin/credentials reflection (from security.cors). No providers are
// configured, so the app needs no KMS/upstream — GET / is the probe route.
import {describe, it, expect, beforeAll} from 'bun:test';
import request from 'supertest';
import {createApp} from '../app';
import {buildTestConfig} from './test-utils';
import {SecurityConfigSchema} from '../utils/schemas/config.schemas';

describe('CommonMiddleware — rate limiting', () => {
  let app: any;

  beforeAll(async () => {
    app = await createApp(buildTestConfig({
      security: SecurityConfigSchema.parse({cors: {}, rateLimit: {max: 2}, headers: {hsts: {}}}),
    }));
  });

  it('emits standard RateLimit headers and 429s once the per-IP limit is exceeded', async () => {
    const first = await request(app).get('/').expect(200);
    // standardHeaders: a RateLimit-* header is present regardless of draft version.
    expect(Object.keys(first.headers).some(h => h.startsWith('ratelimit'))).toBe(true);

    await request(app).get('/').expect(200);          // 2nd — still under limit
    await request(app).get('/').expect(429);          // 3rd — over the limit of 2
  });
});

describe('CommonMiddleware — CORS from config', () => {
  let app: any;

  beforeAll(async () => {
    // Default cors config: origins ['http://localhost:3000'], credentials true.
    app = await createApp(buildTestConfig());
  });

  it('reflects an allowed origin and allows credentials', async () => {
    const res = await request(app).get('/').set('Origin', 'http://localhost:3000').expect(200);
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('does not reflect a disallowed origin', async () => {
    const res = await request(app).get('/').set('Origin', 'http://evil.test').expect(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});
