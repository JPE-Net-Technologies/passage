// tests/wiring.test.ts — app wiring: root route, health probes, error handler, compression.
import {describe, it, expect, afterEach, beforeEach, spyOn} from 'bun:test';
import request from 'supertest';
import {createApp} from '../app';
import {buildTestConfig} from './test-utils';
import {errorHandler} from '../middleware/errorHandlerMiddleware';
import {shouldCompress} from '../middleware/commonMiddleware';
import {snapshot} from '../routes/health.routes';

async function testApp() {
  return createApp(buildTestConfig());
}

describe('App wiring', () => {
  it('GET / returns service metadata', async () => {
    const res = await request(await testApp()).get('/').expect(200);
    expect(res.body.message).toBe('Passage');
    expect(res.body.status).toBe('running');
  });
});

describe('Health probes', () => {
  it('GET /health returns a snapshot', async () => {
    const res = await request(await testApp()).get('/health').expect(200);
    expect(res.body.status).toBe('healthy');
    expect(typeof res.body.uptime).toBe('number');
    expect(typeof res.body.memory.usedMB).toBe('number');
  });

  it('GET /health/live, /ready, /startup respond 200', async () => {
    const app = await testApp();
    expect((await request(app).get('/health/live').expect(200)).body.status).toBe('alive');
    expect((await request(app).get('/health/ready').expect(200)).body.status).toBe('ready');
    expect((await request(app).get('/health/startup').expect(200)).body.status).toBe('started');
  });

  it('snapshot() reports healthy with memory figures', () => {
    const s = snapshot();
    expect(s.status).toBe('healthy');
    expect(s.memory.totalMB).toBeGreaterThanOrEqual(0);
  });
});

function mockRes() {
  const r: any = {};
  r.status = (code: number) => { r.statusCode = code; return r; };
  r.json = (body: unknown) => { r.body = body; return r; };
  return r;
}

describe('errorHandler', () => {
  const noop = (() => undefined) as any;
  const originalEnv = process.env.NODE_ENV;
  let errSpy: ReturnType<typeof spyOn>;
  beforeEach(() => { errSpy = spyOn(console, 'error').mockImplementation(() => undefined); });
  afterEach(() => { process.env.NODE_ENV = originalEnv; errSpy.mockRestore(); });

  it('maps ValidationError to 400', () => {
    const res = mockRes();
    const err = new Error('bad'); err.name = 'ValidationError';
    errorHandler(err, {} as any, res, noop);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  it('maps CastError to 400', () => {
    const res = mockRes();
    const err = new Error('bad id'); err.name = 'CastError';
    errorHandler(err, {} as any, res, noop);
    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toBe('Invalid ID format');
  });

  it('maps UnauthorizedError to 401', () => {
    const res = mockRes();
    const err = new Error('nope'); err.name = 'UnauthorizedError';
    errorHandler(err, {} as any, res, noop);
    expect(res.statusCode).toBe(401);
  });

  it('uses err.message for generic errors (500)', () => {
    const res = mockRes();
    errorHandler(new Error('boom'), {} as any, res, noop);
    expect(res.statusCode).toBe(500);
    expect(res.body.error.message).toBe('boom');
  });

  it('falls back to default message when err.message is empty', () => {
    const res = mockRes();
    const err = new Error(''); err.message = '';
    errorHandler(err, {} as any, res, noop);
    expect(res.body.error.message).toBe('Internal Server Error');
    expect(res.body.error.stack).toBeUndefined();
  });

  it('includes the stack in development', () => {
    process.env.NODE_ENV = 'development';
    const res = mockRes();
    errorHandler(new Error('dev boom'), {} as any, res, noop);
    expect(res.body.error.stack).toBeDefined();
  });
});

describe('shouldCompress', () => {
  it('returns false when x-no-compression is set', () => {
    expect(shouldCompress({headers: {'x-no-compression': '1'}} as any, {} as any)).toBe(false);
  });

  it('defers to compression default otherwise', () => {
    const res: any = {getHeader: () => undefined};
    expect(typeof shouldCompress({headers: {}} as any, res)).toBe('boolean');
  });
});
