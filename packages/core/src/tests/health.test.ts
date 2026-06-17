// tests/health.test.ts
import {describe, it, beforeEach, afterEach, before, after} from "node:test";
import {TestContext, TestEnvironment} from './test-utils';

describe('Health Routes', () => {
  let testEnv: TestEnvironment;
  let context: TestContext;

  before(async () => {
      testEnv = new TestEnvironment();
      context = await testEnv.createContext("health-test");
  });

  after(async () => {
    await testEnv.cleanup();
  });

  it('Should return healthy status', async () => {
    await context.request(context.app)
      .get('/health')
      .expect(200);
  });
});
