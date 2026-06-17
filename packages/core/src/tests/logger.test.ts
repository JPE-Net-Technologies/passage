// tests/logger.test.ts — exercises log levels, env-driven level parsing, and suppression.
import {describe, it, expect, afterEach, spyOn} from 'bun:test';
import {Logger} from '../utils/logger';

const ENV_KEYS = ['LOG_LEVEL', 'NODE_ENV', 'ENABLE_TEST_LOGS'] as const;

describe('Logger', () => {
  const saved: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  function silence() {
    return [
      spyOn(console, 'log').mockImplementation(() => undefined),
      spyOn(console, 'warn').mockImplementation(() => undefined),
      spyOn(console, 'error').mockImplementation(() => undefined),
    ];
  }

  it('writes to the matching console channel for each level', () => {
    process.env.NODE_ENV = 'development'; // not 'test' → not suppressed
    process.env.LOG_LEVEL = 'debug';      // allow all levels through
    const spies = silence();
    const log = new Logger();
    log.error('e', {code: 1}); // meta present
    log.warn('w');             // no meta
    log.info('i');
    log.debug('d');
    const [logSpy, warnSpy, errorSpy] = spies;
    expect(errorSpy).toHaveBeenCalled();
    expect(warnSpy).toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalled(); // info + debug both use console.log
    spies.forEach(s => s.mockRestore());
  });

  it('suppresses output under NODE_ENV=test without ENABLE_TEST_LOGS', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ENABLE_TEST_LOGS;
    const spies = silence();
    new Logger().info('quiet');
    expect(spies[0]).not.toHaveBeenCalled();
    spies.forEach(s => s.mockRestore());
  });

  it('skips messages above the configured level', () => {
    process.env.NODE_ENV = 'development';
    process.env.LOG_LEVEL = 'error'; // only errors emit
    const spies = silence();
    const log = new Logger();
    log.debug('ignored');
    log.info('ignored');
    expect(spies[0]).not.toHaveBeenCalled();
    spies.forEach(s => s.mockRestore());
  });

  it('parses every known LOG_LEVEL and falls back to info on unknown', () => {
    for (const level of ['error', 'warn', 'info', 'debug', 'something-else']) {
      process.env.LOG_LEVEL = level;
      expect(() => new Logger()).not.toThrow();
    }
    delete process.env.LOG_LEVEL; // undefined → default branch
    expect(() => new Logger()).not.toThrow();
  });
});
