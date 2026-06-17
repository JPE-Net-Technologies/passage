interface LogLevel {
  ERROR: 0;
  WARN: 1;
  INFO: 2;
  DEBUG: 3;
}

const LOG_LEVELS: LogLevel = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
} as const;

export class Logger {
  private currentLevel: number;

  constructor() {
    const envLevel = process.env.LOG_LEVEL?.toLowerCase() || 'info';
    this.currentLevel = this.getLevelNumber(envLevel);
  }

  private getLevelNumber(level: string): number {
    switch (level) {
      case 'error': return LOG_LEVELS.ERROR;
      case 'warn': return LOG_LEVELS.WARN;
      case 'info': return LOG_LEVELS.INFO;
      case 'debug': return LOG_LEVELS.DEBUG;
      default: return LOG_LEVELS.INFO;
    }
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const baseLog = {
      timestamp,
      level: level.toUpperCase(),
      message,
      ...(meta && Object.keys(meta).length > 0 ? { meta } : {})
    };

    return JSON.stringify(baseLog);
  }

  private log(level: number, levelName: string, message: string, meta?: any): void {
    if (level <= this.currentLevel) {
      const formatted = this.formatMessage(levelName, message, meta);

      // In test environment, suppress logs unless explicitly requested
      if (process.env.NODE_ENV === 'test' && !process.env.ENABLE_TEST_LOGS) {
        return;
      }

      if (level === LOG_LEVELS.ERROR) {
        console.error(formatted);
      } else if (level === LOG_LEVELS.WARN) {
        console.warn(formatted);
      } else {
        console.log(formatted);
      }
    }
  }

  error(message: string, meta?: any): void {
    this.log(LOG_LEVELS.ERROR, 'error', message, meta);
  }

  warn(message: string, meta?: any): void {
    this.log(LOG_LEVELS.WARN, 'warn', message, meta);
  }

  info(message: string, meta?: any): void {
    this.log(LOG_LEVELS.INFO, 'info', message, meta);
  }

  debug(message: string, meta?: any): void {
      // TODO Implement a debug log inhibitor to prevent debug logs in production
    this.log(LOG_LEVELS.DEBUG, 'debug', message, meta);
  }
}

export const logger = new Logger();
