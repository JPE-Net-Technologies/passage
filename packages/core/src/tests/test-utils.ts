// tests/test-utils.ts
import {createApp, type AppConfig} from '../app';
import {SecurityConfigSchema} from '../utils/schemas/config.schemas';
import type {Express} from 'express';
import request, {Test} from 'supertest';

export interface TestContext {
    app: Express;
    request: typeof request;
    testData: Map<string, any>;
}

/**
 * Build a minimal, valid {@link AppConfig} for tests. Security settings fall back to
 * schema defaults; providers default to none (no upstream federation / network calls).
 * Pass overrides to exercise provider-specific routes.
 */
export function buildTestConfig(overrides: Partial<AppConfig> = {}): AppConfig {
    return {
        security: SecurityConfigSchema.parse({cors: {}, rateLimit: {}, headers: {hsts: {}}}),
        providers: {providers: []},
        clients: {clients: []},
        ...overrides,
    };
}

export class TestEnvironment {
    private contexts: Map<string, TestContext> = new Map();

    /**
     * Creates and initializes a new test context with the specified name.
     *
     * @param name The name of the context to create. Defaults to 'default'.
     * @param config Optional AppConfig override (defaults to {@link buildTestConfig}).
     * @return A promise that resolves to the created TestContext object.
     */
    async createContext(name: string = 'default', config: AppConfig = buildTestConfig()): Promise<TestContext> {
        const app = await createApp(config);

        const context: TestContext = {
            app,
            request,
            testData: new Map()
        };

        this.contexts.set(name, context);
        return context;
    }

    /**
     * Fetches a saved context by-key.
     * @param name Context name key.
     */
    getContext(name: string = 'default'): TestContext | undefined {
        return this.contexts.get(name);
    }

    async cleanup(name?: string): Promise<void> {
        if (name) {
            const context = this.contexts.get(name);
            if (context) {
                context.testData.clear();
                this.contexts.delete(name);
            }
        } else {
            // Clean all contexts
            for (const context of this.contexts.values()) {
                context.testData.clear();
            }
            this.contexts.clear();
        }
    }
}

// Utility function to generate random IDs
const randomId = (prefix: string = ''): string => {
    const random = Math.random().toString(36).substring(2, 11);
    return prefix ? `${prefix}-${random}` : random;
};

// Test data builders for maintainable test data
export const TestDataBuilders = {
    user: (overrides: Partial<{
        id: string;
        email: string;
        name: string;
        createdAt: Date;
    }> = {}) => ({
        id: randomId('test-user'),
        email: 'test@example.com',
        name: 'Test User',
        createdAt: new Date(),
        ...overrides
    }),

    authRequest: (overrides: Partial<{
        client_id: string;
        response_type: string;
        redirect_uri: string;
        scope: string;
        state: string;
        nonce?: string;
        code_challenge?: string;
        code_challenge_method?: string;
    }> = {}) => ({
        client_id: 'test-client',
        response_type: 'code',
        redirect_uri: 'http://localhost:3000/callback',
        scope: 'openid profile email',
        state: randomId('test-state'),
        ...overrides
    }),

    oidcProvider: (overrides: Partial<{
        name: string;
        type: string;
        config: {
            provider_url: string;
            client_id: string;
            client_secret: string;
            redirect_uri: string;
        };
    }> = {}) => ({
        name: randomId('test-provider'),
        type: 'oidc',
        config: {
            provider_url: 'http://localhost:8080/realms/test',
            client_id: 'test-client',
            client_secret: 'test-secret',
            redirect_uri: 'http://localhost:3001/callback',
            ...overrides.config
        },
        ...overrides
    }),

    oidcTokenResponse: (overrides: Partial<{
        access_token: string;
        token_type: string;
        expires_in: number;
        refresh_token?: string;
        id_token?: string;
        scope?: string;
    }> = {}) => ({
        access_token: randomId('access-token'),
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: randomId('refresh-token'),
        id_token: randomId('id-token'),
        scope: 'openid profile email',
        ...overrides
    }),

    oidcUserInfo: (overrides: Partial<{
        sub: string;
        name: string;
        email: string;
        email_verified: boolean;
        preferred_username?: string;
    }> = {}) => ({
        sub: randomId('user'),
        name: 'Test User',
        email: 'test@example.com',
        email_verified: true,
        ...overrides
    })
};

// Helper functions for common test operations
export const TestHelpers = {
    /**
     * Makes an authenticated request with a bearer token
     */
    async makeAuthenticatedRequest(
        context: TestContext,
        method: 'get' | 'post' | 'put' | 'delete' | 'patch',
        url: string,
        token?: string,
        data?: any
    ): Promise<Test> {
        const authToken = token || context.testData.get('access_token') as string;
        if (!authToken) {
            throw new Error('No access token available. Provide token or set it in context.testData');
        }

        let req = context.request(context.app)[method](url);
        req = req.set('Authorization', `Bearer ${authToken}`);

        if (data && ['post', 'put', 'patch'].includes(method)) {
            req = req.send(data);
        }

        return req;
    },

    /**
     * Stores a token in the test context for reuse
     */
    setToken(context: TestContext, token: string): void {
        context.testData.set('access_token', token);
    },

    /**
     * Stores arbitrary test data for reuse across test steps
     */
    setTestData(context: TestContext, key: string, value: any): void {
        context.testData.set(key, value);
    },

    /**
     * Retrieves test data by key
     */
    getTestData<T = any>(context: TestContext, key: string): T | undefined {
        return context.testData.get(key) as T;
    }
};

// Async utilities for integration testing
export const AsyncUtils = {
    /**
     * Wait for a specified number of milliseconds
     */
    wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    /**
     * Retry an async operation with exponential backoff
     */
    async retry<T>(
        operation: () => Promise<T>,
        options: {
            maxAttempts?: number;
            initialDelay?: number;
            maxDelay?: number;
            backoffFactor?: number;
        } = {}
    ): Promise<T> {
        const {
            maxAttempts = 3,
            initialDelay = 100,
            maxDelay = 5000,
            backoffFactor = 2
        } = options;

        let lastError: Error | undefined;
        let delay = initialDelay;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error as Error;

                if (attempt === maxAttempts) {
                    break;
                }

                await this.wait(delay);
                delay = Math.min(delay * backoffFactor, maxDelay);
            }
        }

        throw new Error(
            `Operation failed after ${maxAttempts} attempts. Last error: ${lastError?.message}`
        );
    },

    /**
     * Poll a condition until it becomes true or timeout
     */
    async waitFor(
        condition: () => boolean | Promise<boolean>,
        options: {
            timeout?: number;
            interval?: number;
            timeoutMessage?: string;
        } = {}
    ): Promise<void> {
        const {
            timeout = 5000,
            interval = 100,
            timeoutMessage = 'Condition was not met within timeout'
        } = options;

        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            const result = await condition();
            if (result) {
                return;
            }
            await this.wait(interval);
        }

        throw new Error(timeoutMessage);
    }
};

// Mock utilities for simulating upstream provider responses
export const MockProviderUtils = {
    /**
     * Creates a mock OIDC discovery document
     */
    createDiscoveryDocument(issuer: string = 'http://localhost:8080/realms/test') {
        return {
            issuer,
            authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
            token_endpoint: `${issuer}/protocol/openid-connect/token`,
            userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
            jwks_uri: `${issuer}/protocol/openid-connect/certs`,
            end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
            response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token'],
            subject_types_supported: ['public', 'pairwise'],
            id_token_signing_alg_values_supported: ['RS256', 'ES256', 'HS256'],
            scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt'],
            claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email', 'email_verified', 'preferred_username']
        };
    },

    /**
     * Creates a mock JWT header (not signed, for testing structure only)
     */
    createMockJWT(payload: Record<string, any>, header: Record<string, any> = {}) {
        const defaultHeader = {
            alg: 'RS256',
            typ: 'JWT',
            kid: randomId('key'),
            ...header
        };

        const defaultPayload = {
            iss: 'http://localhost:8080/realms/test',
            aud: 'test-client',
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            ...payload
        };

        // Base64url encode (not actual signing, just for structure)
        const encodeBase64Url = (obj: any) =>
            Buffer.from(JSON.stringify(obj))
                .toString('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');

        const headerEncoded = encodeBase64Url(defaultHeader);
        const payloadEncoded = encodeBase64Url(defaultPayload);
        const signature = randomId('signature');

        return `${headerEncoded}.${payloadEncoded}.${signature}`;
    }
};
