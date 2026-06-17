// Example test demonstrating the improved test utilities
import {describe, it, before, after} from "node:test";
import {
    TestEnvironment,
    TestContext,
    TestDataBuilders,
    TestHelpers,
    AsyncUtils,
    MockProviderUtils
} from './test-utils';

describe('Example: Using Test Utilities', () => {
    let testEnv: TestEnvironment;
    let context: TestContext;

    before(async () => {
        testEnv = new TestEnvironment();
        context = await testEnv.createContext("example-test");
    });

    after(async () => {
        await testEnv.cleanup();
    });

    it('demonstrates TestDataBuilders for OIDC objects', () => {
        // Build a mock auth request with PKCE
        const authRequest = TestDataBuilders.authRequest({
            code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            code_challenge_method: 'S256',
            nonce: 'random-nonce-123'
        });

        console.log('Auth request:', authRequest);

        // Build a mock token response
        const tokenResponse = TestDataBuilders.oidcTokenResponse({
            expires_in: 7200
        });

        console.log('Token response:', tokenResponse);

        // Build a mock user info
        const userInfo = TestDataBuilders.oidcUserInfo({
            email: 'custom@example.com',
            preferred_username: 'custom_user'
        });

        console.log('User info:', userInfo);
    });

    it('demonstrates MockProviderUtils for OIDC discovery', () => {
        const discovery = MockProviderUtils.createDiscoveryDocument(
            'http://localhost:8080/realms/my-realm'
        );

        console.log('Discovery document issuer:', discovery.issuer);
        console.log('Token endpoint:', discovery.token_endpoint);
    });

    it('demonstrates MockProviderUtils for JWT creation', () => {
        const jwt = MockProviderUtils.createMockJWT({
            sub: 'user-123',
            email: 'test@example.com',
            name: 'Test User'
        });

        console.log('Mock JWT:', jwt);
        // This JWT has the correct structure but is NOT cryptographically signed
        // Use it for testing JWT parsing logic, not signature verification
    });

    it('demonstrates AsyncUtils.wait', async () => {
        const start = Date.now();
        await AsyncUtils.wait(100);
        const elapsed = Date.now() - start;

        console.log(`Waited ${elapsed}ms`);
    });

    it('demonstrates AsyncUtils.retry with eventual success', async () => {
        let attempts = 0;

        const result = await AsyncUtils.retry(
            async () => {
                attempts++;
                if (attempts < 3) {
                    throw new Error('Not yet');
                }
                return 'success';
            },
            {
                maxAttempts: 5,
                initialDelay: 10,
                backoffFactor: 2
            }
        );

        console.log(`Result after ${attempts} attempts:`, result);
    });

    it('demonstrates AsyncUtils.waitFor', async () => {
        let ready = false;

        // Simulate something becoming ready after 200ms
        setTimeout(() => { ready = true; }, 200);

        await AsyncUtils.waitFor(
            () => ready,
            {
                timeout: 1000,
                interval: 50,
                timeoutMessage: 'System did not become ready'
            }
        );

        console.log('Condition met!');
    });

    it('demonstrates TestHelpers for storing test data', async () => {
        // Store data in the test context
        TestHelpers.setTestData(context, 'user_id', 'user-12345');
        TestHelpers.setToken(context, 'mock-access-token-abc');

        // Retrieve it later
        const userId = TestHelpers.getTestData<string>(context, 'user_id');
        console.log('Retrieved user ID:', userId);

        // The stored token can be used in authenticated requests
        // (This would work if the endpoint existed and accepted auth)
        // await TestHelpers.makeAuthenticatedRequest(context, 'get', '/api/profile');
    });
});
