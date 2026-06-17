// tests/kms-local.test.ts
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import yaml from 'js-yaml';
import { LocalKMS, SecretsConfigSchema } from '../services/kms-local';

// Each test gets an isolated temp dir and passes explicit paths to initialize(), so the
// KMS never touches the working directory (the injected-paths seam under test).
let TEST_DIR: string;
let TEST_KEYSTORE_FILE: string;
let TEST_SECRETS_FILE: string;
let INIT_OPTS: { keystorePath: string; secretsPath: string };

describe('LocalKMS Service', () => {
    let kms: LocalKMS;

    beforeEach(() => {
        TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'passage-kms-'));
        TEST_KEYSTORE_FILE = path.join(TEST_DIR, 'kms-local.keystore');
        TEST_SECRETS_FILE = path.join(TEST_DIR, 'template.secrets.yaml');
        INIT_OPTS = { keystorePath: TEST_KEYSTORE_FILE, secretsPath: TEST_SECRETS_FILE };

        // Create fresh KMS instance
        kms = new LocalKMS();
    });

    afterEach(() => {
        // Reset KMS and remove the temp dir
        kms.reset();
        fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });

    describe('Master Key Management', () => {
        it('should generate a new master key if keystore does not exist', async () => {
            // Ensure keystore doesn't exist
            assert.ok(!fs.existsSync(TEST_KEYSTORE_FILE), 'Keystore should not exist initially');

            // Create a minimal secrets file
            const testSecrets = {
                Secrets: []
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            // Check keystore was created
            assert.ok(fs.existsSync(TEST_KEYSTORE_FILE), 'Keystore should be created');

            // Check key length (32 bytes = 44 base64 chars with padding)
            const keyData = fs.readFileSync(TEST_KEYSTORE_FILE, 'utf8').trim();
            const key = Buffer.from(keyData, 'base64');
            assert.strictEqual(key.length, 32, 'Master key should be 32 bytes');
        });

        it('should load existing master key from keystore', async () => {
            // Create a known master key
            const knownKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, knownKey.toString('base64'), 'utf8');

            // Create a minimal secrets file
            const testSecrets = { Secrets: [] };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            // Verify KMS initialized successfully
            assert.ok(kms.isInitialized(), 'KMS should be initialized');
        });

        it('should reject invalid master key length', async () => {
            // Create an invalid key (wrong length)
            const invalidKey = crypto.randomBytes(16); // Only 16 bytes instead of 32
            fs.writeFileSync(TEST_KEYSTORE_FILE, invalidKey.toString('base64'), 'utf8');

            // Create a minimal secrets file
            const testSecrets = { Secrets: [] };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await assert.rejects(
                () => kms.initialize(INIT_OPTS),
                /Invalid master key length/,
                'Should reject invalid key length'
            );
        });
    });

    describe('Secret Encryption and Decryption', () => {
        it('should encrypt unencrypted secrets and store them in memory', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets file with unencrypted value
            const testSecrets = {
                Secrets: [
                    {
                        name: 'TestSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'test-ref',
                        unencryptedValue: 'my-secret-value'
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            // Check secret is available in memory
            assert.ok(kms.hasSecret('TestSecret'), 'Secret should exist');
            assert.strictEqual(kms.getSecret('TestSecret'), 'my-secret-value', 'Secret value should match');

            // Check YAML file was updated (unencryptedValue removed, encryptedValue added)
            const updatedContent = fs.readFileSync(TEST_SECRETS_FILE, 'utf8');
            const updatedConfig = yaml.load(updatedContent) as any;

            assert.ok(!updatedConfig.Secrets[0].unencryptedValue, 'unencryptedValue should be removed');
            assert.ok(updatedConfig.Secrets[0].encryptedValue, 'encryptedValue should be added');
        });

        it('should decrypt already-encrypted secrets', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Manually encrypt a value
            const plaintext = 'pre-encrypted-secret';
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv, { authTagLength: 16 });
            const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
            const authTag = cipher.getAuthTag();
            const encryptedValue = Buffer.concat([iv, authTag, ciphertext]).toString('base64');

            // Create secrets file with pre-encrypted value
            const testSecrets = {
                Secrets: [
                    {
                        name: 'PreEncryptedSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'test-ref',
                        encryptedValue: encryptedValue
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            // Check secret was decrypted correctly
            assert.ok(kms.hasSecret('PreEncryptedSecret'), 'Secret should exist');
            assert.strictEqual(kms.getSecret('PreEncryptedSecret'), 'pre-encrypted-secret', 'Decrypted value should match');
        });

        it('should skip secrets from non-LocalKms providers', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets file with mixed providers
            const testSecrets = {
                Secrets: [
                    {
                        name: 'LocalSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'local-ref',
                        unencryptedValue: 'local-value'
                    },
                    {
                        name: 'AWSSecret',
                        provider: 'AWS Secrets Manager',
                        reference: 'arn:aws:secretsmanager:...'
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            // Check only LocalKms secret was loaded
            assert.ok(kms.hasSecret('LocalSecret'), 'LocalKms secret should exist');
            assert.ok(!kms.hasSecret('AWSSecret'), 'AWS secret should not be loaded');
        });
    });

    describe('API Methods', () => {
        beforeEach(async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets file
            const testSecrets = {
                Secrets: [
                    {
                        name: 'Secret1',
                        provider: 'Passage.LocalKms',
                        reference: 'ref1',
                        unencryptedValue: 'value1'
                    },
                    {
                        name: 'Secret2',
                        provider: 'Passage.LocalKms',
                        reference: 'ref2',
                        unencryptedValue: 'value2'
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');
        });

        it('should throw error if getSecret called before initialize', () => {
            assert.throws(
                () => kms.getSecret('Secret1'),
                /LocalKMS not initialized/,
                'Should throw if not initialized'
            );
        });

        it('should throw error if hasSecret called before initialize', () => {
            assert.throws(
                () => kms.hasSecret('Secret1'),
                /LocalKMS not initialized/,
                'Should throw if not initialized'
            );
        });

        it('should return undefined for non-existent secret', async () => {
            await kms.initialize(INIT_OPTS);
            assert.strictEqual(kms.getSecret('NonExistent'), undefined, 'Should return undefined');
        });

        it('should return all secret names', async () => {
            await kms.initialize(INIT_OPTS);

            const names = kms.getSecretNames();
            assert.ok(names.includes('Secret1'), 'Should include Secret1');
            assert.ok(names.includes('Secret2'), 'Should include Secret2');
            assert.strictEqual(names.length, 2, 'Should have exactly 2 secrets');
        });

        it('should skip initialization if already initialized', async () => {
            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should be initialized');

            // Second initialize should be a no-op
            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should still be initialized');
        });

        it('should reset state correctly', async () => {
            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should be initialized');

            kms.reset();
            assert.ok(!kms.isInitialized(), 'Should not be initialized after reset');

            // Should throw after reset
            assert.throws(
                () => kms.getSecret('Secret1'),
                /LocalKMS not initialized/,
                'Should throw after reset'
            );
        });
    });

    describe('Schema Validation', () => {
        it('should validate valid secrets config', () => {
            const validConfig = {
                Secrets: [
                    {
                        name: 'TestSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'test-ref',
                        encryptedValue: 'base64data'
                    }
                ]
            };

            const result = SecretsConfigSchema.parse(validConfig);
            assert.ok(result.Secrets.length === 1, 'Should have one secret');
        });

        it('should provide default empty array for missing Secrets', () => {
            const emptyConfig = {};
            const result = SecretsConfigSchema.parse(emptyConfig);
            assert.ok(Array.isArray(result.Secrets), 'Secrets should be an array');
            assert.strictEqual(result.Secrets.length, 0, 'Secrets should be empty');
        });

        it('should reject invalid secret entry', () => {
            const invalidConfig = {
                Secrets: [
                    {
                        name: 'TestSecret'
                        // Missing required fields: provider, reference
                    }
                ]
            };

            assert.throws(
                () => SecretsConfigSchema.parse(invalidConfig),
                /invalid|expected string/i,
                'Should reject missing required fields'
            );
        });
    });

    describe('Edge Cases', () => {
        it('should handle missing secrets file gracefully', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Ensure secrets file doesn't exist
            if (fs.existsSync(TEST_SECRETS_FILE)) {
                fs.unlinkSync(TEST_SECRETS_FILE);
            }

            // Should initialize without error
            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should be initialized');
            assert.strictEqual(kms.getSecretNames().length, 0, 'Should have no secrets');
        });

        it('should handle empty secrets array', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create empty secrets file
            const testSecrets = { Secrets: [] };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should be initialized');
            assert.strictEqual(kms.getSecretNames().length, 0, 'Should have no secrets');
        });

        it('should handle secret with neither encrypted nor unencrypted value', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets file with incomplete secret
            const testSecrets = {
                Secrets: [
                    {
                        name: 'IncompleteSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'incomplete-ref'
                        // No unencryptedValue or encryptedValue
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            // Should initialize without error (just warn)
            await kms.initialize(INIT_OPTS);
            assert.ok(kms.isInitialized(), 'Should be initialized');
            assert.ok(!kms.hasSecret('IncompleteSecret'), 'Incomplete secret should not be loaded');
        });

        it('should handle special characters in secret values', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets with special characters
            const specialValue = 'p@$$w0rd!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~\n\t\r';
            const testSecrets = {
                Secrets: [
                    {
                        name: 'SpecialSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'special-ref',
                        unencryptedValue: specialValue
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            assert.strictEqual(kms.getSecret('SpecialSecret'), specialValue, 'Special characters should be preserved');
        });

        it('should handle unicode in secret values', async () => {
            // Create keystore
            const masterKey = crypto.randomBytes(32);
            fs.writeFileSync(TEST_KEYSTORE_FILE, masterKey.toString('base64'), 'utf8');

            // Create secrets with unicode
            const unicodeValue = '密码 пароль パスワード 🔐🔑';
            const testSecrets = {
                Secrets: [
                    {
                        name: 'UnicodeSecret',
                        provider: 'Passage.LocalKms',
                        reference: 'unicode-ref',
                        unencryptedValue: unicodeValue
                    }
                ]
            };
            fs.writeFileSync(TEST_SECRETS_FILE, yaml.dump(testSecrets), 'utf8');

            await kms.initialize(INIT_OPTS);

            assert.strictEqual(kms.getSecret('UnicodeSecret'), unicodeValue, 'Unicode should be preserved');
        });
    });
});