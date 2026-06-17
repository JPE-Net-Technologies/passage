// services/kms-local.ts
// Local KMS service for development/small deployments
// Uses AES-256-GCM for encryption with a master key stored in a local keystore file

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import yaml from 'js-yaml';
import { z } from 'zod';
import { logger } from '../utils/logger';

// Default file locations, resolved against the consumer's cwd. These are only a
// fallback: callers (presets, embedders, tests) should pass explicit paths to
// `initialize()` so the KMS never assumes the working-directory layout.
const defaultKeystorePath = (): string => path.join(process.cwd(), 'kms-local.keystore');
const defaultSecretsPath = (): string => path.join(process.cwd(), 'config',
    process.env.NODE_ENV === 'production' ? 'production.secrets.yaml' : 'template.secrets.yaml');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits

// Schema for secrets.yaml
const SecretEntrySchema = z.object({
    name: z.string(),
    provider: z.string(),
    reference: z.string(),
    // Either unencryptedValue (plaintext to be encrypted) or encryptedValue (already encrypted)
    unencryptedValue: z.string().optional(),
    encryptedValue: z.string().optional(),
});

const SecretsConfigSchema = z.object({
    Secrets: z.array(SecretEntrySchema).default([]),
});

type SecretEntry = z.infer<typeof SecretEntrySchema>;
type SecretsConfig = z.infer<typeof SecretsConfigSchema>;

// Encrypted value format: base64(iv:authTag:ciphertext)
interface EncryptedData {
    iv: Buffer;
    authTag: Buffer;
    ciphertext: Buffer;
}

/** Options for {@link LocalKMS.initialize}. Paths default to the cwd-based fallbacks. */
export interface KmsInitOptions {
    /** Path to the master-key keystore file. */
    keystorePath?: string;
    /** Path to the secrets YAML file to load/encrypt. */
    secretsPath?: string;
}

class LocalKMS {
    private masterKey: Buffer | null = null;
    private secrets: Map<string, string> = new Map();
    private initialized: boolean = false;
    private keystorePath: string = defaultKeystorePath();
    private secretsPath: string = defaultSecretsPath();

    /** Use the exported {@link localKMS} singleton; the class is exported for tests. */
    constructor() {}

    /**
     * Initialize the KMS service - must be called before using getSecret().
     * @param opts Explicit keystore/secrets paths; omit to use the cwd-based fallbacks.
     */
    async initialize(opts: KmsInitOptions = {}): Promise<void> {
        if (this.initialized) {
            logger.debug('LocalKMS already initialized');
            return;
        }

        this.keystorePath = opts.keystorePath ?? defaultKeystorePath();
        this.secretsPath = opts.secretsPath ?? defaultSecretsPath();

        logger.info('Initializing LocalKMS service');

        // Load or generate master key
        this.masterKey = await this.loadOrGenerateMasterKey();

        // Load secrets file, encrypt any plaintext values, and decrypt into memory
        await this.loadAndProcessSecrets();

        this.initialized = true;
        logger.info('LocalKMS initialization complete', { secretCount: this.secrets.size });
    }

    /**
     * Get a decrypted secret by name
     */
    getSecret(name: string): string | undefined {
        if (!this.initialized) {
            throw new Error('LocalKMS not initialized. Call initialize() first.');
        }
        return this.secrets.get(name);
    }

    /**
     * Check if a secret exists
     */
    hasSecret(name: string): boolean {
        if (!this.initialized) {
            throw new Error('LocalKMS not initialized. Call initialize() first.');
        }
        return this.secrets.has(name);
    }

    /**
     * Get all secret names (not values)
     */
    getSecretNames(): string[] {
        if (!this.initialized) {
            throw new Error('LocalKMS not initialized. Call initialize() first.');
        }
        return Array.from(this.secrets.keys());
    }

    /**
     * Load master key from keystore file, or generate a new one if it doesn't exist
     */
    private async loadOrGenerateMasterKey(): Promise<Buffer> {
        if (fs.existsSync(this.keystorePath)) {
            logger.debug('Loading master key from keystore', { path: this.keystorePath });
            const keyData = fs.readFileSync(this.keystorePath, 'utf8').trim();
            const key = Buffer.from(keyData, 'base64');

            if (key.length !== KEY_LENGTH) {
                throw new Error(`Invalid master key length: expected ${KEY_LENGTH} bytes, got ${key.length}`);
            }

            return key;
        }

        // Generate new master key
        logger.warn('No keystore found, generating new master key', { path: this.keystorePath });
        const newKey = crypto.randomBytes(KEY_LENGTH);

        // Save to keystore file with restricted permissions
        fs.writeFileSync(this.keystorePath, newKey.toString('base64'), { mode: 0o600 });
        logger.info('Master key generated and saved to keystore');

        return newKey;
    }

    /**
     * Load secrets from YAML file, encrypt any plaintext values, and store decrypted values in memory
     */
    private async loadAndProcessSecrets(): Promise<void> {
        if (!fs.existsSync(this.secretsPath)) {
            logger.warn('Secrets file not found', { path: this.secretsPath });
            return;
        }

        logger.debug('Loading secrets file', { path: this.secretsPath });
        const fileContent = fs.readFileSync(this.secretsPath, 'utf8');
        const rawConfig = yaml.load(fileContent);

        const config = SecretsConfigSchema.parse(rawConfig);
        let hasUnencryptedValues = false;

        for (const secret of config.Secrets) {
            // Only process secrets that use Passage.LocalKms provider
            if (secret.provider !== 'Passage.LocalKms') {
                logger.debug('Skipping non-LocalKms secret', { name: secret.name, provider: secret.provider });
                continue;
            }

            if (secret.unencryptedValue) {
                // Encrypt the plaintext value
                logger.debug('Encrypting plaintext secret', { name: secret.name });
                const encrypted = this.encrypt(secret.unencryptedValue);
                secret.encryptedValue = this.serializeEncryptedData(encrypted);

                // Store decrypted value in memory
                this.secrets.set(secret.name, secret.unencryptedValue);

                // Remove unencrypted value from the object
                delete secret.unencryptedValue;
                hasUnencryptedValues = true;
            } else if (secret.encryptedValue) {
                // Decrypt the value and store in memory
                logger.debug('Decrypting secret', { name: secret.name });
                const encrypted = this.deserializeEncryptedData(secret.encryptedValue);
                const decrypted = this.decrypt(encrypted);
                this.secrets.set(secret.name, decrypted);
            } else {
                logger.warn('Secret has neither encrypted nor unencrypted value', { name: secret.name });
            }
        }

        // Save the YAML file if we encrypted any values
        if (hasUnencryptedValues) {
            logger.info('Saving secrets file with encrypted values');
            const updatedYaml = yaml.dump(config, {
                indent: 2,
                lineWidth: -1, // Don't wrap lines
                quotingType: '"',
                forceQuotes: true,
            });
            fs.writeFileSync(this.secretsPath, updatedYaml, 'utf8');
            logger.info('Secrets file updated with encrypted values');
        }
    }

    /**
     * Encrypt a plaintext string using AES-256-GCM
     */
    private encrypt(plaintext: string): EncryptedData {
        if (!this.masterKey) {
            throw new Error('Master key not loaded');
        }

        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv, {
            authTagLength: AUTH_TAG_LENGTH,
        });

        const ciphertext = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final(),
        ]);
        const authTag = cipher.getAuthTag();

        return { iv, authTag, ciphertext };
    }

    /**
     * Decrypt an encrypted value using AES-256-GCM
     */
    private decrypt(data: EncryptedData): string {
        if (!this.masterKey) {
            throw new Error('Master key not loaded');
        }

        const decipher = crypto.createDecipheriv(ALGORITHM, this.masterKey, data.iv, {
            authTagLength: AUTH_TAG_LENGTH,
        });
        decipher.setAuthTag(data.authTag);

        const plaintext = Buffer.concat([
            decipher.update(data.ciphertext),
            decipher.final(),
        ]);

        return plaintext.toString('utf8');
    }

    /**
     * Serialize encrypted data to a base64 string format: base64(iv:authTag:ciphertext)
     */
    private serializeEncryptedData(data: EncryptedData): string {
        const combined = Buffer.concat([data.iv, data.authTag, data.ciphertext]);
        return combined.toString('base64');
    }

    /**
     * Deserialize a base64 string back to encrypted data components
     */
    private deserializeEncryptedData(serialized: string): EncryptedData {
        const combined = Buffer.from(serialized, 'base64');

        if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH) {
            throw new Error('Invalid encrypted data: too short');
        }

        const iv = combined.subarray(0, IV_LENGTH);
        const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
        const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

        return { iv, authTag, ciphertext };
    }

    /**
     * Check if the service is initialized
     */
    isInitialized(): boolean {
        return this.initialized;
    }

    /**
     * Reset the service (mainly for testing)
     */
    reset(): void {
        this.masterKey = null;
        this.secrets.clear();
        this.initialized = false;
    }
}

/**
 * Singleton instance of LocalKMS.
 * Initialized on server startup.
 */
export const localKMS = new LocalKMS();

// Export class for testing
export { LocalKMS };

// Export schema for external use
export { SecretsConfigSchema, SecretEntrySchema };
export type { SecretEntry, SecretsConfig };
