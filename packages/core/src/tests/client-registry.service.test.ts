// tests/client-registry.service.test.ts — the downstream client registry.
import {describe, it, expect} from 'bun:test';
import {ClientRegistryService} from '../services/oidc/client-registry.service';
import {ClientsConfig} from '../utils/schemas/config.schemas';
import type {ClientEntryType} from '../utils/schemas/config.schemas';

const client = (over: Partial<ClientEntryType> = {}): ClientEntryType => ({
  client_id: 'spa',
  client_type: 'public',
  redirect_uris: ['https://app.test/cb'],
  ...over,
} as ClientEntryType);

describe('ClientRegistryService', () => {
  it('throws on getClient before initialization', () => {
    const r = new ClientRegistryService();
    expect(r.isInitialized()).toBe(false);
    expect(() => r.getClient('spa')).toThrow('not initialized');
  });

  it('registers clients and looks them up by id', () => {
    const r = new ClientRegistryService();
    const a = client({client_id: 'a'});
    const b = client({client_id: 'b', client_type: 'confidential'});
    r.initialize([a, b]);
    expect(r.getClient('a')).toEqual(a);
    expect(r.getClient('b')).toEqual(b);
    expect(r.getClient('absent')).toBeUndefined();
  });

  it('throws on a duplicate client_id', () => {
    const r = new ClientRegistryService();
    expect(() => r.initialize([client({client_id: 'dup'}), client({client_id: 'dup'})])).toThrow('Duplicate client_id');
  });

  it('is idempotent: the first initialize wins', () => {
    const r = new ClientRegistryService();
    r.initialize([client({client_id: 'a'})]);
    r.initialize([client({client_id: 'b'})]); // ignored
    expect(r.isInitialized()).toBe(true);
    expect(r.getClient('a')).toBeDefined();
    expect(r.getClient('b')).toBeUndefined();
  });

  it('reset clears the registry and uninitializes', () => {
    const r = new ClientRegistryService();
    r.initialize([client({client_id: 'a'})]);
    r.reset();
    expect(r.isInitialized()).toBe(false);
    r.initialize([client({client_id: 'b'})]);
    expect(r.getClient('a')).toBeUndefined(); // the prior client was cleared
    expect(r.getClient('b')).toBeDefined();
  });

  it('ClientsConfig accepts a valid client and rejects empty redirect_uris', () => {
    expect(() => ClientsConfig.parse({clients: [client()]})).not.toThrow();
    expect(() => ClientsConfig.parse({clients: [{client_id: 'x', client_type: 'public', redirect_uris: []}]})).toThrow();
  });
});
