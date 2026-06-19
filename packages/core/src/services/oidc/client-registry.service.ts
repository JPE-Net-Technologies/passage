// src/services/oidc/client-registry.service.ts
// The downstream client registry: the declarative set of clients (config/clients.yaml) that
// Passage will issue tokens to. Used to validate client_id + redirect_uri at /authorize — the
// single most important open-redirect / code-exfiltration defense (correctness gate §C).
//
// Static config for now (no dynamic registration). Logger-free and unit-testable to the repo's
// 100% line + 100% mutation gates.
import {ClientEntryType} from '../../utils/schemas/config.schemas';

class ClientRegistryService {
  private clients = new Map<string, ClientEntryType>();
  private initialized = false;

  /** Use the exported {@link clientRegistry} singleton; the class is exported for tests. */
  constructor() {}

  /** Build the registry from the validated client list. Idempotent; throws on a duplicate client_id. */
  initialize(clients: ClientEntryType[]): void {
    if (this.initialized) {
      return;
    }
    for (const client of clients) {
      if (this.clients.has(client.client_id)) {
        throw new Error(`Duplicate client_id in registry: ${client.client_id}`);
      }
      this.clients.set(client.client_id, client);
    }
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  reset(): void {
    this.clients.clear();
    this.initialized = false;
  }

  /** The registered client for an id, or undefined if it is not registered. */
  getClient(clientId: string): ClientEntryType | undefined {
    this.ensureInitialized();
    return this.clients.get(clientId);
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('ClientRegistryService not initialized. Call initialize() first.');
    }
  }
}

// Singleton instance for application use.
export const clientRegistry = new ClientRegistryService();

// Class exported for isolated tests.
export {ClientRegistryService};
