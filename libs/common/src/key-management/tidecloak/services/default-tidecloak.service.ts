import { LogService } from "../../../platform/abstractions/log.service";
import { TideCloakConfig, TideCloakService } from "../abstractions/tidecloak.service";

const STORAGE_KEY_CONFIG = "tidecloak_config";
const STORAGE_KEY_DOKEN = "tidecloak_doken";

export class DefaultTideCloakService extends TideCloakService {
   
  private enclave: any | null = null; // RequestEnclave
  private config: TideCloakConfig | null = null;
  private initializingPromise: Promise<void> | null = null;
  private _skipOrkDecrypt = false;

  constructor(private logService: LogService) {
    super();
  }

  async initialize(config: TideCloakConfig, doken: string): Promise<void> {
    this.config = config;

    const { RequestEnclave } = await import("@tidecloak/js");

    this.enclave = new RequestEnclave({
      homeOrkOrigin: config.homeOrkUrl,
      vendorId: config.vendorId,
      voucherURL: config.voucherUrl,
      signed_client_origin: config.signedClientOrigin,
    });

    this.enclave.init({
      doken,
      dokenRefreshCallback: async () => {
        const stored = await this.loadDoken();
        return stored ?? doken;
      },
      requireReloginCallback: async () => "",
      backgroundUrl: "",
      logoUrl: "",
    });

    await this.enclave.initDone;
    await this.persistConfig(config);
    await this.persistDoken(doken);

    this.logService.info("[TideCloak] RequestEnclave initialized");
  }

  async encrypt(data: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this.enclave) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    const results = await this.enclave.encrypt([{ data, tags }]);
    return results[0];
  }

  async decrypt(encrypted: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this.enclave) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    const results = await this.enclave.decrypt([{ encrypted, tags }]);
    return results[0];
  }

  async updateDoken(doken: string): Promise<void> {
    if (this.enclave) {
      this.enclave.updateDoken(doken);
    }
    await this.persistDoken(doken);
  }

  isInitialized(): boolean {
    return this.enclave != null;
  }

  async ensureInitialized(): Promise<boolean> {
    if (this.enclave != null) {
      return true;
    }

    // Avoid concurrent re-initialization attempts
    if (this.initializingPromise != null) {
      await this.initializingPromise;
      return this.enclave != null;
    }

    // Can't create RequestEnclave without DOM (service worker, CLI)
    if (typeof document === "undefined") {
      return false;
    }

    const config = await this.loadConfig();
    const doken = await this.loadDoken();
    if (!config || !doken) {
      return false;
    }

    this.logService.info("[TideCloak] Re-initializing RequestEnclave from persisted state");

    this.initializingPromise = (async () => {
      await this.initialize(config, doken);
    })()
      .catch((e) => {
        this.logService.error(`[TideCloak] Failed to re-init enclave: ${e}`);
      })
      .finally(() => {
        this.initializingPromise = null;
      });

    await this.initializingPromise;
    return this.enclave != null;
  }

  async hasPersistedConfig(): Promise<boolean> {
    const config = await this.loadConfig();
    return config != null;
  }

  setSkipOrkDecrypt(skip: boolean): void {
    this._skipOrkDecrypt = skip;
  }

  shouldSkipOrkDecrypt(): boolean {
    return this._skipOrkDecrypt;
  }

  destroy(): void {
    if (this.enclave) {
      try {
        this.enclave.close();
      } catch {
        // Enclave may already be closed
      }
    }
    this.enclave = null;
    this.config = null;
    this.clearStorage();
  }

  // --- Storage helpers ---

  private isBrowserExtension(): boolean {
    try {
       
      const g = globalThis as any;
      return g.chrome?.storage?.session != null;
    } catch {
      return false;
    }
  }

   
  private get chromeSessionStorage(): any {
    return (globalThis as any).chrome.storage.session;
  }

  private async persistConfig(config: TideCloakConfig): Promise<void> {
    try {
      if (this.isBrowserExtension()) {
        await this.chromeSessionStorage.set({
          [STORAGE_KEY_CONFIG]: JSON.stringify(config),
        });
        return;
      }
      const storage = this.getSessionStorage();
      if (storage) {
        storage.setItem(STORAGE_KEY_CONFIG, JSON.stringify(config));
      }
    } catch {
      // Storage may not be available
    }
  }

  private async persistDoken(doken: string): Promise<void> {
    try {
      if (this.isBrowserExtension()) {
        await this.chromeSessionStorage.set({
          [STORAGE_KEY_DOKEN]: doken,
        });
        return;
      }
      const storage = this.getSessionStorage();
      if (storage) {
        storage.setItem(STORAGE_KEY_DOKEN, doken);
      }
    } catch {
      // Storage may not be available
    }
  }

  private async loadConfig(): Promise<TideCloakConfig | null> {
    try {
      if (this.isBrowserExtension()) {
        const result = await this.chromeSessionStorage.get([STORAGE_KEY_CONFIG]);
        const json = result[STORAGE_KEY_CONFIG];
        return json ? (JSON.parse(json) as TideCloakConfig) : null;
      }
      const storage = this.getSessionStorage();
      if (!storage) {
        return null;
      }
      const json = storage.getItem(STORAGE_KEY_CONFIG);
      return json ? (JSON.parse(json) as TideCloakConfig) : null;
    } catch {
      return null;
    }
  }

  private async loadDoken(): Promise<string | null> {
    try {
      if (this.isBrowserExtension()) {
        const result = await this.chromeSessionStorage.get([STORAGE_KEY_DOKEN]);
        return result[STORAGE_KEY_DOKEN] ?? null;
      }
      const storage = this.getSessionStorage();
      if (!storage) {
        return null;
      }
      return storage.getItem(STORAGE_KEY_DOKEN);
    } catch {
      return null;
    }
  }

  private clearStorage(): void {
    try {
      if (this.isBrowserExtension()) {
        this.chromeSessionStorage
          .remove([STORAGE_KEY_CONFIG, STORAGE_KEY_DOKEN])
          .catch(() => {});
        return;
      }
      const storage = this.getSessionStorage();
      if (storage) {
        storage.removeItem(STORAGE_KEY_CONFIG);
        storage.removeItem(STORAGE_KEY_DOKEN);
      }
    } catch {
      // Storage may not be available
    }
  }

  private getSessionStorage(): Storage | null {
    return typeof globalThis.sessionStorage !== "undefined" ? globalThis.sessionStorage : null;
  }
}
