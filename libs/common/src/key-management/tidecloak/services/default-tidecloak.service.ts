import { LogService } from "../../../platform/abstractions/log.service";
import { TideCloakConfig, TideCloakService } from "../abstractions/tidecloak.service";

const STORAGE_KEY_CONFIG = "tidecloak_config";
const STORAGE_KEY_DOKEN = "tidecloak_doken";

export class DefaultTideCloakService extends TideCloakService {

  private tc: any | null = null; // TideCloak
  private config: TideCloakConfig | null = null;
  private initializingPromise: Promise<void> | null = null;
  private _skipOrkDecrypt = false;
  // Serialization queue — RequestEnclave can't handle concurrent postMessage operations
  private _opQueue: Promise<any> = Promise.resolve();

  constructor(private logService: LogService) {
    super();
  }

  async initialize(config: TideCloakConfig, doken: string): Promise<void> {
    this.config = config;

    // Extract auth server URL, realm, and session ID from the pre-built voucher URL
    const voucherUrlObj = new URL(config.voucherUrl);
    const pathParts = voucherUrlObj.pathname.split("/");
    const realmIndex = pathParts.indexOf("realms");
    const realm = realmIndex >= 0 ? decodeURIComponent(pathParts[realmIndex + 1]) : "";
    const authServerUrl = voucherUrlObj.origin;
    const sessionId = voucherUrlObj.searchParams.get("sessionId") ?? "";

    const { TideCloak } = await import("@tidecloak/js");

    this.tc = new TideCloak({
      url: authServerUrl,
      realm: realm,
      clientId: "tidewarden",
      vendorId: config.vendorId,
      clientOriginAuth: config.signedClientOrigin,
    });

    // Set public fields that initRequestEnclave() and #getVoucherUrl() need
    this.tc.authServerUrl = authServerUrl;
    this.tc.realm = realm;
    this.tc.doken = doken;
    this.tc.dokenParsed = JSON.parse(atob(doken.split(".")[1]));
    this.tc.tokenParsed = { sid: sessionId };

    this.tc.initRequestEnclave();
    await this.tc.requestEnclave.initDone;

    await this.persistConfig(config);
    await this.persistDoken(doken);

    this.logService.info("[TideCloak] RequestEnclave initialized");
  }

  async encrypt(data: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this.tc?.requestEnclave) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    // Serialize — RequestEnclave postMessage listeners can't handle concurrent ops
    const op = this._opQueue.then(() =>
      this.tc.requestEnclave.encrypt([{ data, tags }]),
    );
    this._opQueue = op.catch(() => {});
    const results = await op;
    return results[0];
  }

  async decrypt(encrypted: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this.tc?.requestEnclave) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    // Serialize — RequestEnclave postMessage listeners can't handle concurrent ops
    const op = this._opQueue.then(() =>
      this.tc.requestEnclave.decrypt([{ encrypted, tags }]),
    );
    this._opQueue = op.catch(() => {});
    const results = await op;
    return results[0];
  }

  async updateDoken(doken: string): Promise<void> {
    if (this.tc) {
      this.tc.doken = doken;
      this.tc.dokenParsed = JSON.parse(atob(doken.split(".")[1]));
      if (this.tc.requestEnclave) {
        this.tc.requestEnclave.updateDoken(doken);
      }
    }
    await this.persistDoken(doken);
  }

  isInitialized(): boolean {
    return this.tc?.requestEnclave != null;
  }

  async ensureInitialized(): Promise<boolean> {
    if (this.tc?.requestEnclave != null) {
      return true;
    }

    // Avoid concurrent re-initialization attempts
    if (this.initializingPromise != null) {
      await this.initializingPromise;
      return this.tc?.requestEnclave != null;
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
    return this.tc?.requestEnclave != null;
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
    if (this.tc?.requestEnclave) {
      try {
        this.tc.requestEnclave.close();
      } catch {
        // Enclave may already be closed
      }
    }
    this.tc = null;
    this.config = null;
    this._opQueue = Promise.resolve();
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
