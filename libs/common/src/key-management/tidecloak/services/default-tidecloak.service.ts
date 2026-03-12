import { LogService } from "../../../platform/abstractions/log.service";
import { EncryptionScope, TideCloakConfig, TideCloakService } from "../abstractions/tidecloak.service";

const STORAGE_KEY_CONFIG = "tidecloak_config";
const STORAGE_KEY_DOKEN = "tidecloak_doken";

export class DefaultTideCloakService extends TideCloakService {

  private tc: any | null = null; // TideCloak
  private config: TideCloakConfig | null = null;
  private initializingPromise: Promise<void> | null = null;
  private _skipOrkDecrypt = true;
  private _skipOrkEncrypt = false;
  private _encryptionScope: EncryptionScope | null = null;
  // Serialization queue — RequestEnclave can't handle concurrent postMessage operations
  private _opQueue: Promise<any> = Promise.resolve();
  private _dokenRefreshFn: (() => Promise<string | null>) | null = null;


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
    // Set token fields so ensureTokenReady() / isTokenExpired() work correctly.
    // We manage auth externally via TideCloak SSO — the JS adapter never refreshes tokens.
    // - flow = "implicit": bypasses the refreshToken requirement in isTokenExpired()
    // - timeSkew = 0: prevents isTokenExpired() from returning true due to null timeSkew
    // - exp = far future: prevents the expiry check from triggering updateToken()
    this.tc.tokenParsed = {
      sid: sessionId,
      exp: Math.ceil(Date.now() / 1000) + 86400 * 365, // 1 year — session won't last that long
    };
    this.tc.flow = "implicit";
    this.tc.timeSkew = 0;

    this.tc.initRequestEnclave();
    await this.tc.requestEnclave.initDone;

    // Override the enclave's dokenRefreshCallback so that when the ORK
    // detects an expired doken it can obtain a truly fresh one via
    // Bitwarden's token refresh (which round-trips through TideCloak).
    // The default callback just calls ensureTokenReady() which is a no-op
    // because we set tokenParsed.exp to 1 year.
    const self = this;
    this.tc.requestEnclave.dokenRefreshCallback = async () => {
      if (self._dokenRefreshFn) {
        try {
          const freshDoken = await self._dokenRefreshFn();
          if (freshDoken) {
            self.tc.doken = freshDoken;
            self.tc.dokenParsed = JSON.parse(atob(freshDoken.split(".")[1]));
            await self.persistDoken(freshDoken);
            self.logService.info("[TideCloak] Doken refreshed via callback");
            return freshDoken;
          }
        } catch (e) {
          self.logService.error(`[TideCloak] Doken refresh callback failed: ${e}`);
        }
      }
      // Fallback: return the current doken (may be stale)
      return self.tc.doken;
    };

    await this.persistConfig(config);
    await this.persistDoken(doken);

    this.logService.info("[TideCloak] RequestEnclave initialized");
  }

  async encryptBatch(
    items: { data: Uint8Array; tags: string[] }[],
    policy?: Uint8Array,
  ): Promise<Uint8Array[]> {
    if (!this.tc) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    console.info(`[TideCloak] encryptBatch: ${items.length} item(s), policy=${policy ? `Uint8Array(${policy.length})` : "undefined"}, flow=${policy ? "policy encrypt" : "encrypt"}`);
    const op = this._opQueue.then(() => this.tc.requestEnclave.encrypt(items, policy));
    this._opQueue = op.catch(() => {});
    return await op;
  }

  async encrypt(data: Uint8Array, tags: string[], policy?: Uint8Array): Promise<Uint8Array> {
    return (await this.encryptBatch([{ data, tags }], policy))[0];
  }

  async decryptBatch(
    items: { encrypted: Uint8Array; tags: string[] }[],
    policy?: Uint8Array,
  ): Promise<Uint8Array[]> {
    if (!this.tc) {
      throw new Error("[TideCloak] Enclave not initialized");
    }
    console.info(`[TideCloak] decryptBatch: ${items.length} item(s), policy=${policy ? `Uint8Array(${policy.length})` : "undefined"}`);
    const op = this._opQueue.then(() => {
      const decryptCall = this.tc.requestEnclave.decrypt(items, policy);
      return Promise.race([
        decryptCall,
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error(`[TideCloak] ORK decrypt timed out (batch of ${items.length})`)),
            30_000,
          ),
        ),
      ]);
    });
    this._opQueue = op.catch(() => {});
    return await op;
  }

  async decrypt(encrypted: Uint8Array, tags: string[], policy?: Uint8Array): Promise<Uint8Array> {
    return (await this.decryptBatch([{ encrypted, tags }], policy))[0];
  }

  async updateDoken(doken: string): Promise<void> {
    if (this.tc) {
      this.tc.doken = doken;
      this.tc.dokenParsed = JSON.parse(atob(doken.split(".")[1]));
      if (this.tc.requestEnclave) {
        this.tc.requestEnclave.updateDoken(doken);
      }
      if (this.tc.approvalEnclave) {
        this.tc.approvalEnclave.updateDoken(doken);
      }
    }
    await this.persistDoken(doken);
  }

  isInitialized(): boolean {
    return this.tc?.requestEnclave != null;
  }

  async ensureInitialized(): Promise<boolean> {
    if (this.tc?.requestEnclave != null) {
      this.logService.info(`[TideCloak] ensureInitialized: already initialized, doken=${this.tc.doken ? 'present' : 'MISSING'}`);
      return true;
    }
    this.logService.info(`[TideCloak] ensureInitialized: NOT initialized, tc=${!!this.tc}`);

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

  setSkipOrkEncrypt(skip: boolean): void {
    this._skipOrkEncrypt = skip;
  }

  shouldSkipOrkEncrypt(): boolean {
    return this._skipOrkEncrypt;
  }

  setEncryptionScope(scope: EncryptionScope | null): void {
    this._encryptionScope = scope;
  }

  getEncryptionScope(): EncryptionScope | null {
    return this._encryptionScope;
  }

  async createTideRequest(encodedRequest: Uint8Array): Promise<Uint8Array> {
    if (!this.tc?.createTideRequest) {
      throw new Error("[TideCloak] createTideRequest not available — enclave not initialized");
    }
    this.logService.info(`[TideCloak] createTideRequest: ${encodedRequest.length} bytes, doken=${this.tc.doken ? 'present(' + this.tc.doken.substring(0, 20) + '...)' : 'MISSING'}, enclave=${!!this.tc.requestEnclave}, enclaveClosed=${this.tc.requestEnclave?.enclaveClosed?.()}`);
    // Serialize through the operation queue like encrypt/decrypt
    const op = this._opQueue.then(() =>
      this.tc.createTideRequest(encodedRequest),
    );
    this._opQueue = op.catch(() => {});
    const result = await op;
    this.logService.info(`[TideCloak] createTideRequest completed: ${result.length} bytes`);
    return result;
  }

  getVendorId(): string {
    if (!this.config) {
      throw new Error("[TideCloak] Config not initialized — cannot get vendorId");
    }
    return this.config.vendorId;
  }

  getResource(): string {
    return "tidewarden";
  }

  async approveTideRequests(
    requests: { id: string; request: Uint8Array }[],
  ): Promise<{ id: string; request: Uint8Array; status: "approved" | "denied" | "pending" }[]> {
    if (!this.tc?.requestTideOperatorApproval) {
      throw new Error("[TideCloak] requestTideOperatorApproval not available — enclave not initialized");
    }
    this.logService.info(
      `[TideCloak] approveTideRequests: ${requests.length} request(s), ids: ${requests.map((r) => r.id).join(", ")}`,
    );
    const results = await this.tc.requestTideOperatorApproval(requests);
    this.logService.info(
      `[TideCloak] approveTideRequests results: ${JSON.stringify(results.map((r: any) => ({ id: r.id, status: r.status })))}`,
    );
    return results;
  }

  async executeSignRequest(request: Uint8Array, initialize = true): Promise<Uint8Array[]> {
    if (!this.tc?.executeSignRequest) {
      throw new Error("[TideCloak] executeSignRequest not available — enclave not initialized");
    }
    // Serialize through the operation queue like encrypt/decrypt
    const op = this._opQueue.then(() =>
      this.tc.executeSignRequest(request, initialize),
    );
    this._opQueue = op.catch(() => {});
    return await op;
  }

  getDoken(): string | null {
    return this.tc?.doken ?? null;
  }

  setDokenRefreshCallback(fn: () => Promise<string | null>): void {
    this._dokenRefreshFn = fn;
  }

  destroy(): void {
    if (this.tc?.requestEnclave) {
      try {
        this.tc.requestEnclave.close();
      } catch {
        // Enclave may already be closed
      }
    }
    if (this.tc?.approvalEnclave) {
      try {
        this.tc.approvalEnclave.close();
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
  //
  // Chrome MV3: use chrome.storage.session (session-scoped, survives service worker restarts)
  // Firefox MV2: use browser.storage.local (persistent) because browser.storage.session
  //   is wiped on browser restart and extension updates, and the popup has no persistent
  //   in-memory state between open/close cycles.
  // Web / other: fall back to sessionStorage.

  private get chromeSessionStorage(): any {
    return (globalThis as any).chrome?.storage?.session ?? null;
  }

  private get firefoxLocalStorage(): any {
    return (globalThis as any).browser?.storage?.local ?? null;
  }

  private get extensionStorage(): { storage: any; isFirefox: boolean } | null {
    const chrome = this.chromeSessionStorage;
    if (chrome) {
      return { storage: chrome, isFirefox: false };
    }
    const firefox = this.firefoxLocalStorage;
    if (firefox) {
      return { storage: firefox, isFirefox: true };
    }
    return null;
  }

  private async persistConfig(config: TideCloakConfig): Promise<void> {
    try {
      const ext = this.extensionStorage;
      if (ext) {
        await ext.storage.set({ [STORAGE_KEY_CONFIG]: JSON.stringify(config) });
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
      const ext = this.extensionStorage;
      if (ext) {
        await ext.storage.set({ [STORAGE_KEY_DOKEN]: doken });
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
      const ext = this.extensionStorage;
      if (ext) {
        const result = await ext.storage.get([STORAGE_KEY_CONFIG]);
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
      const ext = this.extensionStorage;
      if (ext) {
        const result = await ext.storage.get([STORAGE_KEY_DOKEN]);
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
      const ext = this.extensionStorage;
      if (ext) {
        ext.storage.remove([STORAGE_KEY_CONFIG, STORAGE_KEY_DOKEN]).catch(() => {});
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
