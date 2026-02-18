import { Utils } from "@bitwarden/common/platform/misc/utils";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import {
  TideCloakConfig,
  TideCloakService,
} from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { BrowserApi } from "../../platform/browser/browser-api";
import { OffscreenDocumentService } from "../../platform/offscreen-document/abstractions/offscreen-document";

const STORAGE_KEY_CONFIG = "tidecloak_config";
const STORAGE_KEY_DOKEN = "tidecloak_doken";

/**
 * TideCloakService implementation for MV3 service workers.
 *
 * Proxies all encrypt/decrypt operations through the offscreen document,
 * which has DOM access and can host the RequestEnclave's hidden iframe.
 *
 * The offscreen document is held open persistently (via a never-resolving
 * withDocument callback) so the enclave iframe survives across operations.
 * It is only released when destroy() is called.
 */
export class OffscreenTideCloakService extends TideCloakService {
  private config: TideCloakConfig | null = null;
  private _initialized = false;
  private initializingPromise: Promise<void> | null = null;
  private _skipOrkDecrypt = false;
  private _skipOrkEncrypt = false;

  /** Resolving this releases the persistent hold on the offscreen document. */
  private keepAliveResolve: (() => void) | null = null;

  constructor(
    private offscreenDocumentService: OffscreenDocumentService,
    private logService: LogService,
  ) {
    super();
  }

  async initialize(config: TideCloakConfig, doken: string): Promise<void> {
    this.config = config;

    // Acquire a persistent hold on the offscreen document.
    // This starts a withDocument call whose callback never resolves,
    // keeping workerCount > 0 so the document is not closed.
    this.acquireDocumentHold();

    // Use a second withDocument call (which piggybacks on the already-open
    // document) to send the init message. This one resolves normally.
    await this.offscreenDocumentService.withDocument(
      [chrome.offscreen.Reason.DOM_PARSER],
      "TideCloak RequestEnclave initialization",
      async () => {
        // Wait for the offscreen document's script to load and register its
        // message listener. createDocument() resolves when the DOM is ready,
        // but the script may not have executed yet.
        await this.waitForDocumentReady();

        const response = await BrowserApi.sendMessageWithResponse<{ status: string }>(
          "tidecloakInit",
          { config, doken },
        );
        if (!response || response.status === "error") {
          throw new Error(
            `[OffscreenTideCloak] Init failed: ${(response as any)?.error ?? "no response from offscreen document"}`,
          );
        }
      },
    );

    this._initialized = true;
    await this.persistConfig(config);
    await this.persistDoken(doken);
    this.logService.info("[OffscreenTideCloak] Enclave initialized via offscreen document");
  }

  async encrypt(data: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this._initialized) {
      throw new Error("[OffscreenTideCloak] Encrypt failed: Enclave not initialized");
    }

    const response = await this.sendWithRetry<{
      status: string;
      resultB64?: string;
      error?: string;
    }>("tidecloakEncrypt", {
      dataB64: Utils.fromBufferToB64(data),
      tags,
    });

    if (!response || response.status === "error") {
      throw new Error(
        `[OffscreenTideCloak] Encrypt failed: ${response?.error ?? "no response from offscreen document"}`,
      );
    }

    return Utils.fromB64ToArray(response.resultB64);
  }

  async decrypt(encrypted: Uint8Array, tags: string[]): Promise<Uint8Array> {
    if (!this._initialized) {
      throw new Error("[OffscreenTideCloak] Decrypt failed: Enclave not initialized");
    }

    const response = await this.sendWithRetry<{
      status: string;
      resultB64?: string;
      error?: string;
    }>("tidecloakDecrypt", {
      encryptedB64: Utils.fromBufferToB64(encrypted),
      tags,
    });

    if (!response || response.status === "error") {
      throw new Error(
        `[OffscreenTideCloak] Decrypt failed: ${response?.error ?? "no response from offscreen document"}`,
      );
    }

    return Utils.fromB64ToArray(response.resultB64);
  }

  async updateDoken(doken: string): Promise<void> {
    await BrowserApi.sendMessageWithResponse("tidecloakUpdateDoken", { doken });
    await this.persistDoken(doken);
  }

  isInitialized(): boolean {
    return this._initialized;
  }

  async ensureInitialized(): Promise<boolean> {
    if (this._initialized) {
      return true;
    }

    if (this.initializingPromise != null) {
      await this.initializingPromise;
      return this._initialized;
    }

    if (!this.offscreenDocumentService.offscreenApiSupported()) {
      return false;
    }

    const config = await this.loadConfig();
    const doken = await this.loadDoken();
    if (!config || !doken) {
      return false;
    }

    this.logService.info("[OffscreenTideCloak] Re-initializing from persisted state");

    this.initializingPromise = (async () => {
      await this.initialize(config, doken);
    })()
      .catch((e) => {
        this.logService.error(`[OffscreenTideCloak] Failed to re-init: ${e}`);
      })
      .finally(() => {
        this.initializingPromise = null;
      });

    await this.initializingPromise;
    return this._initialized;
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

  destroy(): void {
    if (this._initialized) {
      // Send cleanup message to the offscreen document
      BrowserApi.sendMessageWithResponse("tidecloakDestroy", {}).catch(() => {});
    }

    // Release the persistent hold — this lets withDocument's finally block
    // decrement workerCount and close the document.
    this.releaseDocumentHold();

    this._initialized = false;
    this.config = null;
    this.clearStorage();
  }

  // --- Offscreen document lifecycle ---

  /**
   * Starts a withDocument call that never resolves, keeping the offscreen
   * document alive until releaseDocumentHold() is called.
   */
  private acquireDocumentHold(): void {
    if (this.keepAliveResolve) {
      return; // Already holding
    }

    const keepAlivePromise = new Promise<void>((resolve) => {
      this.keepAliveResolve = resolve;
    });

    // Fire-and-forget — this keeps workerCount > 0
    this.offscreenDocumentService
      .withDocument(
        [chrome.offscreen.Reason.DOM_PARSER],
        "TideCloak RequestEnclave (persistent)",
        () => keepAlivePromise,
      )
      .catch((e) => {
        this.logService.error(`[OffscreenTideCloak] Document hold error: ${e}`);
      });
  }

  private releaseDocumentHold(): void {
    if (this.keepAliveResolve) {
      this.keepAliveResolve();
      this.keepAliveResolve = null;
    }
  }

  /**
   * Polls the offscreen document until it responds, confirming its script
   * has loaded and the onMessage listener is registered.
   * chrome.offscreen.createDocument() resolves when the DOM is ready, but
   * the bundled JS may not have executed yet.
   */
  private async waitForDocumentReady(maxAttempts = 20, delayMs = 100): Promise<void> {
    for (let i = 0; i < maxAttempts; i++) {
      const response = await BrowserApi.sendMessageWithResponse<{ initialized?: boolean }>(
        "tidecloakIsInitialized",
        {},
      );
      // Any non-undefined response means the listener is active
      if (response !== undefined && response !== null) {
        return;
      }
      await new Promise((r) => setTimeout(r, delayMs));
    }
    throw new Error("[OffscreenTideCloak] Offscreen document did not become ready in time");
  }

  /**
   * Sends a message to the offscreen document with a single retry.
   * If the first attempt gets no response (port closed, document restarted),
   * waits briefly and retries once.
   */
  private async sendWithRetry<T>(command: string, args: any): Promise<T> {
    let response = await BrowserApi.sendMessageWithResponse<T>(command, args);
    if (response !== undefined && response !== null) {
      return response;
    }

    // First attempt got no response — the offscreen document may have been
    // closed and recreated. Wait for it and retry once.
    this.logService.warning(
      `[OffscreenTideCloak] No response for ${command}, retrying...`,
    );
    await new Promise((r) => setTimeout(r, 200));

    response = await BrowserApi.sendMessageWithResponse<T>(command, args);
    return response;
  }

  // --- Storage helpers (using chrome.storage.session) ---

  private get chromeSessionStorage(): any {
    return (globalThis as any).chrome.storage.session;
  }

  private async persistConfig(config: TideCloakConfig): Promise<void> {
    try {
      await this.chromeSessionStorage.set({
        [STORAGE_KEY_CONFIG]: JSON.stringify(config),
      });
    } catch {
      // Storage may not be available
    }
  }

  private async persistDoken(doken: string): Promise<void> {
    try {
      await this.chromeSessionStorage.set({
        [STORAGE_KEY_DOKEN]: doken,
      });
    } catch {
      // Storage may not be available
    }
  }

  private async loadConfig(): Promise<TideCloakConfig | null> {
    try {
      const result = await this.chromeSessionStorage.get([STORAGE_KEY_CONFIG]);
      const json = result[STORAGE_KEY_CONFIG];
      return json ? (JSON.parse(json) as TideCloakConfig) : null;
    } catch {
      return null;
    }
  }

  private async loadDoken(): Promise<string | null> {
    try {
      const result = await this.chromeSessionStorage.get([STORAGE_KEY_DOKEN]);
      return result[STORAGE_KEY_DOKEN] ?? null;
    } catch {
      return null;
    }
  }

  private clearStorage(): void {
    try {
      this.chromeSessionStorage
        .remove([STORAGE_KEY_CONFIG, STORAGE_KEY_DOKEN])
        .catch(() => {});
    } catch {
      // Storage may not be available
    }
  }
}
