// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { ConsoleLogService } from "@bitwarden/common/platform/services/console-log.service";

import { BrowserApi } from "../browser/browser-api";
import BrowserClipboardService from "../services/browser-clipboard.service";

import {
  OffscreenDocumentExtensionMessage,
  OffscreenDocumentExtensionMessageHandlers,
  OffscreenDocument as OffscreenDocumentInterface,
} from "./abstractions/offscreen-document";

class OffscreenDocument implements OffscreenDocumentInterface {
  private consoleLogService: ConsoleLogService = new ConsoleLogService(false);
  /** TideCloak instance hosting the RequestEnclave (hidden iframe for ORK crypto). */
  private tc: any | null = null;
  /** Serialization queue — RequestEnclave can't handle concurrent postMessage ops. */
  private _opQueue: Promise<any> = Promise.resolve();

  private readonly extensionMessageHandlers: OffscreenDocumentExtensionMessageHandlers = {
    offscreenCopyToClipboard: ({ message }) => this.handleOffscreenCopyToClipboard(message),
    offscreenReadFromClipboard: () => this.handleOffscreenReadFromClipboard(),
    localStorageGet: ({ message }) => this.handleLocalStorageGet(message.key),
    localStorageSave: ({ message }) => this.handleLocalStorageSave(message.key, message.value),
    localStorageRemove: ({ message }) => this.handleLocalStorageRemove(message.key),
    tidecloakInit: ({ message }) => this.handleTideCloakInit(message),
    tidecloakEncrypt: ({ message }) => this.handleTideCloakEncrypt(message),
    tidecloakDecrypt: ({ message }) => this.handleTideCloakDecrypt(message),
    tidecloakUpdateDoken: ({ message }) => this.handleTideCloakUpdateDoken(message),
    tidecloakDestroy: () => this.handleTideCloakDestroy(),
    tidecloakIsInitialized: () => this.handleTideCloakIsInitialized(),
  };

  init() {
    this.setupExtensionMessageListener();
  }

  // --- Clipboard handlers ---

  private async handleOffscreenCopyToClipboard(message: OffscreenDocumentExtensionMessage) {
    await BrowserClipboardService.copy(self, message.text);
  }

  private async handleOffscreenReadFromClipboard() {
    return await BrowserClipboardService.read(self);
  }

  // --- LocalStorage handlers ---

  private handleLocalStorageGet(key: string) {
    return self.localStorage.getItem(key);
  }

  private handleLocalStorageSave(key: string, value: string) {
    self.localStorage.setItem(key, value);
  }

  private handleLocalStorageRemove(key: string) {
    self.localStorage.removeItem(key);
  }

  // --- TideCloak RequestEnclave handlers ---
  // The offscreen document has DOM access, so it can host the RequestEnclave's
  // hidden iframe that the MV3 service worker cannot create.

  private async handleTideCloakInit(message: OffscreenDocumentExtensionMessage) {
    try {
      const { config, doken } = message;

      if (this.tc?.requestEnclave) {
        return { status: "already-initialized" };
      }

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

      this.tc.authServerUrl = authServerUrl;
      this.tc.realm = realm;
      this.tc.doken = doken;
      this.tc.dokenParsed = JSON.parse(atob(doken.split(".")[1]));
      this.tc.tokenParsed = { sid: sessionId };

      this.tc.initRequestEnclave();
      await this.tc.requestEnclave.initDone;

      this.consoleLogService.info("[OffscreenTideCloak] RequestEnclave initialized");
      return { status: "initialized" };
    } catch (e) {
      this.consoleLogService.error(`[OffscreenTideCloak] Init failed: ${e}`);
      return { status: "error", error: e instanceof Error ? e.message : String(e) };
    }
  }

  private async handleTideCloakEncrypt(message: OffscreenDocumentExtensionMessage) {
    if (!this.tc?.requestEnclave) {
      return { status: "error", error: "Enclave not initialized" };
    }

    try {
      const data = this.b64ToUint8Array(message.dataB64);
      const tags: string[] = message.tags;

      const op = this._opQueue.then(() =>
        this.tc.requestEnclave.encrypt([{ data, tags }]),
      );
      this._opQueue = op.catch(() => {});
      const results = await op;

      return { status: "success", resultB64: this.uint8ArrayToB64(results[0]) };
    } catch (e) {
      this.consoleLogService.error(`[OffscreenTideCloak] Encrypt failed: ${e}`);
      return { status: "error", error: e instanceof Error ? e.message : String(e) };
    }
  }

  private async handleTideCloakDecrypt(message: OffscreenDocumentExtensionMessage) {
    if (!this.tc?.requestEnclave) {
      return { status: "error", error: "Enclave not initialized" };
    }

    try {
      const encrypted = this.b64ToUint8Array(message.encryptedB64);
      const tags: string[] = message.tags;

      const op = this._opQueue.then(() =>
        Promise.race([
          this.tc.requestEnclave.decrypt([{ encrypted, tags }]),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("ORK decrypt timed out")), 30_000),
          ),
        ]),
      );
      this._opQueue = op.catch(() => {});
      const results = await op;

      return { status: "success", resultB64: this.uint8ArrayToB64(results[0]) };
    } catch (e) {
      this.consoleLogService.error(`[OffscreenTideCloak] Decrypt failed: ${e}`);
      return { status: "error", error: e instanceof Error ? e.message : String(e) };
    }
  }

  private async handleTideCloakUpdateDoken(message: OffscreenDocumentExtensionMessage) {
    try {
      if (this.tc) {
        this.tc.doken = message.doken;
        this.tc.dokenParsed = JSON.parse(atob(message.doken.split(".")[1]));
        if (this.tc.requestEnclave) {
          this.tc.requestEnclave.updateDoken(message.doken);
        }
      }
      return { status: "success" };
    } catch (e) {
      return { status: "error", error: e instanceof Error ? e.message : String(e) };
    }
  }

  private handleTideCloakDestroy() {
    if (this.tc?.requestEnclave) {
      try {
        this.tc.requestEnclave.close();
      } catch {
        // Enclave may already be closed
      }
    }
    this.tc = null;
    this._opQueue = Promise.resolve();
    return { status: "destroyed" };
  }

  private handleTideCloakIsInitialized() {
    return { initialized: this.tc?.requestEnclave != null };
  }

  // --- Base64 helpers for Uint8Array serialization over chrome.runtime messages ---

  private uint8ArrayToB64(data: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < data.length; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
  }

  private b64ToUint8Array(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // --- Message listener setup ---

  private setupExtensionMessageListener() {
    BrowserApi.messageListener("offscreen-document", this.handleExtensionMessage);
  }

  private handleExtensionMessage = (
    message: OffscreenDocumentExtensionMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: any) => void,
  ) => {
    const handler: CallableFunction | undefined = this.extensionMessageHandlers[message?.command];
    if (!handler) {
      return;
    }

    const messageResponse = handler({ message, sender });
    if (!messageResponse) {
      return;
    }

    Promise.resolve(messageResponse)
      .then((response) => sendResponse(response))
      .catch((error) => {
        this.consoleLogService.error("Error resolving extension message response", error);
        sendResponse({ status: "error", error: error instanceof Error ? error.message : String(error) });
      });
    return true;
  };
}

(() => {
  const offscreenDocument = new OffscreenDocument();
  offscreenDocument.init();
})();
