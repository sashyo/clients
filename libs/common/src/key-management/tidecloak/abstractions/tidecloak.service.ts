export interface TideCloakConfig {
  homeOrkUrl: string;
  vendorId: string;
  voucherUrl: string;
  signedClientOrigin: string;
}

export abstract class TideCloakService {
  abstract initialize(config: TideCloakConfig, doken: string): Promise<void>;
  abstract encrypt(data: Uint8Array, tags: string[]): Promise<Uint8Array>;
  abstract decrypt(encrypted: Uint8Array, tags: string[]): Promise<Uint8Array>;
  abstract updateDoken(doken: string): Promise<void>;
  abstract isInitialized(): boolean;
  /**
   * Re-initializes the enclave from persisted config/doken if it was lost
   * (e.g. after a page refresh). Returns true if the enclave is initialized
   * after this call, false otherwise.
   */
  abstract ensureInitialized(): Promise<boolean>;
  /**
   * Returns true if TideCloak config exists in persisted storage,
   * meaning the current user logged in via TideCloak SSO.
   * Used to distinguish "not a TideCloak user" from "TideCloak user whose ORK failed".
   */
  abstract hasPersistedConfig(): Promise<boolean>;
  /**
   * When true, ORK decryption is skipped and null is returned for type 100 fields.
   * Used during bulk vault decryption so sensitive data is never held in memory.
   * On-demand decryption (when user opens a cipher) should set this to false.
   */
  abstract setSkipOrkDecrypt(skip: boolean): void;
  abstract shouldSkipOrkDecrypt(): boolean;
  abstract destroy(): void;
}
