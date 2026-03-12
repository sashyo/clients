export interface TideCloakConfig {
  homeOrkUrl: string;
  vendorId: string;
  voucherUrl: string;
  signedClientOrigin: string;
}

export interface EncryptionScope {
  orgId: string;
  collectionIds: string[];
  policy: Uint8Array;
}

export abstract class TideCloakService {
  abstract initialize(config: TideCloakConfig, doken: string): Promise<void>;
  abstract encryptBatch(items: { data: Uint8Array; tags: string[] }[], policy?: Uint8Array): Promise<Uint8Array[]>;
  abstract encrypt(data: Uint8Array, tags: string[], policy?: Uint8Array): Promise<Uint8Array>;
  abstract decryptBatch(items: { encrypted: Uint8Array; tags: string[] }[], policy?: Uint8Array): Promise<Uint8Array[]>;
  abstract decrypt(encrypted: Uint8Array, tags: string[], policy?: Uint8Array): Promise<Uint8Array>;
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
  /**
   * When true, ORK encryption is skipped and standard AES is used instead.
   * Used when encrypting non-sensitive fields (e.g. collection/folder/send names)
   * that need to be readable by other org members.
   */
  abstract setSkipOrkEncrypt(skip: boolean): void;
  abstract shouldSkipOrkEncrypt(): boolean;
  abstract destroy(): void;
  /**
   * Signs/initializes a Tide request using the enclave's createTideRequest.
   * This is the equivalent of KeyleSSH's initializeTideRequest.
   * @param encodedRequest - The encoded PolicySignRequest bytes
   * @returns The initialized (signed) request bytes
   */
  abstract createTideRequest(encodedRequest: Uint8Array): Promise<Uint8Array>;
  /**
   * Returns the vendorId from the persisted config.
   */
  abstract getVendorId(): string;
  /**
   * Returns the TideCloak resource (client ID) for policy params.
   * Defaults to "tidewarden".
   */
  abstract getResource(): string;
  /**
   * Opens the Tide operator approval popup for cryptographic signing of policy requests.
   * Each request contains an id and the encoded PolicySignRequest bytes.
   * Returns approved/denied/pending status with signed bytes for approved requests.
   */
  abstract approveTideRequests(
    requests: { id: string; request: Uint8Array }[],
  ): Promise<{ id: string; request: Uint8Array; status: "approved" | "denied" | "pending" }[]>;
  /**
   * Executes a signed Tide request against the ORK to get the final VVK signature.
   * Called after a policy has been approved and is ready to commit.
   * @param initialize - If true (default), also calls createTideRequest before executing.
   *   Pass false for commit to avoid double initialization.
   */
  abstract executeSignRequest(request: Uint8Array, initialize?: boolean): Promise<Uint8Array[]>;
  /**
   * Returns the current doken string, or null if not available.
   */
  abstract getDoken(): string | null;
  /**
   * Sets the current encryption scope for org/collection policy-enabled encryption.
   * When set, encrypt/decrypt will use the policy and collection-scoped tags
   * instead of selfencrypt/selfdecrypt realm roles.
   */
  abstract setEncryptionScope(scope: EncryptionScope | null): void;
  abstract getEncryptionScope(): EncryptionScope | null;
  /**
   * Registers a callback that obtains a fresh doken (e.g. by triggering a
   * Bitwarden token refresh). Called automatically by the ORK enclave when
   * the current doken expires.
   */
  abstract setDokenRefreshCallback(fn: () => Promise<string | null>): void;
}
