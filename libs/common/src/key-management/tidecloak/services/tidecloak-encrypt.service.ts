import { LogService } from "../../../platform/abstractions/log.service";
import { EncryptionType } from "../../../platform/enums";
import { Utils } from "../../../platform/misc/utils";
import { SymmetricCryptoKey } from "../../../platform/models/domain/symmetric-crypto-key";
import { CryptoFunctionService } from "../../crypto/abstractions/crypto-function.service";
import { EncString } from "../../crypto/models/enc-string";
import { EncryptServiceImplementation } from "../../crypto/services/encrypt.service.implementation";
import { TideCloakService } from "../abstractions/tidecloak.service";

/**
 * EncryptService that routes encryption/decryption through the TideCloak ORK
 * when the enclave is available.
 *
 * Non-sensitive fields (names) should call setSkipOrkEncrypt(true) before
 * encrypting so they use standard AES and remain readable by other org members.
 *
 * Key management methods (wrap/unwrap/encapsulate) are inherited unchanged.
 */
export class TideCloakEncryptService extends EncryptServiceImplementation {
  // After an ORK decrypt failure (e.g. data encrypted by another user's ORK),
  // skip subsequent ORK decrypts for a cooldown period so the edit dialog
  // doesn't hang for 5s × N fields.  Resets after 10s so the user's own
  // ORK-encrypted data can still be decrypted on the next interaction.
  private _orkDecryptCooldownUntil = 0;

  constructor(
    cryptoFunctionService: CryptoFunctionService,
    logService: LogService,
    logMacFailures: boolean,
    private tideCloakService: TideCloakService,
  ) {
    super(cryptoFunctionService, logService, logMacFailures);
  }

  /**
   * Decrypts multiple TideCloak-encrypted EncStrings in a single ORK round-trip.
   * Items with the same policy are sent together. Non-TideCloak items fall back to
   * individual AES decryption. Results are returned in input order.
   */
  async decryptEncStringsBatch(
    encStrings: (EncString | null)[],
    key: SymmetricCryptoKey,
  ): Promise<(string | null)[]> {
    if (encStrings.length === 0) return [];

    // Short-circuit: nothing to decrypt if all items are null
    if (encStrings.every((es) => !es)) {
      return new Array(encStrings.length).fill(null);
    }

    // Cooldown after recent ORK failure
    if (Date.now() < this._orkDecryptCooldownUntil) {
      throw new Error("ORK decrypt temporarily disabled after recent failure");
    }

    await this.tideCloakService.ensureInitialized();

    // Split into TideCloak items (batched) vs AES items (parallel)
    const results: (string | null)[] = new Array(encStrings.length).fill(null);
    const tidePolicyItems: { idx: number; bytes: Uint8Array }[] = [];
    const tideOrkItems: { idx: number; bytes: Uint8Array }[] = [];
    const aesItems: { idx: number; encString: EncString }[] = [];

    const skipOrk = this.tideCloakService.shouldSkipOrkDecrypt();

    for (let i = 0; i < encStrings.length; i++) {
      const es = encStrings[i];
      if (!es) continue;
      if (es.encryptionType === EncryptionType.TideCloakOrkPolicy) {
        if (!skipOrk) tidePolicyItems.push({ idx: i, bytes: Utils.fromB64ToArray(es.data) });
        // else: stays null — bulk vault load skips ORK-encrypted sensitive fields
      } else if (es.encryptionType === EncryptionType.TideCloakOrk) {
        if (!skipOrk) tideOrkItems.push({ idx: i, bytes: Utils.fromB64ToArray(es.data) });
      } else if (es.encryptionType === EncryptionType.Plaintext) {
        results[i] = new TextDecoder().decode(Utils.fromB64ToArray(es.data));
      } else {
        aesItems.push({ idx: i, encString: es });
      }
    }

    const isInitialized = this.tideCloakService.isInitialized();
    const decoder = new TextDecoder();

    // Batch: policy-encrypted — one ORK call for all items sharing the same policy
    if (tidePolicyItems.length > 0) {
      const { tags, policy } = this.getDecryptionContext();
      if (policy && isInitialized) {
        try {
          const decrypted = await this.tideCloakService.decryptBatch(
            tidePolicyItems.map((p) => ({ encrypted: p.bytes, tags })),
            policy,
          );
          tidePolicyItems.forEach((p, i) => {
            results[p.idx] = decoder.decode(decrypted[i]);
          });
        } catch (e) {
          this.logService.error(`[TideCloakEncrypt] ORK policy batch decryption failed: ${e}`);
          this._orkDecryptCooldownUntil = Date.now() + 10_000;
          throw new Error("TideCloak decryption failed. Please try again or re-login.");
        }
      }
      // No policy scope or enclave not ready: results stay null
    }

    // Batch: self-encrypted (legacy selfencrypt/selfdecrypt realm roles)
    if (tideOrkItems.length > 0 && isInitialized) {
      try {
        const decrypted = await this.tideCloakService.decryptBatch(
          tideOrkItems.map((p) => ({ encrypted: p.bytes, tags: ["vaultwarden"] })),
        );
        tideOrkItems.forEach((p, i) => {
          results[p.idx] = decoder.decode(decrypted[i]);
        });
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK batch decryption failed: ${e}`);
        this._orkDecryptCooldownUntil = Date.now() + 10_000;
        throw new Error("TideCloak decryption failed. Please try again or re-login.");
      }
    }

    // AES items in parallel
    if (aesItems.length > 0) {
      const decrypted = await Promise.all(
        aesItems.map(({ encString }) => super.decryptString(encString, key)),
      );
      aesItems.forEach(({ idx }, i) => {
        results[idx] = decrypted[i];
      });
    }

    return results;
  }

  override async encryptString(
    plainValue: string,
    key: SymmetricCryptoKey,
  ): Promise<EncString> {
    if (plainValue == null) {
      return null;
    }

    // Non-sensitive fields (names) bypass ORK so all org members can decrypt
    if (this.tideCloakService.shouldSkipOrkEncrypt()) {
      return super.encryptString(plainValue, key);
    }

    await this.tideCloakService.ensureInitialized();

    if (this.tideCloakService.isInitialized()) {
      try {
        const bytes = new TextEncoder().encode(plainValue);
        const { tags, policy } = this.getEncryptionContext();
        const encrypted = await this.tideCloakService.encrypt(bytes, tags, policy);
        const b64 = Utils.fromBufferToB64(encrypted);
        const encType = policy ? EncryptionType.TideCloakOrkPolicy : EncryptionType.TideCloakOrk;
        return new EncString(encType, b64);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK encryption failed: ${e}`);
        throw new Error(
          "TideCloak encryption failed. Your data could not be encrypted securely.",
        );
      }
    }

    return super.encryptString(plainValue, key);
  }

  override async encryptBytes(
    plainValue: Uint8Array,
    key: SymmetricCryptoKey,
  ): Promise<EncString> {
    await this.tideCloakService.ensureInitialized();

    if (this.tideCloakService.isInitialized()) {
      try {
        const { tags, policy } = this.getEncryptionContext();
        const encrypted = await this.tideCloakService.encrypt(plainValue, tags, policy);
        const b64 = Utils.fromBufferToB64(encrypted);
        const encType = policy ? EncryptionType.TideCloakOrkPolicy : EncryptionType.TideCloakOrk;
        return new EncString(encType, b64);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK byte encryption failed: ${e}`);
        throw new Error(
          "TideCloak encryption failed. Your data could not be encrypted securely.",
        );
      }
    }

    return super.encryptBytes(plainValue, key);
  }

  override async decryptString(
    encString: EncString,
    key: SymmetricCryptoKey,
  ): Promise<string> {
    // Plaintext type: just decode base64, no decryption needed
    if (encString.encryptionType === EncryptionType.Plaintext) {
      const bytes = Utils.fromB64ToArray(encString.data);
      return new TextDecoder().decode(bytes);
    }

    if (
      encString.encryptionType === EncryptionType.TideCloakOrk ||
      encString.encryptionType === EncryptionType.TideCloakOrkPolicy
    ) {
      // During bulk vault load, skip ORK decryption — sensitive data stays encrypted in memory
      if (this.tideCloakService.shouldSkipOrkDecrypt()) {
        return null;
      }

      // After a recent ORK decrypt failure, skip immediately so the UI
      // doesn't block on 5s timeout per field
      if (Date.now() < this._orkDecryptCooldownUntil) {
        throw new Error("ORK decrypt temporarily disabled after recent failure");
      }

      // Re-initialize enclave from persisted state if needed
      await this.tideCloakService.ensureInitialized();

      if (!this.tideCloakService.isInitialized()) {
        // Enclave not available (e.g. service worker context) — return null
        // so background tasks (badge, sync) don't crash. On-demand decrypt
        // in popup context will handle actual decryption.
        return null;
      }

      try {
        const bytes = Utils.fromB64ToArray(encString.data);
        // Policy-encrypted data (type 102) requires the crypto policy for decryption.
        // Legacy selfencrypt data (type 100) uses ["vaultwarden"] without a policy.
        const isPolicyEncrypted = encString.encryptionType === EncryptionType.TideCloakOrkPolicy;
        const { tags, policy } = isPolicyEncrypted
          ? this.getDecryptionContext()
          : { tags: ["vaultwarden"], policy: undefined };
        // Policy-encrypted data without a scope set (e.g. list preview) — can't decrypt
        // without the correct tags+policy, so return null instead of crashing
        if (isPolicyEncrypted && !policy) {
          return null;
        }
        const decrypted = await this.tideCloakService.decrypt(bytes, tags, policy);
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK decryption failed: ${e}`);
        // Skip subsequent ORK decrypts for 10s so remaining fields fail instantly
        this._orkDecryptCooldownUntil = Date.now() + 10_000;
        throw new Error(
          "TideCloak decryption failed. Please try again or re-login.",
        );
      }
    }

    // For any other encryption type (e.g. AES), use parent
    return super.decryptString(encString, key);
  }

  override async decryptBytes(
    encString: EncString,
    key: SymmetricCryptoKey,
  ): Promise<Uint8Array> {
    // Plaintext type: just decode base64
    if (encString.encryptionType === EncryptionType.Plaintext) {
      return Utils.fromB64ToArray(encString.data);
    }

    if (
      encString.encryptionType === EncryptionType.TideCloakOrk ||
      encString.encryptionType === EncryptionType.TideCloakOrkPolicy
    ) {
      // During bulk vault load, skip ORK decryption — sensitive data stays encrypted in memory
      if (this.tideCloakService.shouldSkipOrkDecrypt()) {
        return null;
      }

      // After a recent ORK decrypt failure, skip immediately
      if (Date.now() < this._orkDecryptCooldownUntil) {
        throw new Error("ORK decrypt temporarily disabled after recent failure");
      }

      // Re-initialize enclave from persisted state if needed
      await this.tideCloakService.ensureInitialized();

      if (!this.tideCloakService.isInitialized()) {
        // Enclave not available — return null (same as skipOrkDecrypt)
        return null;
      }

      try {
        const bytes = Utils.fromB64ToArray(encString.data);
        const isPolicyEncrypted = encString.encryptionType === EncryptionType.TideCloakOrkPolicy;
        const { tags, policy } = isPolicyEncrypted
          ? this.getDecryptionContext()
          : { tags: ["vaultwarden"], policy: undefined };
        // Policy-encrypted data without a scope set — can't decrypt without correct tags+policy
        if (isPolicyEncrypted && !policy) {
          return null;
        }
        return await this.tideCloakService.decrypt(bytes, tags, policy);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK byte decryption failed: ${e}`);
        this._orkDecryptCooldownUntil = Date.now() + 10_000;
        throw new Error(
          "TideCloak decryption failed. Please try again or re-login.",
        );
      }
    }

    // For any other encryption type (e.g. AES), use parent
    return super.decryptBytes(encString, key);
  }

  /**
   * Returns tags and policy for encryption based on the current scope.
   * Org ciphers use collection-scoped tags + crypto policy (PolicyEnabledEncryption).
   * Personal vault ciphers use ["vaultwarden"] tags (selfencrypt).
   */
  private getEncryptionContext(): { tags: string[]; policy?: Uint8Array } {
    const scope = this.tideCloakService.getEncryptionScope();
    if (scope) {
      const tags = scope.collectionIds.map(
        (cid) => `org:${scope.orgId}:collection:${cid}`,
      );
      console.info(`[TideCloakEncrypt] getEncryptionContext: scope SET, tags=${JSON.stringify(tags)}, policyLen=${scope.policy?.length}`);
      return { tags, policy: scope.policy };
    }
    console.info(`[TideCloakEncrypt] getEncryptionContext: NO scope, using default tags=["vaultwarden"]`);
    return { tags: ["vaultwarden"] };
  }

  /**
   * Returns tags and policy for decryption based on the current scope.
   * Org ciphers use collection-scoped tags + crypto policy (PolicyEnabledDecryption).
   * Personal vault ciphers use ["vaultwarden"] tags (selfdecrypt).
   */
  private getDecryptionContext(): { tags: string[]; policy?: Uint8Array } {
    const scope = this.tideCloakService.getEncryptionScope();
    if (scope) {
      const tags = scope.collectionIds.map(
        (cid) => `org:${scope.orgId}:collection:${cid}`,
      );
      return { tags, policy: scope.policy };
    }
    return { tags: ["vaultwarden"] };
  }

  override async withoutOrk<T>(fn: () => Promise<T>): Promise<T> {
    this.tideCloakService.setSkipOrkEncrypt(true);
    try {
      return await fn();
    } finally {
      this.tideCloakService.setSkipOrkEncrypt(false);
    }
  }

  // encryptFileData / decryptFileData: inherited (standard AES — files can be large)
  // All key wrap/unwrap/encapsulate methods: inherited (standard AES)
  // hash: inherited
}
