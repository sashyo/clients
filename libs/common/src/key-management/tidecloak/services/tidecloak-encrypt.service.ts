import { LogService } from "../../../platform/abstractions/log.service";
import { EncryptionType } from "../../../platform/enums";
import { Utils } from "../../../platform/misc/utils";
import { SymmetricCryptoKey } from "../../../platform/models/domain/symmetric-crypto-key";
import { CryptoFunctionService } from "../../crypto/abstractions/crypto-function.service";
import { EncString } from "../../crypto/models/enc-string";
import { EncryptServiceImplementation } from "../../crypto/services/encrypt.service.implementation";
import { TideCloakService } from "../abstractions/tidecloak.service";

/**
 * EncryptService that routes data encryption/decryption through the TideCloak ORK
 * when the enclave is available.
 *
 * When the ORK enclave is not available (e.g. service worker context),
 * encrypt falls through to standard AES and decrypt returns null for type 100.
 *
 * Key management methods (wrap/unwrap/encapsulate) are inherited unchanged.
 */
export class TideCloakEncryptService extends EncryptServiceImplementation {
  constructor(
    cryptoFunctionService: CryptoFunctionService,
    logService: LogService,
    logMacFailures: boolean,
    private tideCloakService: TideCloakService,
  ) {
    super(cryptoFunctionService, logService, logMacFailures);
  }

  override async encryptString(
    plainValue: string,
    key: SymmetricCryptoKey,
  ): Promise<EncString> {
    if (plainValue == null) {
      return null;
    }

    // Re-initialize enclave from persisted state if needed (e.g. after page refresh)
    await this.tideCloakService.ensureInitialized();

    if (this.tideCloakService.isInitialized()) {
      try {
        const bytes = new TextEncoder().encode(plainValue);
        const encrypted = await this.tideCloakService.encrypt(bytes, ["vaultwarden"]);
        const b64 = Utils.fromBufferToB64(encrypted);
        return new EncString(EncryptionType.TideCloakOrk, b64);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK encryption failed: ${e}`);
        throw new Error(
          "TideCloak encryption failed. Your data could not be encrypted securely.",
        );
      }
    }

    // Enclave not available (e.g. service worker) — fall through to AES
    return super.encryptString(plainValue, key);
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

    if (encString.encryptionType === EncryptionType.TideCloakOrk) {
      // During bulk vault load, skip ORK decryption — sensitive data stays encrypted in memory
      if (this.tideCloakService.shouldSkipOrkDecrypt()) {
        return null;
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
        const decrypted = await this.tideCloakService.decrypt(bytes, ["vaultwarden"]);
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK decryption failed: ${e}`);
        throw new Error(
          "TideCloak decryption failed. Please try again or re-login.",
        );
      }
    }

    // For any other encryption type (e.g. AES), use parent
    return super.decryptString(encString, key);
  }

  override async encryptBytes(
    plainValue: Uint8Array,
    key: SymmetricCryptoKey,
  ): Promise<EncString> {
    // Re-initialize enclave from persisted state if needed
    await this.tideCloakService.ensureInitialized();

    if (this.tideCloakService.isInitialized()) {
      try {
        const encrypted = await this.tideCloakService.encrypt(plainValue, ["vaultwarden"]);
        const b64 = Utils.fromBufferToB64(encrypted);
        return new EncString(EncryptionType.TideCloakOrk, b64);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK byte encryption failed: ${e}`);
        throw new Error(
          "TideCloak encryption failed. Your data could not be encrypted securely.",
        );
      }
    }

    // Enclave not available — fall through to AES
    return super.encryptBytes(plainValue, key);
  }

  override async decryptBytes(
    encString: EncString,
    key: SymmetricCryptoKey,
  ): Promise<Uint8Array> {
    // Plaintext type: just decode base64
    if (encString.encryptionType === EncryptionType.Plaintext) {
      return Utils.fromB64ToArray(encString.data);
    }

    if (encString.encryptionType === EncryptionType.TideCloakOrk) {
      // During bulk vault load, skip ORK decryption — sensitive data stays encrypted in memory
      if (this.tideCloakService.shouldSkipOrkDecrypt()) {
        return null;
      }

      // Re-initialize enclave from persisted state if needed
      await this.tideCloakService.ensureInitialized();

      if (!this.tideCloakService.isInitialized()) {
        // Enclave not available — return null (same as skipOrkDecrypt)
        return null;
      }

      try {
        const bytes = Utils.fromB64ToArray(encString.data);
        return await this.tideCloakService.decrypt(bytes, ["vaultwarden"]);
      } catch (e) {
        this.logService.error(`[TideCloakEncrypt] ORK byte decryption failed: ${e}`);
        throw new Error(
          "TideCloak decryption failed. Please try again or re-login.",
        );
      }
    }

    // For any other encryption type (e.g. AES), use parent
    return super.decryptBytes(encString, key);
  }

  // encryptFileData / decryptFileData: inherited (standard AES — files can be large)
  // All key wrap/unwrap/encapsulate methods: inherited (standard AES)
  // hash: inherited
}
