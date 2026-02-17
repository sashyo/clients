import { Directive, HostBinding, HostListener, Input, OnChanges, Optional } from "@angular/core";
import { firstValueFrom } from "rxjs";

import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { uuidAsString } from "@bitwarden/common/platform/abstractions/sdk/sdk.service";
import { EncryptionType } from "@bitwarden/common/platform/enums";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { Cipher } from "@bitwarden/common/vault/models/domain/cipher";
import {
  CipherViewLike,
  CipherViewLikeUtils,
} from "@bitwarden/common/vault/utils/cipher-view-like-utils";
import { MenuItemComponent, BitIconButtonComponent } from "@bitwarden/components";
import { CopyAction, CopyCipherFieldService } from "@bitwarden/vault";

/**
 * Directive to copy a specific field from a cipher on click. Uses the `CopyCipherFieldService` to
 * handle the copying of the field and any necessary password re-prompting or totp generation.
 *
 * Automatically disables the host element if the field to copy is not available or null.
 *
 * If the host element is a menu item, it will be hidden when disabled.
 *
 * @example
 * ```html
 * <button appCopyField="username" [cipher]="cipher">Copy Username</button>
 * ```
 */
@Directive({
  selector: "[appCopyField]",
})
export class CopyCipherFieldDirective implements OnChanges {
  // FIXME(https://bitwarden.atlassian.net/browse/CL-903): Migrate to Signals
  // eslint-disable-next-line @angular-eslint/prefer-signals
  @Input({
    alias: "appCopyField",
    required: true,
  })
  action!: CopyAction;

  // FIXME(https://bitwarden.atlassian.net/browse/CL-903): Migrate to Signals
  // eslint-disable-next-line @angular-eslint/prefer-signals
  @Input({ required: true })
  cipher!: CipherViewLike;

  constructor(
    private copyCipherFieldService: CopyCipherFieldService,
    private accountService: AccountService,
    private cipherService: CipherService,
    @Optional() private menuItemComponent?: MenuItemComponent,
    @Optional() private iconButtonComponent?: BitIconButtonComponent,
  ) {}

  @HostBinding("attr.disabled")
  protected disabled: boolean | null = null;

  /**
   * Hide the element if it is disabled and is a menu item.
   * @private
   */
  @HostBinding("class.tw-hidden")
  private get hidden() {
    return this.disabled && this.menuItemComponent;
  }

  @HostListener("click")
  async copy() {
    const value = await this.getValueToCopy();
    await this.copyCipherFieldService.copy(value ?? "", this.action, this.cipher);
  }

  async ngOnChanges() {
    await this.updateDisabledState();
  }

  private async updateDisabledState() {
    this.disabled =
      !this.cipher ||
      !(await this.hasValueToCopy()) ||
      (this.action === "totp" && !(await this.copyCipherFieldService.totpAllowed(this.cipher)))
        ? true
        : null;

    // When used on an icon button, update the disabled state of the button component
    if (this.iconButtonComponent) {
      this.iconButtonComponent.disabled.set(this.disabled ?? false);
    }

    // If the directive is used on a menu item, update the menu item to prevent keyboard navigation
    if (this.menuItemComponent) {
      this.menuItemComponent.disabled = this.disabled ?? false;
    }
  }

  /**
   * Returns `true` when the cipher has the associated value as populated.
   * For ORK-encrypted fields (type 100), the decrypted CipherView may show null
   * during bulk load. In that case, check the encrypted cipher's EncString fields.
   */
  private async hasValueToCopy(): Promise<boolean> {
    // Fast path: check cached decrypted value
    if (CipherViewLikeUtils.hasCopyableValue(this.cipher, this.action)) {
      return true;
    }

    // For CipherListView, trust the SDK's copyableFields
    if (CipherViewLikeUtils.isCipherListView(this.cipher)) {
      return false;
    }

    // The cached CipherView has null for this field — check if the encrypted
    // cipher has an ORK-encrypted (type 100) EncString for it
    try {
      const activeAccountId = await firstValueFrom(
        this.accountService.activeAccount$.pipe(getUserId),
      );
      const encryptedCipher = await this.cipherService.get(
        uuidAsString(this.cipher.id!),
        activeAccountId,
      );
      if (!encryptedCipher) {
        return false;
      }
      return this.hasOrkEncryptedField(encryptedCipher);
    } catch {
      return false;
    }
  }

  /**
   * Checks if the encrypted cipher has an ORK-encrypted (type 100) EncString
   * for the current copy action. This handles the case where bulk decryption
   * skipped ORK fields, leaving them null in the CipherView.
   */
  private hasOrkEncryptedField(cipher: Cipher): boolean {
    const isOrk = (enc: { encryptionType?: number } | null | undefined) =>
      enc?.encryptionType === EncryptionType.TideCloakOrk;

    switch (this.action) {
      case "username":
        return isOrk(cipher.login?.username) || isOrk(cipher.identity?.username);
      case "password":
        return isOrk(cipher.login?.password);
      case "totp":
        return isOrk(cipher.login?.totp);
      case "cardNumber":
        return isOrk(cipher.card?.number);
      case "securityCode":
        return isOrk(cipher.card?.code);
      case "email":
        return isOrk(cipher.identity?.email);
      case "phone":
        return isOrk(cipher.identity?.phone);
      case "secureNote":
        return isOrk(cipher.notes);
      case "privateKey":
        return isOrk(cipher.sshKey?.privateKey);
      default:
        return false;
    }
  }

  /**
   * Returns the value of the cipher to be copied.
   * Always fetches from the encrypted store and does fresh decryption
   * to handle ORK-encrypted fields that were null in the cached CipherView.
   */
  private async getValueToCopy() {
    const activeAccountId = await firstValueFrom(
      this.accountService.activeAccount$.pipe(getUserId),
    );
    const encryptedCipher = await this.cipherService.get(
      uuidAsString(this.cipher.id!),
      activeAccountId,
    );
    const _cipher = await this.cipherService.decrypt(encryptedCipher, activeAccountId);

    switch (this.action) {
      case "username":
        return _cipher.login?.username || _cipher.identity?.username;
      case "password":
        return _cipher.login?.password;
      case "totp":
        return _cipher.login?.totp;
      case "cardNumber":
        return _cipher.card?.number;
      case "securityCode":
        return _cipher.card?.code;
      case "email":
        return _cipher.identity?.email;
      case "phone":
        return _cipher.identity?.phone;
      case "address":
        return _cipher.identity?.fullAddressForCopy;
      case "secureNote":
        return _cipher.notes;
      case "privateKey":
        return _cipher.sshKey?.privateKey;
      case "publicKey":
        return _cipher.sshKey?.publicKey;
      case "keyFingerprint":
        return _cipher.sshKey?.keyFingerprint;
      default:
        return null;
    }
  }
}
