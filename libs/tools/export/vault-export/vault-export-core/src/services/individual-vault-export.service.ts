// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import * as JSZip from "jszip";
import * as papa from "papaparse";
import { firstValueFrom } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { EncryptService } from "@bitwarden/common/key-management/crypto/abstractions/encrypt.service";
import { CipherWithIdExport, FolderWithIdExport } from "@bitwarden/common/models/export";
import { CipherId, UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { FolderService } from "@bitwarden/common/vault/abstractions/folder/folder.service.abstraction";
import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FolderView } from "@bitwarden/common/vault/models/view/folder.view";
import { RestrictedItemTypesService } from "@bitwarden/common/vault/services/restricted-item-types.service";

import {
  BitwardenCsvIndividualExportType,
  BitwardenTideCloakEncryptedFileFormat,
  BitwardenUnEncryptedIndividualJsonExport,
  ExportedVault,
  ExportedVaultAsBlob,
  ExportedVaultAsString,
} from "../types";

import { BaseVaultExportService } from "./base-vault-export.service";
import { ExportHelper } from "./export-helper";
import { IndividualVaultExportServiceAbstraction } from "./individual-vault-export.service.abstraction";
import { ExportFormat } from "./vault-export.service.abstraction";

export class IndividualVaultExportService
  extends BaseVaultExportService
  implements IndividualVaultExportServiceAbstraction
{
  constructor(
    private folderService: FolderService,
    private cipherService: CipherService,
    encryptService: EncryptService,
    private apiService: ApiService,
    private restrictedItemTypesService: RestrictedItemTypesService,
  ) {
    super(encryptService);
  }

  async getExport(userId: UserId, format: ExportFormat = "csv"): Promise<ExportedVault> {
    if (format === "encrypted_json") {
      return this.getEncryptedExport(userId);
    } else if (format === "zip") {
      return this.getDecryptedExportZip(userId);
    }
    return this.getDecryptedExport(userId, format);
  }

  async getDecryptedExportZip(activeUserId: UserId): Promise<ExportedVaultAsBlob> {
    const zip = new JSZip();

    const exportedVault = await this.getDecryptedExport(activeUserId, "json");
    zip.file("data.json", exportedVault.data);

    const attachmentsFolder = zip.folder("attachments");
    if (attachmentsFolder == null) {
      throw new Error("Error creating attachments folder");
    }

    for (const cipher of await this.cipherService.getAllDecrypted(activeUserId)) {
      if (
        !cipher.attachments ||
        cipher.attachments.length === 0 ||
        cipher.deletedDate != null ||
        cipher.organizationId != null
      ) {
        continue;
      }

      const cipherFolder = attachmentsFolder.folder(cipher.id);
      for (const attachment of cipher.attachments) {
        const response = await this.downloadAttachment(cipher.id, attachment.id);

        try {
          const decBuf = await this.cipherService.getDecryptedAttachmentBuffer(
            cipher.id as CipherId,
            attachment,
            response,
            activeUserId,
          );

          cipherFolder.file(attachment.fileName, decBuf);
        } catch {
          throw new Error("Error decrypting attachment");
        }
      }
    }

    const blobData = await zip.generateAsync({ type: "blob" });

    return {
      type: "application/zip",
      data: blobData,
      fileName: ExportHelper.getFileName("", "zip"),
    } as ExportedVaultAsBlob;
  }

  private async downloadAttachment(cipherId: string, attachmentId: string): Promise<Response> {
    const attachmentDownloadResponse = await this.apiService.getAttachmentData(
      cipherId,
      attachmentId,
    );
    const url = attachmentDownloadResponse.url;

    const response = await fetch(new Request(url, { cache: "no-store" }));
    if (response.status !== 200) {
      throw new Error("Error downloading attachment");
    }
    return response;
  }

  private async getDecryptedExport(
    activeUserId: UserId,
    format: "json" | "csv",
  ): Promise<ExportedVaultAsString> {
    let decFolders: FolderView[] = [];
    let decCiphers: CipherView[] = [];
    const promises = [];

    promises.push(
      firstValueFrom(this.folderService.folderViews$(activeUserId)).then((folders) => {
        decFolders = folders;
      }),
    );

    const restrictions = await firstValueFrom(this.restrictedItemTypesService.restricted$);

    promises.push(
      this.cipherService.getAllDecrypted(activeUserId).then((ciphers) => {
        decCiphers = ciphers.filter(
          (f) =>
            f.deletedDate == null &&
            !this.restrictedItemTypesService.isCipherRestricted(f, restrictions),
        );
      }),
    );

    await Promise.all(promises);

    if (format === "csv") {
      return {
        type: "text/plain",
        data: this.buildCsvExport(decFolders, decCiphers),
        fileName: ExportHelper.getFileName("", "csv"),
      } as ExportedVaultAsString;
    }

    return {
      type: "text/plain",
      data: this.buildJsonExport(decFolders, decCiphers),
      fileName: ExportHelper.getFileName("", "json"),
    } as ExportedVaultAsString;
  }

  private async getEncryptedExport(activeUserId: UserId): Promise<ExportedVaultAsString> {
    if (!activeUserId) {
      throw new Error("User ID must not be null or undefined");
    }

    // Get the decrypted JSON export, then encrypt the whole thing via TideCloak ORK
    const decryptedExport = await this.getDecryptedExport(activeUserId, "json");
    const encData = await this.encryptService.encryptString(decryptedExport.data, null);

    const jsonDoc: BitwardenTideCloakEncryptedFileFormat = {
      encrypted: true,
      tideCloakEncrypted: true,
      data: encData.encryptedString,
    };

    return {
      type: "text/plain",
      data: JSON.stringify(jsonDoc, null, "  "),
      fileName: ExportHelper.getFileName("", "encrypted_json"),
    } as ExportedVaultAsString;
  }

  private buildCsvExport(decFolders: FolderView[], decCiphers: CipherView[]): string {
    const foldersMap = new Map<string, FolderView>();
    decFolders.forEach((f) => {
      if (f.id) {
        foldersMap.set(f.id, f);
      }
    });

    const exportCiphers: BitwardenCsvIndividualExportType[] = [];
    decCiphers.forEach((c) => {
      // only export logins and secure notes
      if (c.type !== CipherType.Login && c.type !== CipherType.SecureNote) {
        return;
      }
      if (c.organizationId != null) {
        return;
      }

      const cipher = {} as BitwardenCsvIndividualExportType;
      cipher.folder =
        c.folderId != null && foldersMap.has(c.folderId) ? foldersMap.get(c.folderId).name : null;
      cipher.favorite = c.favorite ? 1 : null;
      this.buildCommonCipher(cipher, c);
      exportCiphers.push(cipher);
    });

    return papa.unparse(exportCiphers);
  }

  private buildJsonExport(decFolders: FolderView[], decCiphers: CipherView[]): string {
    const jsonDoc: BitwardenUnEncryptedIndividualJsonExport = {
      encrypted: false,
      folders: [],
      items: [],
    };

    decFolders.forEach((f) => {
      if (!f.id) {
        return;
      }
      const folder = new FolderWithIdExport();
      folder.build(f);
      jsonDoc.folders.push(folder);
    });

    decCiphers.forEach((c) => {
      if (c.organizationId != null) {
        return;
      }
      const cipher = new CipherWithIdExport();
      cipher.build(c);
      cipher.collectionIds = null;
      delete cipher.key;
      jsonDoc.items.push(cipher);
    });

    return JSON.stringify(jsonDoc, null, "  ");
  }
}
