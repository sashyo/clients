// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import * as papa from "papaparse";
import { filter, firstValueFrom, map } from "rxjs";

import { CollectionService } from "@bitwarden/admin-console/common";
import {
  CollectionView,
  CollectionDetailsResponse,
  Collection,
  CollectionData,
} from "@bitwarden/common/admin-console/models/collections";
import { EncryptService } from "@bitwarden/common/key-management/crypto/abstractions/encrypt.service";
import { CipherWithIdExport, CollectionWithIdExport } from "@bitwarden/common/models/export";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { OrganizationId, UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherData } from "@bitwarden/common/vault/models/data/cipher.data";
import { Cipher } from "@bitwarden/common/vault/models/domain/cipher";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { RestrictedItemTypesService } from "@bitwarden/common/vault/services/restricted-item-types.service";
import { KeyService } from "@bitwarden/key-management";

import {
  BitwardenCsvOrgExportType,
  BitwardenTideCloakEncryptedFileFormat,
  BitwardenUnEncryptedOrgJsonExport,
  ExportedVaultAsString,
} from "../types";

import { VaultExportApiService } from "./api/vault-export-api.service.abstraction";
import { BaseVaultExportService } from "./base-vault-export.service";
import { ExportHelper } from "./export-helper";
import { OrganizationVaultExportServiceAbstraction } from "./org-vault-export.service.abstraction";
import { ExportFormat } from "./vault-export.service.abstraction";

export class OrganizationVaultExportService
  extends BaseVaultExportService
  implements OrganizationVaultExportServiceAbstraction
{
  constructor(
    private cipherService: CipherService,
    private vaultExportApiService: VaultExportApiService,
    private keyService: KeyService,
    encryptService: EncryptService,
    private collectionService: CollectionService,
    private restrictedItemTypesService: RestrictedItemTypesService,
  ) {
    super(encryptService);
  }

  async getOrganizationExport(
    userId: UserId,
    organizationId: OrganizationId,
    format: ExportFormat = "csv",
    onlyManagedCollections: boolean,
  ): Promise<ExportedVaultAsString> {
    if (Utils.isNullOrWhitespace(organizationId)) {
      throw new Error("OrganizationId must be set");
    }

    if (format === "zip") {
      throw new Error("Zip export not supported for organization");
    }

    if (format === "encrypted_json") {
      const decryptedJson = onlyManagedCollections
        ? await this.getDecryptedManagedExport(userId, organizationId, "json")
        : await this.getOrganizationDecryptedExport(userId, organizationId, "json");

      const encData = await this.encryptService.encryptString(decryptedJson, null);

      const jsonDoc: BitwardenTideCloakEncryptedFileFormat = {
        encrypted: true,
        tideCloakEncrypted: true,
        data: encData.encryptedString,
      };

      return {
        type: "text/plain",
        data: JSON.stringify(jsonDoc, null, "  "),
        fileName: ExportHelper.getFileName("org", "encrypted_json"),
      } as ExportedVaultAsString;
    }

    return {
      type: "text/plain",
      data: onlyManagedCollections
        ? await this.getDecryptedManagedExport(userId, organizationId, format)
        : await this.getOrganizationDecryptedExport(userId, organizationId, format),
      fileName: ExportHelper.getFileName("org", format),
    } as ExportedVaultAsString;
  }

  private async getOrganizationDecryptedExport(
    activeUserId: UserId,
    organizationId: OrganizationId,
    format: "json" | "csv",
  ): Promise<string> {
    const decCollections: CollectionView[] = [];
    const decCiphers: CipherView[] = [];
    const promises = [];

    const orgKeys = await firstValueFrom(
      this.keyService.orgKeys$(activeUserId).pipe(filter((orgKeys) => orgKeys != null)),
    );

    const restrictions = await firstValueFrom(this.restrictedItemTypesService.restricted$);

    promises.push(
      this.vaultExportApiService.getOrganizationExport(organizationId).then((exportData) => {
        const exportPromises: Promise<void>[] = [];
        if (exportData != null) {
          if (exportData.collections != null && exportData.collections.length > 0) {
            exportData.collections.forEach((c) => {
              const collection = Collection.fromCollectionData(
                new CollectionData(c as CollectionDetailsResponse),
              );
              const orgKey = orgKeys[organizationId];
              exportPromises.push(
                collection.decrypt(orgKey, this.encryptService).then((decCol) => {
                  decCollections.push(decCol);
                }),
              );
            });
          }
          if (exportData.ciphers != null && exportData.ciphers.length > 0) {
            exportData.ciphers
              .filter((c) => c.deletedDate === null)
              .forEach(async (c) => {
                const cipher = new Cipher(new CipherData(c));
                exportPromises.push(
                  this.cipherService.decrypt(cipher, activeUserId).then((decCipher) => {
                    if (
                      !this.restrictedItemTypesService.isCipherRestricted(decCipher, restrictions)
                    ) {
                      decCiphers.push(decCipher);
                    }
                  }),
                );
              });
          }
        }
        return Promise.all(exportPromises);
      }),
    );

    await Promise.all(promises);

    if (format === "csv") {
      return this.buildCsvExport(decCollections, decCiphers);
    }
    return this.buildJsonExport(decCollections, decCiphers);
  }

  private async getDecryptedManagedExport(
    activeUserId: UserId,
    organizationId: OrganizationId,
    format: "json" | "csv",
  ): Promise<string> {
    let decCiphers: CipherView[] = [];
    let allDecCiphers: CipherView[] = [];
    const promises = [];

    promises.push(
      this.cipherService.getAllDecrypted(activeUserId).then((ciphers) => {
        allDecCiphers = ciphers;
      }),
    );
    await Promise.all(promises);

    const decCollections: CollectionView[] = await firstValueFrom(
      this.collectionService
        .decryptedCollections$(activeUserId)
        .pipe(
          map((collections) =>
            collections.filter((c) => c.organizationId == organizationId && c.manage),
          ),
        ),
    );

    const restrictions = await firstValueFrom(this.restrictedItemTypesService.restricted$);

    decCiphers = allDecCiphers.filter(
      (f) =>
        f.deletedDate == null &&
        f.organizationId == organizationId &&
        decCollections.some((dC) => f.collectionIds.some((cId) => dC.id === cId)) &&
        !this.restrictedItemTypesService.isCipherRestricted(f, restrictions),
    );

    if (format === "csv") {
      return this.buildCsvExport(decCollections, decCiphers);
    }
    return this.buildJsonExport(decCollections, decCiphers);
  }

  private buildCsvExport(decCollections: CollectionView[], decCiphers: CipherView[]): string {
    const collectionsMap = new Map<string, CollectionView>();
    decCollections.forEach((c) => {
      collectionsMap.set(c.id, c);
    });

    const exportCiphers: BitwardenCsvOrgExportType[] = [];
    decCiphers.forEach((c) => {
      if (c.type !== CipherType.Login && c.type !== CipherType.SecureNote) {
        return;
      }

      const cipher = {} as BitwardenCsvOrgExportType;
      cipher.collections = [];
      if (c.collectionIds != null) {
        cipher.collections = c.collectionIds
          .filter((id) => collectionsMap.has(id))
          .map((id) => collectionsMap.get(id).name);
      }
      this.buildCommonCipher(cipher, c);
      exportCiphers.push(cipher);
    });

    return papa.unparse(exportCiphers);
  }

  private buildJsonExport(decCollections: CollectionView[], decCiphers: CipherView[]): string {
    const jsonDoc: BitwardenUnEncryptedOrgJsonExport = {
      encrypted: false,
      collections: [],
      items: [],
    };

    decCollections.forEach((c) => {
      const collection = new CollectionWithIdExport();
      collection.build(c);
      jsonDoc.collections.push(collection);
    });

    decCiphers.forEach((c) => {
      const cipher = new CipherWithIdExport();
      cipher.build(c);
      delete cipher.key;
      jsonDoc.items.push(cipher);
    });
    return JSON.stringify(jsonDoc, null, "  ");
  }
}
