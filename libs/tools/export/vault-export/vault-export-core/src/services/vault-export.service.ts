import { firstValueFrom, Observable, of } from "rxjs";

import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { UserId, OrganizationId } from "@bitwarden/common/types/guid";

import { ExportedVault } from "../types";

import { IndividualVaultExportServiceAbstraction } from "./individual-vault-export.service.abstraction";
import { OrganizationVaultExportServiceAbstraction } from "./org-vault-export.service.abstraction";
import {
  ExportFormat,
  ExportFormatMetadata,
  FormatOptions,
  VaultExportServiceAbstraction,
} from "./vault-export.service.abstraction";

export class VaultExportService implements VaultExportServiceAbstraction {
  constructor(
    private individualVaultExportService: IndividualVaultExportServiceAbstraction,
    private organizationVaultExportService: OrganizationVaultExportServiceAbstraction,
    private accountService: AccountService,
  ) {}

  /** Creates an export of an individual vault (My vault). Based on the provided format it will either be unencrypted or encrypted via TideCloak
   * @param userId The userId of the account requesting the export
   * @param format The format of the export
   * @returns The exported vault
   */
  async getExport(
    userId: UserId,
    format: ExportFormat = "csv",
  ): Promise<ExportedVault> {
    await this.checkForImpersonation(userId);

    return this.individualVaultExportService.getExport(userId, format);
  }

  /** Creates an export of an organizational vault. Based on the provided format it will either be unencrypted or encrypted via TideCloak
   * @param userId The userId of the account requesting the export
   * @param organizationId The organization id
   * @param format The format of the export
   * @param onlyManagedCollections If true only managed collections will be exported
   * @returns The exported vault
   */
  async getOrganizationExport(
    userId: UserId,
    organizationId: OrganizationId,
    format: ExportFormat,
    onlyManagedCollections = false,
  ): Promise<ExportedVault> {
    await this.checkForImpersonation(userId);

    return this.organizationVaultExportService.getOrganizationExport(
      userId,
      organizationId,
      format,
      onlyManagedCollections,
    );
  }

  /**
   * Get available export formats based on vault context
   * @param options Options determining which formats are available
   * @returns Observable stream of available export formats
   */
  formats$(options: FormatOptions): Observable<ExportFormatMetadata[]> {
    const baseFormats: ExportFormatMetadata[] = [
      { name: ".json", format: "json" },
      { name: ".csv", format: "csv" },
      { name: ".json (Encrypted)", format: "encrypted_json" },
    ];

    // ZIP format with attachments is only available for individual vault exports
    if (options.isMyVault) {
      return of([...baseFormats, { name: ".zip (with attachments)", format: "zip" }]);
    }

    return of(baseFormats);
  }

  /** Checks if the provided userId matches the currently authenticated user
   * @param userId The userId to check
   * @throws Error if the userId does not match the currently authenticated user
   */
  private async checkForImpersonation(userId: UserId): Promise<void> {
    const currentUserId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
    if (userId !== currentUserId) {
      throw new Error("UserId does not match the currently authenticated user");
    }
  }
}
