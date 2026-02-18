// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { OptionValues } from "commander";
import { firstValueFrom, switchMap } from "rxjs";

import { EventCollectionService } from "@bitwarden/common/abstractions/event/event-collection.service";
import { PolicyService } from "@bitwarden/common/admin-console/abstractions/policy/policy.service.abstraction";
import { PolicyType } from "@bitwarden/common/admin-console/enums";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { EventType } from "@bitwarden/common/enums";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import {
  ExportFormat,
  EXPORT_FORMATS,
  VaultExportServiceAbstraction,
  ExportedVault,
  ExportedVaultAsBlob,
} from "@bitwarden/vault-export-core";

import { Response } from "../models/response";
import { CliUtils } from "../utils";

export class ExportCommand {
  constructor(
    private exportService: VaultExportServiceAbstraction,
    private policyService: PolicyService,
    private eventCollectionService: EventCollectionService,
    private accountService: AccountService,
  ) {}

  async run(options: OptionValues): Promise<Response> {
    const policyApplies$ = this.accountService.activeAccount$.pipe(
      getUserId,
      switchMap((userId) =>
        this.policyService.policyAppliesToUser$(PolicyType.DisablePersonalVaultExport, userId),
      ),
    );

    if (options.organizationid == null && (await firstValueFrom(policyApplies$))) {
      return Response.badRequest(
        "One or more organization policies prevents you from exporting your personal vault.",
      );
    }

    const format = options.format ?? "csv";

    if (!this.isSupportedExportFormat(format)) {
      return Response.badRequest(
        `'${format}' is not a supported export format. Supported formats: ${EXPORT_FORMATS.join(
          ", ",
        )}.`,
      );
    }

    if (options.organizationid != null && !Utils.isGuid(options.organizationid)) {
      return Response.error("`" + options.organizationid + "` is not a GUID.");
    }

    let exportContent: ExportedVault = null;
    try {
      const userId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));

      exportContent =
        options.organizationid == null
          ? await this.exportService.getExport(userId, format)
          : await this.exportService.getOrganizationExport(
              userId,
              options.organizationid,
              format,
            );

      const eventType = options.organizationid
        ? EventType.Organization_ClientExportedVault
        : EventType.User_ClientExportedVault;
      // FIXME: Verify that this floating promise is intentional. If it is, add an explanatory comment and ensure there is proper error handling.
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      this.eventCollectionService.collect(eventType, null, true, options.organizationid);
    } catch (e) {
      return Response.error(e);
    }
    return await this.saveFile(exportContent, options);
  }

  private async saveFile(exportContent: ExportedVault, options: OptionValues): Promise<Response> {
    try {
      if (exportContent.type === "application/zip") {
        exportContent = exportContent as ExportedVaultAsBlob;
        const arrayBuffer = await exportContent.data.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        return await CliUtils.saveResultToFile(buffer, options.output, exportContent.fileName);
      }

      return await CliUtils.saveResultToFile(
        exportContent.data,
        options.output,
        exportContent.fileName,
      );
    } catch (e) {
      return Response.error(e.toString());
    }
  }

  private isSupportedExportFormat(format: string): format is ExportFormat {
    return EXPORT_FORMATS.includes(format as ExportFormat);
  }
}
