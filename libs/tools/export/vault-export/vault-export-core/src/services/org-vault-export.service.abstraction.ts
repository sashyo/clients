import { UserId, OrganizationId } from "@bitwarden/common/types/guid";

import { ExportedVaultAsString } from "../types";

import { ExportFormat } from "./vault-export.service.abstraction";

export abstract class OrganizationVaultExportServiceAbstraction {
  abstract getOrganizationExport: (
    userId: UserId,
    organizationId: OrganizationId,
    format: ExportFormat,
    onlyManagedCollections: boolean,
  ) => Promise<ExportedVaultAsString>;
}
