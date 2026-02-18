import { mock, MockProxy } from "jest-mock-extended";

import { Utils } from "@bitwarden/common/platform/misc/utils";
import { FakeAccountService, mockAccountServiceWith } from "@bitwarden/common/spec";
import { OrganizationId, UserId } from "@bitwarden/common/types/guid";

import { IndividualVaultExportServiceAbstraction } from "./individual-vault-export.service.abstraction";
import { OrganizationVaultExportServiceAbstraction } from "./org-vault-export.service.abstraction";
import { VaultExportService } from "./vault-export.service";

/** Tests the vault export service which handles exporting both individual and organizational vaults */
describe("VaultExportService", () => {
  let service: VaultExportService;
  let individualVaultExportService: MockProxy<IndividualVaultExportServiceAbstraction>;
  let organizationVaultExportService: MockProxy<OrganizationVaultExportServiceAbstraction>;
  let accountService: FakeAccountService;
  const mockUserId = Utils.newGuid() as UserId;
  const mockOrganizationId = Utils.newGuid() as OrganizationId;

  beforeEach(() => {
    individualVaultExportService = mock<IndividualVaultExportServiceAbstraction>();
    organizationVaultExportService = mock<OrganizationVaultExportServiceAbstraction>();
    accountService = mockAccountServiceWith(mockUserId);

    service = new VaultExportService(
      individualVaultExportService,
      organizationVaultExportService,
      accountService,
    );
  });

  describe("getExport", () => {
    it("calls checkForImpersonation with userId", async () => {
      const spy = jest.spyOn(service as any, "checkForImpersonation");

      await service.getExport(mockUserId, "json");
      expect(spy).toHaveBeenCalledWith(mockUserId);
    });

    it("validates the given userId matches the current authenticated user", async () => {
      const anotherUserId = "another-user-id" as UserId;

      await expect(service.getExport(anotherUserId, "json")).rejects.toThrow(
        "UserId does not match the currently authenticated user",
      );

      expect(individualVaultExportService.getExport).not.toHaveBeenCalledWith(mockUserId, "json");
    });

    it("calls getExport with json format", async () => {
      await service.getExport(mockUserId, "json");
      expect(individualVaultExportService.getExport).toHaveBeenCalledWith(mockUserId, "json");
    });

    it("uses default format csv if not provided", async () => {
      await service.getExport(mockUserId);
      expect(individualVaultExportService.getExport).toHaveBeenCalledWith(mockUserId, "csv");
    });
  });

  describe("getOrganizationExport", () => {
    it("calls checkForImpersonation with userId", async () => {
      const spy = jest.spyOn(service as any, "checkForImpersonation");

      await service.getOrganizationExport(mockUserId, mockOrganizationId, "json");
      expect(spy).toHaveBeenCalledWith(mockUserId);
    });

    it("validates the given userId matches the current authenticated user", async () => {
      const anotherUserId = "another-user-id" as UserId;

      await expect(
        service.getOrganizationExport(anotherUserId, mockOrganizationId, "json"),
      ).rejects.toThrow("UserId does not match the currently authenticated user");

      expect(organizationVaultExportService.getOrganizationExport).not.toHaveBeenCalledWith(
        mockUserId,
        mockOrganizationId,
        "json",
      );
    });

    it("calls getOrganizationExport", async () => {
      await service.getOrganizationExport(mockUserId, mockOrganizationId, "json");
      expect(organizationVaultExportService.getOrganizationExport).toHaveBeenCalledWith(
        mockUserId,
        mockOrganizationId,
        "json",
        false,
      );
    });

    it("passes onlyManagedCollections param", async () => {
      await service.getOrganizationExport(mockUserId, mockOrganizationId, "json", true);
      expect(organizationVaultExportService.getOrganizationExport).toHaveBeenCalledWith(
        mockUserId,
        mockOrganizationId,
        "json",
        true,
      );
    });
  });
});
