import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import {
  createBackendAdminAPI,
  createBackendCollectionAccessAPI,
  createBackendPolicyAPI,
  createBackendPolicyApprovalsAPI,
  createBackendPolicyLogsAPI,
  createBackendTemplateAPI,
} from "./tide-api.service";
import { ORG_OWNER_CONTRACT } from "./collection-owner-contract";
import { ORG_CRYPTO_CONTRACT } from "./org-crypto-contract";
import {
  loadTideLibs,
  areTideLibsAvailable,
  createSignedPolicyRequest,
  MODEL_IDS,
} from "./tide-policy.service";

@Component({
  selector: "app-org-roles-page",
  template: `<app-react-host [component]="rolesPage" [props]="rolesProps"></app-react-host>`,
  standalone: true,
  imports: [ReactHostComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrgRolesPageComponent implements OnInit {
  rolesPage: any;
  rolesProps: Record<string, any> = {};

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private tideCloakService = inject(TideCloakService);

  ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    const { RolesPage } = require("@tideorg/ui");
    this.rolesPage = RolesPage;

    // Load Tide libs in background — not awaited so props are set synchronously
    loadTideLibs();

    const policyAPI = createBackendPolicyAPI(this.apiService, orgId);
    const policyApprovalsAPI = createBackendPolicyApprovalsAPI(this.apiService, orgId);
    const policyLogsAPI = createBackendPolicyLogsAPI(this.apiService, orgId);
    const collectionAccessAPI = createBackendCollectionAccessAPI(this.apiService, orgId);
    const tideCloakService = this.tideCloakService;
    const templateAPI = createBackendTemplateAPI(this.apiService, orgId);

    const apiService = this.apiService;

    this.rolesProps = {
      adminAPI: createBackendAdminAPI(this.apiService, orgId),
      templateAPI,
      policyAPI,
      policyLogsAPI,
      title: "Roles",
      onRegeneratePolicy: async (roleName: string) => {
        await loadTideLibs();
        await tideCloakService.ensureInitialized();

        if (!areTideLibsAvailable() || !tideCloakService.isInitialized()) {
          throw new Error("Tide libraries or enclave not available");
        }

        // Determine contract code and config based on role
        let contractCode: string;
        let approvalType: "implicit" | "explicit";
        let executionType: "public" | "private";
        let threshold = 1;
        let modelId: string[] | undefined;

        if (roleName === "orgOwner") {
          contractCode = ORG_OWNER_CONTRACT;
          approvalType = "explicit";
          executionType = "public";
        } else if (roleName === "appUser") {
          contractCode = ORG_CRYPTO_CONTRACT;
          approvalType = "implicit";
          executionType = "private";
          modelId = [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION];
        } else {
          // Custom role — fetch existing policy config
          const existingPolicy = await policyAPI.getPolicy(roleName);
          if (!existingPolicy) {
            throw new Error(`No existing policy config found for role "${roleName}"`);
          }
          approvalType = existingPolicy.approvalType || "explicit";
          executionType = existingPolicy.executionType || "public";
          threshold = existingPolicy.threshold || 1;
          if (existingPolicy.templateId) {
            const template = await templateAPI.getTemplate(existingPolicy.templateId);
            contractCode = template?.csCode;
          }
          if (!contractCode) {
            throw new Error(`No contract code found for role "${roleName}"`);
          }
        }

        // Create signed policy request
        const policyConfig: any = {
          roleName,
          threshold,
          approvalType,
          executionType,
          resource: tideCloakService.getResource(),
          vendorId: tideCloakService.getVendorId(),
          contractCode,
        };
        if (modelId) {
          policyConfig.modelId = modelId;
        }

        const { policyRequestBase64 } = await createSignedPolicyRequest(policyConfig, tideCloakService);
        console.info("[TideWarden] [regenerate] Created signed policy request for", roleName, ":", policyRequestBase64.length, "chars");

        // Replace or create the pending approval
        const existingApprovals = await policyApprovalsAPI.getPendingPolicies();
        const existingApproval = existingApprovals.find((a: any) => a.roleId === roleName);

        if (existingApproval) {
          await apiService.send(
            "PUT",
            `/organizations/${orgId}/tide/policy-approvals/${existingApproval.id}/data`,
            { policyRequestData: policyRequestBase64, contractCode },
            true,
            false,
          );
          console.info("[TideWarden] [regenerate] Updated existing approval", existingApproval.id);
        } else {
          await policyApprovalsAPI.createApproval({
            roleId: roleName,
            threshold,
            policyRequestData: policyRequestBase64,
            contractCode,
          });
          console.info("[TideWarden] [regenerate] Created new approval for", roleName);
        }

        // If regenerating orgOwner, also regenerate appUser
        if (roleName === "orgOwner") {
          try {
            await collectionAccessAPI.resetCryptoPolicy();
          } catch {
            // No existing crypto policy — fine
          }
          const { policyRequestBase64: cryptoPolicyBase64 } = await createSignedPolicyRequest(
            {
              roleName: "appUser",
              threshold: 1,
              approvalType: "implicit",
              executionType: "private",
              modelId: [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION],
              resource: tideCloakService.getResource(),
              vendorId: tideCloakService.getVendorId(),
              contractCode: ORG_CRYPTO_CONTRACT,
            },
            tideCloakService,
          );
          const existingAppUser = existingApprovals.find((a: any) => a.roleId === "appUser");
          if (existingAppUser) {
            await apiService.send(
              "PUT",
              `/organizations/${orgId}/tide/policy-approvals/${existingAppUser.id}/data`,
              { policyRequestData: cryptoPolicyBase64, contractCode: ORG_CRYPTO_CONTRACT },
              true,
              false,
            );
          } else {
            await policyApprovalsAPI.createApproval({
              roleId: "appUser",
              threshold: 1,
              policyRequestData: cryptoPolicyBase64,
              contractCode: ORG_CRYPTO_CONTRACT,
            });
          }
          console.info("[TideWarden] [regenerate] appUser crypto policy regenerated alongside orgOwner");
        }

        await policyLogsAPI.addLog({
          policyId: `policy-${roleName}-${Date.now()}`,
          roleId: roleName,
          action: "regenerated",
          performedBy: "admin",
          policyStatus: "pending",
          policyThreshold: threshold,
          approvalCount: 0,
          rejectionCount: 0,
        });

        return { success: true };
      },
      onCreatePolicy: async (params: {
        roleName: string;
        policyConfig: any;
        templateId?: string;
        templateParams?: Record<string, any>;
        threshold: number;
      }) => {
        // Resolve contract code: use built-in contracts for orgOwner/appUser,
        // or fetch from template for custom roles.
        let contractCode: string | undefined;
        if (params.roleName === "orgOwner") {
          contractCode = ORG_OWNER_CONTRACT;
        } else if (params.roleName === "appUser") {
          contractCode = ORG_CRYPTO_CONTRACT;
        } else if (params.templateId) {
          try {
            const template = await templateAPI.getTemplate(params.templateId);
            contractCode = template?.csCode;
          } catch (e) {
            console.error("[TideWarden] Failed to fetch template csCode:", e);
          }
        }

        const approvalType = params.policyConfig?.approvalType || "explicit";
        const executionType = params.policyConfig?.executionType || "public";

        // Save role policy config to backend
        await policyAPI.upsertPolicy({
          roleName: params.roleName,
          enabled: params.policyConfig?.enabled ?? true,
          contractType: params.policyConfig?.contractType || "forseti",
          approvalType,
          executionType,
          threshold: params.threshold,
          templateId: params.templateId,
          templateParams: params.templateParams,
        });

        // Build policyRequestData via Tide signing
        await loadTideLibs();
        await tideCloakService.ensureInitialized();

        let policyRequestData: string | undefined;
        if (contractCode && areTideLibsAvailable() && tideCloakService.isInitialized()) {
          try {
            const { policyRequestBase64 } = await createSignedPolicyRequest(
              {
                roleName: params.roleName,
                threshold: params.threshold,
                approvalType,
                executionType,
                resource: tideCloakService.getResource(),
                vendorId: tideCloakService.getVendorId(),
                contractCode,
                templateParams: params.templateParams,
              },
              tideCloakService,
            );
            policyRequestData = policyRequestBase64;
            console.info("[TideWarden] Created signed policy request for", params.roleName, ":", policyRequestData.length, "chars");
          } catch (e) {
            console.error("[TideWarden] Failed to create signed policy request:", e);
          }
        }

        // Create or update pending approval in backend.
        // The backend sync may have already created an empty approval for this role,
        // so update the existing one instead of creating a duplicate.
        const existingApprovals = await policyApprovalsAPI.getPendingPolicies();
        const existingApproval = existingApprovals.find(
          (a: any) => a.roleId === params.roleName && !a.policyRequestData,
        );
        if (existingApproval && policyRequestData) {
          await this.apiService.send(
            "PUT",
            `/organizations/${orgId}/tide/policy-approvals/${existingApproval.id}/data`,
            { policyRequestData, contractCode },
            true,
            false,
          );
          console.info("[TideWarden] Updated existing approval", existingApproval.id, "with policyRequestData");
        } else if (policyRequestData) {
          await policyApprovalsAPI.createApproval({
            roleId: params.roleName,
            threshold: params.threshold,
            policyRequestData,
            contractCode,
          });
          console.info("[TideWarden] Created new approval for", params.roleName);
        } else {
          console.error("[TideWarden] Cannot create policy — no policyRequestData generated");
        }

        // When creating orgOwner, also update/create the appUser crypto policy
        if (params.roleName === "orgOwner" && areTideLibsAvailable() && tideCloakService.isInitialized()) {
          try {
            // Delete any existing committed appUser crypto policy so we can recreate with correct model IDs
            try {
              await collectionAccessAPI.resetCryptoPolicy();
            } catch {
              // No existing policy to reset — that's fine
            }
            const cryptoContractCode = ORG_CRYPTO_CONTRACT;
            const { policyRequestBase64: cryptoPolicyBase64 } = await createSignedPolicyRequest(
              {
                roleName: "appUser",
                threshold: 1,
                approvalType: "implicit",
                executionType: "private",
                modelId: [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION],
                resource: tideCloakService.getResource(),
                vendorId: tideCloakService.getVendorId(),
                contractCode: cryptoContractCode,
              },
              tideCloakService,
            );
            // Update existing empty appUser approval or create new
            const existingAppUser = existingApprovals.find(
              (a: any) => a.roleId === "appUser" && !a.policyRequestData,
            );
            if (existingAppUser) {
              await this.apiService.send(
                "PUT",
                `/organizations/${orgId}/tide/policy-approvals/${existingAppUser.id}/data`,
                { policyRequestData: cryptoPolicyBase64, contractCode: cryptoContractCode },
                true,
                false,
              );
            } else {
              await policyApprovalsAPI.createApproval({
                roleId: "appUser",
                threshold: 1,
                policyRequestData: cryptoPolicyBase64,
                contractCode: cryptoContractCode,
              });
            }
            console.info("[TideWarden] appUser crypto policy ready alongside orgOwner");
          } catch (cryptoErr) {
            console.warn("[TideWarden] Failed to create appUser crypto policy:", cryptoErr);
          }
        }

        // Log the policy creation
        await policyLogsAPI.addLog({
          policyId: `policy-${params.roleName}-${Date.now()}`,
          roleId: params.roleName,
          action: "created",
          performedBy: "admin",
          policyStatus: "pending",
          policyThreshold: params.threshold,
          approvalCount: 0,
          rejectionCount: 0,
        });
      },
    };
  }
}
