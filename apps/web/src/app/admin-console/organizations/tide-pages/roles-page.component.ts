import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import {
  createBackendAdminAPI,
  createBackendPolicyAPI,
  createBackendPolicyApprovalsAPI,
  createBackendPolicyLogsAPI,
  createBackendTemplateAPI,
} from "./tide-api.service";
import {
  loadTideLibs,
  areTideLibsAvailable,
  createSignedPolicyRequest,
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
    const tideCloakService = this.tideCloakService;
    const templateAPI = createBackendTemplateAPI(this.apiService, orgId);

    this.rolesProps = {
      adminAPI: createBackendAdminAPI(this.apiService, orgId),
      templateAPI,
      policyAPI,
      policyLogsAPI,
      title: "Roles",
      onCreatePolicy: async (params: {
        roleName: string;
        policyConfig: any;
        templateId?: string;
        templateParams?: Record<string, any>;
        threshold: number;
      }) => {
        // Resolve contract code from the selected template (like KeyleSSH's SSH_CONTRACT)
        let contractCode: string | undefined;
        if (params.templateId) {
          try {
            const template = await templateAPI.getTemplate(params.templateId);
            contractCode = template?.csCode;
          } catch (e) {
            console.error("[TideWarden] Failed to fetch template csCode:", e);
          }
        }

        const approvalType = params.policyConfig?.approvalType || "explicit";
        const executionType = params.policyConfig?.executionType || "private";

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

        // Build policyRequestData — attempt Tide signing (like KeyleSSH),
        // fall back to JSON if anything fails so the approval is always created
        let policyRequestData: string;

        try {
          await loadTideLibs();
          await tideCloakService.ensureInitialized();

          if (contractCode && areTideLibsAvailable() && tideCloakService.isInitialized()) {
            console.info("[TideWarden] Creating Tide-signed policy request");
            const { policyRequestBase64 } = await createSignedPolicyRequest(
              {
                roleName: params.roleName,
                threshold: params.threshold,
                approvalType,
                executionType,
                resource: tideCloakService.getResource(),
                vendorId: tideCloakService.getVendorId(),
                contractCode,
              },
              tideCloakService,
            );
            policyRequestData = policyRequestBase64;
          } else {
            console.warn(
              "[TideWarden] Tide signing not available, using JSON fallback.",
              "contractCode:", !!contractCode,
              "tideLibs:", areTideLibsAvailable(),
              "enclaveReady:", tideCloakService.isInitialized(),
            );
            policyRequestData = JSON.stringify({
              roleName: params.roleName,
              contractCode,
              approvalType,
              executionType,
            });
          }
        } catch (e) {
          console.error("[TideWarden] Tide signing failed, using JSON fallback:", e);
          policyRequestData = JSON.stringify({
            roleName: params.roleName,
            contractCode,
            approvalType,
            executionType,
          });
        }

        // Create pending approval in backend
        await policyApprovalsAPI.createApproval({
          roleId: params.roleName,
          threshold: params.threshold,
          policyRequestData,
          contractCode,
        });

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
