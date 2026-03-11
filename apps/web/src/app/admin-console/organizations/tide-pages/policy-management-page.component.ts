import { CommonModule } from "@angular/common";
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { ORG_OWNER_CONTRACT } from "./collection-owner-contract";
import { ORG_CRYPTO_CONTRACT } from "./org-crypto-contract";
import {
  createBackendCollectionAccessAPI,
  createBackendPolicyAPI,
  createBackendPolicyApprovalsAPI,
} from "./tide-api.service";
import {
  areTideLibsAvailable,
  createSignedPolicyRequest,
  loadTideLibs,
  MODEL_IDS,
} from "./tide-policy.service";

interface PolicyRow {
  roleName: string;
  hasApproval: boolean;
  approvalId?: string;
  hasPolicyData: boolean;
  hasContractCode: boolean;
  contractType: string;
  status: string;
  threshold: number;
  approvalType: string;
  executionType: string;
}

@Component({
  selector: "app-org-policy-management-page",
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="tw-container tw-mx-auto tw-p-6">
      <div class="tw-mb-6">
        <h1 class="tw-text-2xl tw-font-bold tw-mb-2">Policy Management</h1>
        <p class="tw-text-muted-foreground">
          View and regenerate signing policies for roles. Regenerating creates a fresh
          PolicySignRequest via the ORK enclave.
        </p>
      </div>

      <div *ngIf="loading" class="tw-text-center tw-py-8">
        <p>Loading policies...</p>
      </div>

      <div *ngIf="error" class="tw-bg-danger-100 tw-border tw-border-danger-500 tw-text-danger-700 tw-px-4 tw-py-3 tw-rounded tw-mb-4">
        {{ error }}
      </div>

      <div *ngIf="successMessage" class="tw-bg-success-100 tw-border tw-border-success-500 tw-text-success-700 tw-px-4 tw-py-3 tw-rounded tw-mb-4">
        {{ successMessage }}
      </div>

      <div *ngIf="!loading && policies.length === 0" class="tw-text-center tw-py-8">
        <p>No policies found. Create roles with policies on the Roles page first.</p>
      </div>

      <table *ngIf="!loading && policies.length > 0" class="tw-w-full tw-border-collapse">
        <thead>
          <tr class="tw-border-b tw-border-secondary-300">
            <th class="tw-text-left tw-p-3 tw-font-semibold">Role</th>
            <th class="tw-text-left tw-p-3 tw-font-semibold">Status</th>
            <th class="tw-text-left tw-p-3 tw-font-semibold">Policy Data</th>
            <th class="tw-text-left tw-p-3 tw-font-semibold">Contract</th>
            <th class="tw-text-left tw-p-3 tw-font-semibold">Type</th>
            <th class="tw-text-left tw-p-3 tw-font-semibold">Threshold</th>
            <th class="tw-text-right tw-p-3 tw-font-semibold">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr *ngFor="let p of policies" class="tw-border-b tw-border-secondary-200 hover:tw-bg-secondary-100">
            <td class="tw-p-3">
              <span class="tw-font-medium">{{ p.roleName }}</span>
              <span *ngIf="p.roleName === 'orgOwner' || p.roleName === 'appUser'"
                class="tw-ml-2 tw-text-xs tw-bg-primary-100 tw-text-primary-700 tw-px-2 tw-py-0.5 tw-rounded">
                Built-in
              </span>
            </td>
            <td class="tw-p-3">
              <span [class]="p.status === 'ready' ? 'tw-text-success-600' : 'tw-text-warning-600'">
                {{ p.status }}
              </span>
            </td>
            <td class="tw-p-3">
              <span [class]="p.hasPolicyData ? 'tw-text-success-600' : 'tw-text-danger-600'">
                {{ p.hasPolicyData ? 'Yes' : 'Missing' }}
              </span>
            </td>
            <td class="tw-p-3">
              <span [class]="p.hasContractCode ? 'tw-text-success-600' : 'tw-text-danger-600'">
                {{ p.hasContractCode ? 'Yes' : 'Missing' }}
              </span>
            </td>
            <td class="tw-p-3 tw-text-sm">{{ p.approvalType }} / {{ p.executionType }}</td>
            <td class="tw-p-3">{{ p.threshold }}</td>
            <td class="tw-p-3 tw-text-right">
              <button
                class="tw-btn tw-btn-sm tw-btn-outline-primary tw-mr-2"
                (click)="regenerate(p.roleName)"
                [disabled]="regenerating === p.roleName"
              >
                {{ regenerating === p.roleName ? 'Regenerating...' : 'Regenerate' }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div class="tw-mt-6 tw-flex tw-gap-3">
        <button class="tw-btn tw-btn-sm tw-btn-outline-primary" (click)="regenerateAll()" [disabled]="regenerating !== null">
          {{ regenerating ? 'Working...' : 'Regenerate All' }}
        </button>
        <button class="tw-btn tw-btn-sm tw-btn-outline-secondary" (click)="refresh()" [disabled]="loading">
          Refresh
        </button>
      </div>
    </div>
  `,
})
export class OrgPolicyManagementPageComponent implements OnInit {
  policies: PolicyRow[] = [];
  loading = true;
  error: string | null = null;
  successMessage: string | null = null;
  regenerating: string | null = null;

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private tideCloakService = inject(TideCloakService);
  private cdr = inject(ChangeDetectorRef);

  private orgId = "";
  private policyAPI: any;
  private policyApprovalsAPI: any;
  private collectionAccessAPI: any;

  ngOnInit() {
    this.orgId = this.route.snapshot.params["organizationId"] ?? "";
    this.policyAPI = createBackendPolicyAPI(this.apiService, this.orgId);
    this.policyApprovalsAPI = createBackendPolicyApprovalsAPI(this.apiService, this.orgId);
    this.collectionAccessAPI = createBackendCollectionAccessAPI(this.apiService, this.orgId);
    this.refresh();
  }

  async refresh() {
    this.loading = true;
    this.error = null;
    this.cdr.detectChanges();

    try {
      const approvals: any[] = await this.policyApprovalsAPI.getPendingPolicies();

      // Build rows from approvals
      const rows: PolicyRow[] = [];
      const seenRoles = new Set<string>();

      for (const a of approvals) {
        seenRoles.add(a.roleId);
        rows.push({
          roleName: a.roleId,
          hasApproval: true,
          approvalId: a.id,
          hasPolicyData: !!a.policyRequestData,
          hasContractCode: !!a.contractCode,
          contractType: a.contractCode ? "forseti" : "none",
          status: a.policyRequestData ? "ready" : "missing data",
          threshold: a.threshold || 1,
          approvalType: a.roleId === "appUser" ? "implicit" : "explicit",
          executionType: a.roleId === "appUser" ? "private" : "public",
        });
      }

      // Add built-in roles if not present
      for (const roleName of ["orgOwner", "appUser"]) {
        if (!seenRoles.has(roleName)) {
          rows.push({
            roleName,
            hasApproval: false,
            hasPolicyData: false,
            hasContractCode: false,
            contractType: "none",
            status: "no approval",
            threshold: roleName === "appUser" ? 1 : 1,
            approvalType: roleName === "appUser" ? "implicit" : "explicit",
            executionType: roleName === "appUser" ? "private" : "public",
          });
        }
      }

      // Sort: orgOwner first, appUser second, rest alphabetical
      rows.sort((a, b) => {
        const order: Record<string, number> = { orgOwner: 0, appUser: 1 };
        const aOrder = order[a.roleName] ?? 2;
        const bOrder = order[b.roleName] ?? 2;
        if (aOrder !== bOrder) {
          return aOrder - bOrder;
        }
        return a.roleName.localeCompare(b.roleName);
      });

      this.policies = rows;
    } catch (e) {
      this.error = `Failed to load policies: ${(e as any)?.message || e}`;
    } finally {
      this.loading = false;
      this.cdr.detectChanges();
    }
  }

  async regenerate(roleName: string) {
    this.regenerating = roleName;
    this.error = null;
    this.successMessage = null;
    this.cdr.detectChanges();

    try {
      await loadTideLibs();
      await this.tideCloakService.ensureInitialized();

      if (!areTideLibsAvailable() || !this.tideCloakService.isInitialized()) {
        throw new Error("Tide libraries or enclave not available. Are you logged in via TideCloak SSO?");
      }

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
        const existingPolicy = await this.policyAPI.getPolicy(roleName);
        if (!existingPolicy) {
          throw new Error(`No existing policy config found for role "${roleName}"`);
        }
        approvalType = existingPolicy.approvalType || "explicit";
        executionType = existingPolicy.executionType || "public";
        threshold = existingPolicy.threshold || 1;
        if (existingPolicy.templateId) {
          const templateAPI = (await import("./tide-api.service")).createBackendTemplateAPI(this.apiService, this.orgId);
          const template = await templateAPI.getTemplate(existingPolicy.templateId);
          contractCode = template?.csCode;
        }
        if (!contractCode) {
          throw new Error(`No contract code found for role "${roleName}"`);
        }
      }

      const config: any = {
        roleName,
        threshold,
        approvalType,
        executionType,
        resource: this.tideCloakService.getResource(),
        vendorId: this.tideCloakService.getVendorId(),
        contractCode,
      };
      if (modelId) {
        config.modelId = modelId;
      }

      const { policyRequestBase64 } = await createSignedPolicyRequest(config, this.tideCloakService);

      // Find or create approval
      const existingApprovals: any[] = await this.policyApprovalsAPI.getPendingPolicies();
      const existingApproval = existingApprovals.find((a: any) => a.roleId === roleName);

      if (existingApproval) {
        await this.apiService.send(
          "PUT",
          `/organizations/${this.orgId}/tide/policy-approvals/${existingApproval.id}/data`,
          { policyRequestData: policyRequestBase64, contractCode },
          true,
          false,
        );
      } else {
        await this.policyApprovalsAPI.createApproval({
          roleId: roleName,
          threshold,
          policyRequestData: policyRequestBase64,
          contractCode,
        });
      }

      // If orgOwner, also regenerate appUser
      if (roleName === "orgOwner") {
        try {
          await this.collectionAccessAPI.resetCryptoPolicy();
        } catch {
          // fine
        }
        const { policyRequestBase64: cryptoBase64 } = await createSignedPolicyRequest(
          {
            roleName: "appUser",
            threshold: 1,
            approvalType: "implicit",
            executionType: "private",
            modelId: [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION],
            resource: this.tideCloakService.getResource(),
            vendorId: this.tideCloakService.getVendorId(),
            contractCode: ORG_CRYPTO_CONTRACT,
          },
          this.tideCloakService,
        );
        const existingAppUser = existingApprovals.find((a: any) => a.roleId === "appUser");
        if (existingAppUser) {
          await this.apiService.send(
            "PUT",
            `/organizations/${this.orgId}/tide/policy-approvals/${existingAppUser.id}/data`,
            { policyRequestData: cryptoBase64, contractCode: ORG_CRYPTO_CONTRACT },
            true,
            false,
          );
        } else {
          await this.policyApprovalsAPI.createApproval({
            roleId: "appUser",
            threshold: 1,
            policyRequestData: cryptoBase64,
            contractCode: ORG_CRYPTO_CONTRACT,
          });
        }
        this.successMessage = `Regenerated policies for orgOwner + appUser`;
      } else {
        this.successMessage = `Regenerated policy for ${roleName}`;
      }

      await this.refresh();
    } catch (e) {
      this.error = `Failed to regenerate ${roleName}: ${(e as any)?.message || e}`;
      console.error("[TideWarden] [policy-mgmt] regenerate failed:", e);
    } finally {
      this.regenerating = null;
      this.cdr.detectChanges();
    }
  }

  async regenerateAll() {
    const roleNames = this.policies.map((p) => p.roleName);
    // Regenerate orgOwner first (which also regenerates appUser), then others
    const orgOwnerIdx = roleNames.indexOf("orgOwner");
    if (orgOwnerIdx >= 0) {
      await this.regenerate("orgOwner");
      // Remove both orgOwner and appUser since they were handled
      const remaining = roleNames.filter((r) => r !== "orgOwner" && r !== "appUser");
      for (const roleName of remaining) {
        await this.regenerate(roleName);
      }
    } else {
      for (const roleName of roleNames) {
        await this.regenerate(roleName);
      }
    }
  }
}
