// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { CommonModule } from "@angular/common";
import { ChangeDetectorRef, Component, OnInit } from "@angular/core";
import { ActivatedRoute, RouterModule } from "@angular/router";
import { combineLatest, filter, map, Observable, switchMap, withLatestFrom } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import { AdminConsoleLogo } from "@bitwarden/assets/svg";
import {
  canAccessAccessIntelligence,
  canAccessBillingTab,
  canAccessGroupsTab,
  canAccessMembersTab,
  canAccessOrgAdmin,
  canAccessReportingTab,
  canAccessSettingsTab,
  canAccessVaultTab,
  OrganizationService,
} from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { PolicyService } from "@bitwarden/common/admin-console/abstractions/policy/policy.service.abstraction";
import { ProviderService } from "@bitwarden/common/admin-console/abstractions/provider.service";
import { PolicyType, ProviderStatusType } from "@bitwarden/common/admin-console/enums";
import { Organization } from "@bitwarden/common/admin-console/models/domain/organization";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { getById } from "@bitwarden/common/platform/misc";
import { BannerModule, CalloutModule, SvgModule } from "@bitwarden/components";
import { OrganizationWarningsModule } from "@bitwarden/web-vault/app/billing/organizations/warnings/organization-warnings.module";
import { OrganizationWarningsService } from "@bitwarden/web-vault/app/billing/organizations/warnings/services";
import { NonIndividualSubscriber } from "@bitwarden/web-vault/app/billing/types";
import { TaxIdWarningComponent } from "@bitwarden/web-vault/app/billing/warnings/components";
import { TaxIdWarningType } from "@bitwarden/web-vault/app/billing/warnings/types";

import { FreeFamiliesPolicyService } from "../../../billing/services/free-families-policy.service";
import { OrgSwitcherComponent } from "../../../layouts/org-switcher/org-switcher.component";
import { WebLayoutModule } from "../../../layouts/web-layout.module";

// FIXME(https://bitwarden.atlassian.net/browse/CL-764): Migrate to OnPush
// eslint-disable-next-line @angular-eslint/prefer-on-push-component-change-detection
@Component({
  selector: "app-organization-layout",
  templateUrl: "organization-layout.component.html",
  imports: [
    CommonModule,
    RouterModule,
    JslibModule,
    WebLayoutModule,
    SvgModule,
    OrgSwitcherComponent,
    BannerModule,
    CalloutModule,
    TaxIdWarningComponent,
    TaxIdWarningComponent,
    OrganizationWarningsModule,
  ],
})
export class OrganizationLayoutComponent implements OnInit {
  protected readonly logo = AdminConsoleLogo;

  protected orgFilter = (org: Organization) => canAccessOrgAdmin(org);

  protected integrationPageEnabled$: Observable<boolean>;
  protected selfHosted: boolean;

  organization$: Observable<Organization>;
  canAccessExport$: Observable<boolean>;
  showPaymentAndHistory$: Observable<boolean>;
  hideNewOrgButton$: Observable<boolean>;
  organizationIsUnmanaged$: Observable<boolean>;

  protected showSponsoredFamiliesDropdown$: Observable<boolean>;

  protected subscriber$: Observable<NonIndividualSubscriber>;
  protected getTaxIdWarning$: () => Observable<TaxIdWarningType | null>;

  orgOwnerBanner: "pending" | "committed" | null = null;

  constructor(
    private route: ActivatedRoute,
    private organizationService: OrganizationService,
    private platformUtilsService: PlatformUtilsService,
    private policyService: PolicyService,
    private providerService: ProviderService,
    private accountService: AccountService,
    private freeFamiliesPolicyService: FreeFamiliesPolicyService,
    private organizationWarningsService: OrganizationWarningsService,
    private apiService: ApiService,
    private cdr: ChangeDetectorRef,
    private tideCloakService: TideCloakService,
  ) {}

  async ngOnInit() {
    document.body.classList.remove("layout_frontend");
    this.selfHosted = this.platformUtilsService.isSelfHost();

    // Check org-owner policy status for banner
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    if (orgId) {
      this.checkOrgOwnerStatus(orgId);
    }

    this.organization$ = this.route.params.pipe(
      map((p) => p.organizationId),
      withLatestFrom(this.accountService.activeAccount$.pipe(getUserId)),
      switchMap(([orgId, userId]) =>
        this.organizationService.organizations$(userId).pipe(getById(orgId)),
      ),
      filter((org) => org != null),
    );
    this.showSponsoredFamiliesDropdown$ =
      this.freeFamiliesPolicyService.showSponsoredFamiliesDropdown$(this.organization$);

    this.canAccessExport$ = this.organization$.pipe(map((org) => org.canAccessExport));

    this.showPaymentAndHistory$ = this.organization$.pipe(
      map(
        (org) =>
          !this.platformUtilsService.isSelfHost() &&
          org.canViewBillingHistory &&
          org.canEditPaymentMethods,
      ),
    );

    this.hideNewOrgButton$ = this.accountService.activeAccount$.pipe(
      getUserId,
      switchMap((userId) => this.policyService.policyAppliesToUser$(PolicyType.SingleOrg, userId)),
    );

    const provider$ = combineLatest([
      this.organization$,
      this.accountService.activeAccount$.pipe(getUserId),
    ]).pipe(
      switchMap(([organization, userId]) =>
        this.providerService.get$(organization.providerId, userId),
      ),
    );

    this.organizationIsUnmanaged$ = combineLatest([this.organization$, provider$]).pipe(
      map(
        ([organization, provider]) =>
          !organization.hasProvider ||
          !provider ||
          provider.providerStatus !== ProviderStatusType.Billable,
      ),
    );

    this.integrationPageEnabled$ = this.organization$.pipe(
      map((org) => !this.platformUtilsService.isSelfHost() && org.canAccessIntegrations),
    );

    this.subscriber$ = this.organization$.pipe(
      map((organization) => ({
        type: "organization",
        data: organization,
      })),
    );

    this.getTaxIdWarning$ = () =>
      this.organization$.pipe(
        switchMap((organization) =>
          this.organizationWarningsService.getTaxIdWarning$(organization),
        ),
      );
  }

  canShowVaultTab(organization: Organization): boolean {
    return canAccessVaultTab(organization);
  }

  canShowSettingsTab(organization: Organization): boolean {
    return canAccessSettingsTab(organization);
  }

  canShowMembersTab(organization: Organization): boolean {
    return canAccessMembersTab(organization);
  }

  canShowGroupsTab(organization: Organization): boolean {
    return canAccessGroupsTab(organization);
  }

  canShowReportsTab(organization: Organization): boolean {
    return canAccessReportingTab(organization);
  }

  canShowBillingTab(organization: Organization): boolean {
    if (this.platformUtilsService.isSelfHost()) {
      return false;
    }
    return canAccessBillingTab(organization);
  }

  canShowAccessIntelligenceTab(organization: Organization): boolean {
    if (this.platformUtilsService.isSelfHost()) {
      return false;
    }
    return canAccessAccessIntelligence(organization);
  }

  getReportTabLabel(organization: Organization): string {
    return organization.useEvents ? "reporting" : "reports";
  }

  refreshTaxIdWarning = () => this.organizationWarningsService.refreshTaxIdWarning();

  async resetOrgOwnerPolicy() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    if (!orgId) return;
    try {
      await this.apiService.send(
        "POST",
        `/organizations/${orgId}/tide/org-owner-reset`,
        null,
        true,
        false,
      );
      // Re-create the role and trigger fresh policy flow
      await this.apiService.send(
        "POST",
        `/organizations/${orgId}/tide/org-owner-role`,
        null,
        true,
        false,
      );
      // Refresh the page to pick up the new state
      window.location.reload();
    } catch (e) {
      console.error("[TideWarden] Failed to reset org owner policy:", e);
    }
  }

  private async checkOrgOwnerStatus(orgId: string) {
    try {
      const status = await this.apiService.send(
        "GET",
        `/organizations/${orgId}/tide/org-owner-status`,
        null,
        true,
        true,
      );
      if (status.policyStatus === "committed") {
        this.orgOwnerBanner = "committed";
      } else {
        // pending or none — policy needs to be approved
        this.orgOwnerBanner = "pending";
        // Auto-populate empty policy approvals in the background
        this.autoPopulateEmptyApprovals(orgId);
      }
    } catch {
      this.orgOwnerBanner = null;
    }
    this.cdr.detectChanges();
  }

  private async autoPopulateEmptyApprovals(orgId: string) {
    try {
      const { loadTideLibs, areTideLibsAvailable, createSignedPolicyRequest, MODEL_IDS } =
        await import("../tide-pages/tide-policy.service");
      const { ORG_OWNER_CONTRACT } = await import("../tide-pages/collection-owner-contract");
      const { ORG_CRYPTO_CONTRACT } = await import("../tide-pages/org-crypto-contract");

      await loadTideLibs();
      await this.tideCloakService.ensureInitialized();

      if (!areTideLibsAvailable() || !this.tideCloakService.isInitialized()) {
        return;
      }

      const approvals: any[] = await this.apiService.send(
        "GET",
        `/organizations/${orgId}/tide/policy-approvals`,
        null,
        true,
        true,
      );

      for (const approval of approvals) {
        if (approval.policyRequestData || approval.contractCode) {
          continue; // Already populated
        }

        const isAppUser = approval.roleId === "appUser";
        const isOrgOwner = approval.roleId === "orgOwner";
        if (!isAppUser && !isOrgOwner) {
          continue;
        }

        try {
          const contractCode = isAppUser ? ORG_CRYPTO_CONTRACT : ORG_OWNER_CONTRACT;
          const config: any = {
            roleName: approval.roleId,
            threshold: approval.threshold || 1,
            approvalType: isAppUser ? "implicit" : "explicit",
            executionType: isAppUser ? "private" : "public",
            resource: this.tideCloakService.getResource(),
            vendorId: this.tideCloakService.getVendorId(),
            contractCode,
          };
          if (isAppUser) {
            config.modelId = [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION];
          }

          const { policyRequestBase64 } = await createSignedPolicyRequest(config, this.tideCloakService);

          await this.apiService.send(
            "PUT",
            `/organizations/${orgId}/tide/policy-approvals/${approval.id}/data`,
            { policyRequestData: policyRequestBase64, contractCode },
            true,
            false,
          );
          console.info(`[TideWarden] Auto-populated ${approval.roleId} approval ${approval.id} with policyRequestData`);
        } catch (e) {
          console.warn(`[TideWarden] Failed to auto-populate ${approval.roleId} approval:`, e);
        }
      }
    } catch (e) {
      // Non-critical — approvals page enrichment will catch this as fallback
      console.warn("[TideWarden] Auto-populate approvals failed:", e);
    }
  }
}
