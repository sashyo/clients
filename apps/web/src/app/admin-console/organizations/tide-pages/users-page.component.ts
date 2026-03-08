import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  OnInit,
  inject,
} from "@angular/core";
import { CommonModule } from "@angular/common";
import { ActivatedRoute } from "@angular/router";
import { firstValueFrom } from "rxjs";

import {
  OrganizationUserApiService,
  OrganizationUserService,
} from "@bitwarden/admin-console/common";
import { OrganizationUserStatusType } from "@bitwarden/common/admin-console/enums";
import { OrganizationService } from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import { createBackendAccessMetadataAPI, createBackendAdminAPI } from "./tide-api.service";

interface PendingMember {
  id: string;
  userId: string;
  name: string;
  email: string;
  confirming: boolean;
  error?: string;
  statusLabel?: string;
}

@Component({
  selector: "app-org-users-page",
  template: `
    <!-- Pending confirmations banner -->
    <div *ngIf="pendingMembers.length > 0" class="tw-mb-4 tw-rounded tw-border tw-border-warning-600 tw-bg-warning-100 tw-p-4">
      <h3 class="tw-m-0 tw-mb-2 tw-text-base tw-font-semibold tw-text-warning-700">
        Members Needing Key Provisioning ({{ pendingMembers.length }})
      </h3>
      <p class="tw-m-0 tw-mb-3 tw-text-sm tw-text-warning-700">
        These members need their organization encryption key provisioned. Click Confirm to encrypt and send the org key to each member.
      </p>
      <div class="tw-flex tw-flex-col tw-gap-2">
        <div
          *ngFor="let member of pendingMembers"
          class="tw-flex tw-items-center tw-justify-between tw-rounded tw-bg-background tw-px-3 tw-py-2"
        >
          <div>
            <span class="tw-font-medium">{{ member.name || member.email }}</span>
            <span *ngIf="member.name" class="tw-ml-2 tw-text-sm tw-text-muted">{{ member.email }}</span>
            <span class="tw-ml-2 tw-rounded tw-bg-warning-600 tw-px-2 tw-py-0.5 tw-text-xs tw-text-contrast">{{ member.statusLabel }}</span>
          </div>
          <div class="tw-flex tw-items-center tw-gap-2">
            <span *ngIf="member.error" class="tw-text-sm tw-text-danger">{{ member.error }}</span>
            <button
              class="tw-rounded tw-border-0 tw-bg-primary-600 tw-px-3 tw-py-1 tw-text-sm tw-text-contrast hover:tw-bg-primary-700 disabled:tw-opacity-50"
              [disabled]="member.confirming"
              (click)="confirmMember(member)"
            >
              {{ member.confirming ? "Confirming..." : "Confirm" }}
            </button>
          </div>
        </div>
      </div>
      <button
        *ngIf="pendingMembers.length > 1"
        class="tw-mt-3 tw-rounded tw-border-0 tw-bg-primary-600 tw-px-4 tw-py-2 tw-text-sm tw-text-contrast hover:tw-bg-primary-700 disabled:tw-opacity-50"
        [disabled]="confirmingAll"
        (click)="confirmAll()"
      >
        {{ confirmingAll ? "Confirming All..." : "Confirm All" }}
      </button>
    </div>

    <app-react-host [component]="usersPage" [props]="usersProps"></app-react-host>
  `,
  standalone: true,
  imports: [CommonModule, ReactHostComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrgUsersPageComponent implements OnInit {
  usersPage: any;
  usersProps: Record<string, any> = {};
  pendingMembers: PendingMember[] = [];
  confirmingAll = false;

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private orgUserApiService = inject(OrganizationUserApiService);
  private orgUserService = inject(OrganizationUserService);
  private orgService = inject(OrganizationService);
  private accountService = inject(AccountService);
  private logService = inject(LogService);
  private cdr = inject(ChangeDetectorRef);

  async ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    const { UsersPage } = require("@tideorg/ui");
    this.usersPage = UsersPage;
    this.usersProps = {
      adminAPI: createBackendAdminAPI(this.apiService, orgId),
      accessMetadataAPI: createBackendAccessMetadataAPI(this.apiService, orgId),
      title: "Members",
    };

    await this.loadPendingMembers(orgId);
  }

  private async loadPendingMembers(orgId: string): Promise<void> {
    try {
      const response = await this.orgUserApiService.getAllUsers(orgId);
      // Get current user to exclude them from the pending list
      const currentUserId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
      console.log("[TideMembers] Total org users:", response.data.length,
        "statuses:", response.data.map((u) => ({ email: u.email, status: u.status })));
      // Show Accepted members AND Confirmed members (who may be missing akey from SSO auto-confirm)
      this.pendingMembers = response.data
        .filter((u) =>
          u.userId !== currentUserId &&
          (u.status === OrganizationUserStatusType.Accepted ||
           u.status === OrganizationUserStatusType.Confirmed))
        .map((u) => ({
          id: u.id,
          userId: u.userId,
          name: u.name || "",
          email: u.email || "",
          confirming: false,
          statusLabel: u.status === OrganizationUserStatusType.Accepted ? "Needs Confirmation" : "Re-confirm Key",
        }));
      console.log("[TideMembers] Pending members:", this.pendingMembers.length);
      this.cdr.markForCheck();
    } catch (e) {
      console.error("[TideMembers] Failed to load pending members:", e);
      this.logService.error("Failed to load pending members: " + e);
    }
  }

  async confirmMember(member: PendingMember): Promise<void> {
    member.confirming = true;
    member.error = undefined;
    this.cdr.markForCheck();

    try {
      const orgId = this.route.snapshot.params["organizationId"] ?? "";
      const userId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
      const orgs = await firstValueFrom(this.orgService.organizations$(userId));
      const org = orgs?.find((o) => o.id === orgId);
      if (!org) {
        throw new Error("Organization not found");
      }

      // Get user's public key
      const pubKeyResponse = await this.apiService.getUserPublicKey(member.userId);
      const publicKey = Utils.fromB64ToArray(pubKeyResponse.publicKey);

      // Confirm: encrypts org key to user's public key and calls API
      await firstValueFrom(this.orgUserService.confirmUser(org, member.id, publicKey));

      // Remove from pending list
      this.pendingMembers = this.pendingMembers.filter((m) => m.id !== member.id);
      this.cdr.markForCheck();
    } catch (e) {
      member.confirming = false;
      member.error = (e as Error).message || String(e);
      this.cdr.markForCheck();
      this.logService.error("Failed to confirm member: " + e);
    }
  }

  async confirmAll(): Promise<void> {
    this.confirmingAll = true;
    this.cdr.markForCheck();

    for (const member of [...this.pendingMembers]) {
      await this.confirmMember(member);
    }

    this.confirmingAll = false;
    this.cdr.markForCheck();
  }
}
