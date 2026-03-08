import { CommonModule } from "@angular/common";
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

interface MembershipSigEntry {
  collectionId: string;
  collectionName: string;
  membershipData: string;
  signature: string;
  signedBy: string;
  updatedAt: number;
}

interface ParsedMember {
  userId: string;
  accessLevel: string;
}

@Component({
  selector: "app-org-membership-proofs-page",
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="tw-p-6 tw-max-w-5xl">
      <h1 class="tw-text-xl tw-font-semibold tw-mb-2">Membership Proofs</h1>
      <p class="tw-text-sm tw-text-muted tw-mb-6">
        Cryptographic proofs of collection membership. Each entry is a Tide-signed membership list
        that proves an org owner authorized the exact set of users and their access levels.
      </p>

      <div *ngIf="loading" class="tw-text-sm tw-text-muted tw-py-4">Loading...</div>

      <div *ngIf="!loading && entries.length === 0" class="tw-text-sm tw-text-muted tw-py-4">
        No signed membership lists yet. Membership proofs are created when collection access
        is modified on the Collection Access page.
      </div>

      <div *ngIf="!loading && entries.length > 0">
        <div
          *ngFor="let entry of entries"
          class="tw-border tw-border-secondary-500 tw-rounded tw-mb-4 tw-overflow-hidden"
        >
          <!-- Header -->
          <div
            class="tw-bg-background-alt tw-px-4 tw-py-3 tw-flex tw-justify-between tw-items-center tw-cursor-pointer"
            (click)="toggleExpand(entry.collectionId)"
          >
            <div>
              <span class="tw-font-medium">{{ entry.collectionName }}</span>
              <span class="tw-text-xs tw-text-muted tw-ml-2">
                {{ parseMemberCount(entry.membershipData) }} member(s)
              </span>
            </div>
            <div class="tw-text-right tw-text-xs tw-text-muted">
              <div>Signed by <strong>{{ entry.signedBy }}</strong></div>
              <div>{{ formatDate(entry.updatedAt) }}</div>
            </div>
          </div>

          <!-- Expanded details -->
          <div *ngIf="expandedId === entry.collectionId" class="tw-px-4 tw-py-3 tw-text-sm">
            <!-- Members table -->
            <h3 class="tw-font-medium tw-mb-2">Members</h3>
            <table class="tw-w-full tw-mb-4 tw-text-sm">
              <thead>
                <tr class="tw-border-b tw-border-secondary-300">
                  <th class="tw-text-left tw-py-1 tw-pr-4">User ID</th>
                  <th class="tw-text-left tw-py-1">Access Level</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  *ngFor="let member of parseMembers(entry.membershipData)"
                  class="tw-border-b tw-border-secondary-200"
                >
                  <td class="tw-py-1 tw-pr-4 tw-font-mono tw-text-xs">{{ member.userId }}</td>
                  <td class="tw-py-1">
                    <span
                      class="tw-inline-block tw-px-2 tw-py-0.5 tw-rounded tw-text-xs"
                      [ngClass]="{
                        'tw-bg-success-100 tw-text-success-700': member.accessLevel === 'manage',
                        'tw-bg-info-100 tw-text-info-700': member.accessLevel === 'write',
                        'tw-bg-secondary-100 tw-text-secondary-700': member.accessLevel === 'read'
                      }"
                    >
                      {{ member.accessLevel }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>

            <!-- Signature -->
            <h3 class="tw-font-medium tw-mb-2">Ed25519 Signature</h3>
            <div
              class="tw-bg-background tw-border tw-border-secondary-300 tw-rounded tw-p-2 tw-font-mono tw-text-xs tw-break-all tw-mb-4"
            >
              {{ entry.signature }}
            </div>

            <!-- Raw data -->
            <h3 class="tw-font-medium tw-mb-2">Canonical Membership Data</h3>
            <div
              class="tw-bg-background tw-border tw-border-secondary-300 tw-rounded tw-p-2 tw-font-mono tw-text-xs tw-break-all"
            >
              {{ entry.membershipData }}
            </div>
          </div>
        </div>
      </div>

      <div *ngIf="errorMessage" class="tw-text-danger tw-text-sm tw-mt-3">
        {{ errorMessage }}
      </div>
    </div>
  `,
})
export class OrgMembershipProofsPageComponent implements OnInit {
  entries: MembershipSigEntry[] = [];
  loading = false;
  errorMessage = "";
  expandedId: string | null = null;

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private cdr = inject(ChangeDetectorRef);

  async ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";

    this.loading = true;
    this.cdr.markForCheck();

    try {
      const basePath = `/organizations/${orgId}/tide/collection-membership-sigs`;
      this.entries = (await this.apiService.send("GET", basePath, null, true, true)) || [];
    } catch {
      this.errorMessage = "Failed to load membership proofs.";
    }

    this.loading = false;
    this.cdr.markForCheck();
  }

  toggleExpand(collectionId: string) {
    this.expandedId = this.expandedId === collectionId ? null : collectionId;
    this.cdr.markForCheck();
  }

  parseMembers(membershipData: string): ParsedMember[] {
    // Format: collectionId|userId1:level|userId2:level|...
    const parts = membershipData.split("|");
    if (parts.length < 2) {
      return [];
    }
    return parts.slice(1).filter(Boolean).map((part) => {
      const [userId, accessLevel] = part.split(":");
      return { userId, accessLevel: accessLevel || "unknown" };
    });
  }

  parseMemberCount(membershipData: string): number {
    return this.parseMembers(membershipData).length;
  }

  formatDate(timestamp: number): string {
    return new Date(timestamp).toLocaleString();
  }
}
