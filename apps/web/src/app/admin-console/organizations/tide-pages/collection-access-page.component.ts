import { CommonModule } from "@angular/common";
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnInit, inject } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

import { createBackendAdminAPI, createBackendCollectionAccessAPI } from "./tide-api.service";

interface CollectionItem {
  id: string;
  name: string;
}

interface UserItem {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
}

interface AccessEntry {
  collectionId: string;
  collectionName: string;
  accessLevel: string;
}

@Component({
  selector: "app-org-collection-access-page",
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="tw-p-6 tw-max-w-4xl">
      <h1 class="tw-text-xl tw-font-semibold tw-mb-4">Collection Access</h1>
      <p class="tw-text-sm tw-text-muted tw-mb-6">
        Manage which collections each user can access and their permission level.
      </p>

      <!-- User selector -->
      <div class="tw-mb-6">
        <label class="tw-block tw-text-sm tw-font-medium tw-mb-1">Select User</label>
        <select
          class="tw-w-full tw-max-w-md tw-border tw-border-secondary-500 tw-rounded tw-px-3 tw-py-2 tw-bg-background"
          [(ngModel)]="selectedUserId"
          (ngModelChange)="onUserSelected()"
        >
          <option value="">-- Select a user --</option>
          <option *ngFor="let user of users" [value]="user.id">
            {{ user.username || user.email }}
            <span *ngIf="user.firstName || user.lastName">
              ({{ user.firstName }} {{ user.lastName }})
            </span>
          </option>
        </select>
      </div>

      <!-- Loading -->
      <div *ngIf="loading" class="tw-text-sm tw-text-muted tw-py-4">Loading...</div>

      <!-- Current access table -->
      <div *ngIf="selectedUserId && !loading">
        <h2 class="tw-text-lg tw-font-medium tw-mb-3">Current Access</h2>

        <div *ngIf="userAccess.length === 0" class="tw-text-sm tw-text-muted tw-py-2 tw-mb-4">
          This user has no collection access assigned.
        </div>

        <table *ngIf="userAccess.length > 0" class="tw-w-full tw-mb-4 tw-text-sm">
          <thead>
            <tr class="tw-border-b tw-border-secondary-500">
              <th class="tw-text-left tw-py-2 tw-pr-4">Collection</th>
              <th class="tw-text-left tw-py-2 tw-pr-4">Access Level</th>
              <th class="tw-text-left tw-py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let entry of userAccess" class="tw-border-b tw-border-secondary-300">
              <td class="tw-py-2 tw-pr-4">{{ entry.collectionName }}</td>
              <td class="tw-py-2 tw-pr-4">
                <select
                  class="tw-border tw-border-secondary-500 tw-rounded tw-px-2 tw-py-1 tw-bg-background tw-text-sm"
                  [ngModel]="entry.accessLevel"
                  (ngModelChange)="changeAccess(entry.collectionId, $event)"
                  [disabled]="saving"
                >
                  <option value="read">Read</option>
                  <option value="write">Write</option>
                  <option value="manage">Manage</option>
                </select>
              </td>
              <td class="tw-py-2">
                <button
                  class="tw-text-danger tw-text-sm tw-underline hover:tw-no-underline"
                  [disabled]="saving"
                  (click)="removeAccess(entry.collectionId)"
                >
                  Remove
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Add new access -->
        <h2 class="tw-text-lg tw-font-medium tw-mb-3 tw-mt-6">Add Collection Access</h2>

        <div *ngIf="availableCollections.length === 0" class="tw-text-sm tw-text-muted tw-py-2">
          All collections are already assigned to this user.
        </div>

        <div *ngIf="availableCollections.length > 0" class="tw-flex tw-gap-3 tw-items-end">
          <div>
            <label class="tw-block tw-text-sm tw-font-medium tw-mb-1">Collection</label>
            <select
              class="tw-border tw-border-secondary-500 tw-rounded tw-px-3 tw-py-2 tw-bg-background"
              [(ngModel)]="newCollectionId"
            >
              <option value="">-- Select --</option>
              <option *ngFor="let col of availableCollections" [value]="col.id">
                {{ col.name }}
              </option>
            </select>
          </div>
          <div>
            <label class="tw-block tw-text-sm tw-font-medium tw-mb-1">Access Level</label>
            <select
              class="tw-border tw-border-secondary-500 tw-rounded tw-px-3 tw-py-2 tw-bg-background"
              [(ngModel)]="newAccessLevel"
            >
              <option value="read">Read</option>
              <option value="write">Write</option>
              <option value="manage">Manage</option>
            </select>
          </div>
          <button
            class="tw-bg-primary-600 tw-text-contrast tw-px-4 tw-py-2 tw-rounded tw-text-sm hover:tw-bg-primary-700 disabled:tw-opacity-50"
            [disabled]="!newCollectionId || saving"
            (click)="addAccess()"
          >
            {{ saving ? "Saving..." : "Add" }}
          </button>
        </div>

        <!-- Error message -->
        <div *ngIf="errorMessage" class="tw-text-danger tw-text-sm tw-mt-3">
          {{ errorMessage }}
        </div>
      </div>
    </div>
  `,
})
export class OrgCollectionAccessPageComponent implements OnInit {
  users: UserItem[] = [];
  collections: CollectionItem[] = [];
  userAccess: AccessEntry[] = [];
  selectedUserId = "";
  newCollectionId = "";
  newAccessLevel = "write";
  loading = false;
  saving = false;
  errorMessage = "";

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private cdr = inject(ChangeDetectorRef);

  private orgId = "";
  private adminAPI: any;
  private collectionAccessAPI: any;

  async ngOnInit() {
    this.orgId = this.route.snapshot.params["organizationId"] ?? "";
    this.adminAPI = createBackendAdminAPI(this.apiService, this.orgId);
    this.collectionAccessAPI = createBackendCollectionAccessAPI(this.apiService, this.orgId);

    this.loading = true;
    this.cdr.markForCheck();

    try {
      const [users, collections] = await Promise.all([
        this.adminAPI.getUsers(),
        this.collectionAccessAPI.getCollections(),
      ]);
      console.info("[TideWarden] Loaded users:", users?.length, "collections:", collections?.length);
      this.users = users || [];
      this.collections = collections || [];
    } catch (e: any) {
      console.error("[TideWarden] Failed to load users or collections:", e);
      this.errorMessage = "Failed to load users or collections.";
    }

    this.loading = false;
    this.cdr.markForCheck();
  }

  async onUserSelected() {
    console.info("[TideWarden] onUserSelected called, selectedUserId:", this.selectedUserId);
    if (!this.selectedUserId) {
      this.userAccess = [];
      this.cdr.markForCheck();
      return;
    }

    this.loading = true;
    this.errorMessage = "";
    this.cdr.markForCheck();

    try {
      console.info("[TideWarden] Fetching access for user:", this.selectedUserId);
      this.userAccess = (await this.collectionAccessAPI.getUserAccess(this.selectedUserId)) || [];
      console.info("[TideWarden] User access loaded:", this.userAccess.length, "entries");
    } catch (e: any) {
      console.error("[TideWarden] Failed to load user access:", e);
      this.userAccess = [];
      this.errorMessage = "Failed to load user access.";
    }

    this.loading = false;
    this.cdr.markForCheck();
  }

  get availableCollections(): CollectionItem[] {
    const assignedIds = new Set(this.userAccess.map((a) => a.collectionId));
    return this.collections.filter((c) => !assignedIds.has(c.id));
  }

  async addAccess() {
    if (!this.newCollectionId || !this.selectedUserId) {
      return;
    }

    this.saving = true;
    this.errorMessage = "";
    this.cdr.markForCheck();

    try {
      await this.collectionAccessAPI.setUserAccess(
        this.selectedUserId,
        this.newCollectionId,
        this.newAccessLevel,
      );
      this.newCollectionId = "";
      await this.onUserSelected();
    } catch (e: any) {
      this.errorMessage = e?.message || "Failed to set collection access.";
    }

    this.saving = false;
    this.cdr.markForCheck();
  }

  async changeAccess(collectionId: string, newLevel: string) {
    this.saving = true;
    this.errorMessage = "";
    this.cdr.markForCheck();

    try {
      await this.collectionAccessAPI.setUserAccess(
        this.selectedUserId,
        collectionId,
        newLevel,
      );
      await this.onUserSelected();
    } catch (e: any) {
      this.errorMessage = e?.message || "Failed to update access level.";
    }

    this.saving = false;
    this.cdr.markForCheck();
  }

  async removeAccess(collectionId: string) {
    this.saving = true;
    this.errorMessage = "";
    this.cdr.markForCheck();

    try {
      await this.collectionAccessAPI.removeUserAccess(
        this.selectedUserId,
        collectionId,
      );
      await this.onUserSelected();
    } catch (e: any) {
      this.errorMessage = e?.message || "Failed to remove access.";
    }

    this.saving = false;
    this.cdr.markForCheck();
  }
}
