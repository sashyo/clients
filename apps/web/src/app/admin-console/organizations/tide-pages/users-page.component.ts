import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import { createBackendAccessMetadataAPI, createBackendAdminAPI } from "./tide-api.service";

@Component({
  selector: "app-org-users-page",
  template: `<app-react-host [component]="usersPage" [props]="usersProps"></app-react-host>`,
  standalone: true,
  imports: [ReactHostComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrgUsersPageComponent implements OnInit {
  usersPage: any;
  usersProps: Record<string, any> = {};

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);

  ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    const { UsersPage } = require("@tideorg/ui");
    this.usersPage = UsersPage;
    this.usersProps = {
      adminAPI: createBackendAdminAPI(this.apiService, orgId),
      accessMetadataAPI: createBackendAccessMetadataAPI(this.apiService, orgId),
      title: "Members",
    };
  }
}
