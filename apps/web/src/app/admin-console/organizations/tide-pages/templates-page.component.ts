import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import { createBackendTemplateAPI } from "./tide-api.service";

@Component({
  selector: "app-org-templates-page",
  template: `<app-react-host [component]="templatesPage" [props]="templatesProps"></app-react-host>`,
  standalone: true,
  imports: [ReactHostComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrgTemplatesPageComponent implements OnInit {
  templatesPage: any;
  templatesProps: Record<string, any> = {};

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);

  ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    const { TemplatesPage } = require("@tideorg/ui");
    this.templatesPage = TemplatesPage;
    this.templatesProps = {
      api: createBackendTemplateAPI(this.apiService, orgId),
      title: "Policy Templates",
    };
  }
}
