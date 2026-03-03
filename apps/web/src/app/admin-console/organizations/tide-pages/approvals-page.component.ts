import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import {
  createBackendAccessMetadataAPI,
  createBackendPolicyApprovalsAPI,
  createBackendPolicyLogsAPI,
} from "./tide-api.service";

@Component({
  selector: "app-org-approvals-page",
  template: `<app-react-host [component]="approvalsPage" [props]="approvalsProps"></app-react-host>`,
  standalone: true,
  imports: [ReactHostComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrgApprovalsPageComponent implements OnInit {
  approvalsPage: any;
  approvalsProps: Record<string, any> = {};

  private route = inject(ActivatedRoute);
  private apiService = inject(ApiService);
  private tideCloakService = inject(TideCloakService);

  ngOnInit() {
    const orgId = this.route.snapshot.params["organizationId"] ?? "";
    const { ApprovalsPage } = require("@tideorg/ui");
    this.approvalsPage = ApprovalsPage;

    const tideCloakService = this.tideCloakService;

    this.approvalsProps = {
      policyApprovalsAPI: createBackendPolicyApprovalsAPI(this.apiService, orgId),
      policyLogsAPI: createBackendPolicyLogsAPI(this.apiService, orgId),
      accessMetadataAPI: createBackendAccessMetadataAPI(this.apiService, orgId),
      showPolicyTab: true,
      title: "Approvals",
      tideContext: {
        initializeTideRequest: async <T extends { encode: () => Uint8Array }>(
          request: T,
        ): Promise<T> => {
          // Ensure enclave is initialized (may have been lost on page refresh)
          await tideCloakService.ensureInitialized();

          const encodedRequest = request.encode();
          const initializedBytes = await tideCloakService.createTideRequest(encodedRequest);

          const RequestClass = (request as any).constructor;
          if (typeof RequestClass.decode === "function") {
            return RequestClass.decode(initializedBytes) as T;
          }
          return request;
        },
        approveTideRequests: async (
          requests: { id: string; request: Uint8Array }[],
        ): Promise<
          { id: string; approved?: { request: Uint8Array }; denied?: boolean; pending?: boolean }[]
        > => {
          console.info(
            "[TideWarden] approveTideRequests called with",
            requests.length,
            "request(s):",
            requests.map((r) => ({ id: r.id, bytes: r.request?.length })),
          );

          // Ensure enclave is initialized (may have been lost on page refresh)
          const ready = await tideCloakService.ensureInitialized();
          if (!ready) {
            console.error("[TideWarden] TideCloak enclave not available for approvals");
            throw new Error("TideCloak enclave not initialized");
          }

          console.info("[TideWarden] Enclave ready, calling requestTideOperatorApproval...");

          try {
            const results = await tideCloakService.approveTideRequests(requests);
            console.info(
              "[TideWarden] Enclave results:",
              results.map((r) => ({ id: r.id, status: r.status })),
            );
            return results.map((res) => {
              if (res.status === "approved") {
                return { id: res.id, approved: { request: res.request } };
              } else if (res.status === "denied") {
                return { id: res.id, denied: true };
              } else {
                return { id: res.id, pending: true };
              }
            });
          } catch (e) {
            console.error("[TideWarden] Error in approveTideRequests:", e);
            return requests.map((req) => ({ id: req.id, pending: true }));
          }
        },
      },
    };
  }
}
