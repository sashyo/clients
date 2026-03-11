import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

import { ReactHostComponent } from "../../../shared/react-host/react-host.component";

import { ORG_OWNER_CONTRACT } from "./collection-owner-contract";
import { ORG_CRYPTO_CONTRACT } from "./org-crypto-contract";
import {
  createBackendAccessMetadataAPI,
  createBackendChangeRequestAPI,
  createBackendCollectionAccessAPI,
  createBackendPolicyApprovalsAPI,
  createBackendPolicyLogsAPI,
} from "./tide-api.service";
import {
  areTideLibsAvailable,
  bytesToBase64,
  createSignedPolicyRequest,
  loadTideLibs,
  MODEL_IDS,
} from "./tide-policy.service";

@Component({
  selector: "app-org-approvals-page",
  template: `
    <app-react-host [component]="approvalsPage" [props]="approvalsProps"></app-react-host>
  `,
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
    const backendAPI = createBackendPolicyApprovalsAPI(this.apiService, orgId);
    const collectionAccessAPI = createBackendCollectionAccessAPI(this.apiService, orgId);
    // Wrap the policyApprovalsAPI to:
    // 1. Auto-populate policyRequestData for approvals created by backend (empty data)
    // 2. Handle signed policy data on commit via enclave
    const apiService = this.apiService;
    // Enrich approvals that have empty policyRequestData by auto-generating it
    // from the appropriate contract. Both orgOwner and appUser are detected by roleId.
    const enrichApprovals = async (policies: any[]) => {
      await loadTideLibs();
      await tideCloakService.ensureInitialized();
      const libsReady = areTideLibsAvailable();
      const enclaveReady = tideCloakService.isInitialized();
      console.info("[TideWarden] [enrich] libs:", libsReady, "enclave:", enclaveReady, "policies:", policies.length);
      if (libsReady && enclaveReady) {
        for (const policy of policies) {
          const needsEnrich = !policy.policyRequestData && !policy.contractCode;
          console.info("[TideWarden] [enrich] policy", policy.id, "roleId:", policy.roleId, "needsEnrich:", needsEnrich, "policyRequestData:", JSON.stringify(policy.policyRequestData)?.substring(0, 50), "contractCode:", policy.contractCode);
          if (needsEnrich) {
            try {
              const isAppUser = policy.roleId === "appUser";
              const contractCode = isAppUser ? ORG_CRYPTO_CONTRACT : ORG_OWNER_CONTRACT;
              const roleName = isAppUser ? "appUser" : "orgOwner";
              const config: any = {
                roleName,
                threshold: policy.threshold || 1,
                approvalType: isAppUser ? "implicit" : "explicit",
                executionType: isAppUser ? "private" : "public",
                resource: tideCloakService.getResource(),
                vendorId: tideCloakService.getVendorId(),
                contractCode,
              };
              if (isAppUser) {
                config.modelId = [MODEL_IDS.ENCRYPTION, MODEL_IDS.DECRYPTION];
              }
              console.info("[TideWarden] [enrich] Creating signed policy request for", roleName, "resource:", config.resource, "vendorId:", config.vendorId?.substring(0, 20));
              const { policyRequestBase64 } = await createSignedPolicyRequest(config, tideCloakService);
              console.info("[TideWarden] [enrich] Generated policyRequestBase64:", policyRequestBase64.length, "chars");
              await apiService.send(
                "PUT",
                `/organizations/${orgId}/tide/policy-approvals/${policy.id}/data`,
                { policyRequestData: policyRequestBase64, contractCode },
                true,
                false,
              );
              policy.policyRequestData = policyRequestBase64;
              policy.contractCode = contractCode;
              console.info(`[TideWarden] Auto-generated policyRequestData for ${roleName} approval`, policy.id);
            } catch (e) {
              console.error(`[TideWarden] [enrich] FAILED for ${policy.roleId}:`, e);
            }
          }
        }
      }
      return policies;
    };

    const policyApprovalsAPI = {
      ...backendAPI,
      getPendingPolicies: async () => {
        const policies = await backendAPI.getPendingPolicies();
        return enrichApprovals(policies);
      },
      commit: async (id: string) => {
        let signedPolicyData: string | undefined;
        let signedPolicySignature: string | undefined;

        try {
          // 0. Ensure enclave is initialized before signing
          await loadTideLibs();
          await tideCloakService.ensureInitialized();

          // 1. Fetch admin policy
          const adminPolicyResponse = await collectionAccessAPI.getAdminPolicy();
          const adminPolicyBase64: string | null = adminPolicyResponse?.adminPolicy || null;

          // 2. Fetch pending approvals WITH enrichment (auto-generate policyRequestData if empty)
          const approvals = await backendAPI.getPendingPolicies();
          const enriched = await enrichApprovals(approvals);
          const approval = enriched.find((a: any) => a.id === id);
          console.info("[TideWarden] [commit] Matched approval:", approval ? { id: approval.id, roleId: approval.roleId, hasPolicyData: !!approval.policyRequestData, dataLen: approval.policyRequestData?.length } : "NOT FOUND");

          if (approval?.policyRequestData) {
            const heimdall = await import("heimdall-tide");
            const { PolicySignRequest } = heimdall;

            // 3. Decode and add admin policy
            const requestBytes = Uint8Array.from(atob(approval.policyRequestData), (c) => c.charCodeAt(0));
            const policyRequest = (PolicySignRequest as any).decode(requestBytes);
            if (adminPolicyBase64) {
              const adminPolicyBytes = Uint8Array.from(atob(adminPolicyBase64), (c) => c.charCodeAt(0));
              policyRequest.addPolicy(adminPolicyBytes);
            }

            // 4. Execute sign request with re-initialization for fresh nonces
            const encoded = policyRequest.encode();
            console.info("[TideWarden] [commit] Calling executeSignRequest with", encoded.length, "bytes");
            const signatures = await tideCloakService.executeSignRequest(encoded, true);
            const policySignature = signatures?.[0];

            if (!policySignature) {
              throw new Error("No signature received from executeSignRequest");
            }

            // 5. Build signed policy: initCert + initCertSig
            const policy = policyRequest.getRequestedPolicy();
            policy.signature = policySignature;
            const signedPolicyBytes = policy.toBytes();
            signedPolicyData = bytesToBase64(signedPolicyBytes);
            signedPolicySignature = bytesToBase64(policySignature);
            console.info("[TideWarden] [commit] Signed policy:", signedPolicyBytes.length, "bytes, sig:", policySignature.length, "bytes");
          } else {
            console.warn("[TideWarden] [commit] No policyRequestData found for approval", id);
          }
        } catch (e) {
          console.error("[TideWarden] [commit] Failed to execute policy sign request:", e);
          alert("[TideWarden] Commit signing failed: " + ((e as any)?.message || e));
        }

        console.info("[TideWarden] [commit] Calling backend commit with signedPolicyData:", signedPolicyData ? signedPolicyData.length + " chars" : "EMPTY", "sig:", signedPolicySignature ? signedPolicySignature.length + " chars" : "EMPTY");
        await backendAPI.commit(id, signedPolicyData, signedPolicySignature);
      },
    };

    this.approvalsProps = {
      adminAPI: createBackendChangeRequestAPI(this.apiService, orgId),
      policyApprovalsAPI,
      policyLogsAPI: createBackendPolicyLogsAPI(this.apiService, orgId),
      accessMetadataAPI: createBackendAccessMetadataAPI(this.apiService, orgId),
      showPolicyTab: true,
      title: "Approvals",
      tideContext: {
        initializeTideRequest: async <T extends { encode: () => Uint8Array }>(
          request: T,
        ): Promise<T> => {
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
