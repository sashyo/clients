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
    // Cache approved request bytes from requestTideOperatorApproval keyed by approval id.
    // The ORK embeds its policy authorization into the approved bytes; commit must use them.
    const approvedRequestCache = new Map<string, Uint8Array>();
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
          console.info("[TideWarden] [commit] Admin policy:", adminPolicyBase64 ? adminPolicyBase64.length + " chars" : "NOT AVAILABLE");

          // 2. Fetch pending approvals WITH enrichment (auto-generate policyRequestData if empty)
          const approvals = await backendAPI.getPendingPolicies();
          const enriched = await enrichApprovals(approvals);
          const approval = enriched.find((a: any) => a.id === id);
          console.info("[TideWarden] [commit] Matched approval:", approval ? { id: approval.id, roleId: approval.roleId, hasPolicyData: !!approval.policyRequestData, dataLen: approval.policyRequestData?.length } : "NOT FOUND");

          if (approval?.policyRequestData) {
            const heimdall = await import("heimdall-tide");
            const { PolicySignRequest } = heimdall;

            // 3. Use ORK-approved bytes from cache if available.
            // requestTideOperatorApproval embeds the ORK's policy authorization into the returned
            // request bytes; executeSignRequest requires those authorized bytes (not the original).
            // Decode from either cached approved bytes or original policyRequestData
            const cachedApprovedBytes = approvedRequestCache.get(id);
            const sourceBytes = cachedApprovedBytes
              ?? Uint8Array.from(atob(approval.policyRequestData), (c) => c.charCodeAt(0));
            if (cachedApprovedBytes) {
              console.info("[TideWarden] [commit] Using cached approved bytes (", cachedApprovedBytes.length, "bytes) for", id);
            } else {
              console.warn("[TideWarden] [commit] No cached approved bytes for", id, "— using policyRequestData");
            }
            const policyRequest = PolicySignRequest.decode(sourceBytes);

            // Always attach the admin policy — ORK PolicyAuthorizationFlow requires it
            if (adminPolicyBase64) {
              const adminPolicyBytes = Uint8Array.from(atob(adminPolicyBase64), (c) => c.charCodeAt(0));
              policyRequest.addPolicy(adminPolicyBytes);
              console.info("[TideWarden] [commit] Admin policy attached (", adminPolicyBytes.length, "bytes)");
            } else {
              console.warn("[TideWarden] [commit] No admin policy available — ORK may reject with PolicyAuthorizationFlow error");
            }
            let requestBytesForSign: Uint8Array = policyRequest.encode();

            // 4. Execute sign request; approved bytes are already ORK-initialized, no re-init
            console.info("[TideWarden] [commit] Calling executeSignRequest with", requestBytesForSign.length, "bytes");
            const signatures = await tideCloakService.executeSignRequest(requestBytesForSign, false);
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
          throw e; // Don't proceed with commit if signing failed
        }

        const doken = tideCloakService.getDoken() ?? undefined;
        console.info("[TideWarden] [commit] Calling backend commit with signedPolicyData:", signedPolicyData ? signedPolicyData.length + " chars" : "EMPTY", "sig:", signedPolicySignature ? signedPolicySignature.length + " chars" : "EMPTY", "doken:", doken ? "present" : "MISSING");
        await backendAPI.commit(id, signedPolicyData, signedPolicySignature, doken);
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
            // Cache approved bytes: ORK embeds its policy authorization into approved request
            for (const res of results) {
              if (res.status === "approved" && res.request?.length) {
                // @tideorg/ui prefixes ids with "approval-", strip it to get the real approval id
                const realId = res.id.replace(/^approval-/, "");
                approvedRequestCache.set(realId, res.request);
                console.info("[TideWarden] Cached approved bytes for", realId, "—", res.request.length, "bytes");
              }
            }
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
