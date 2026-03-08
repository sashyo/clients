/**
 * Tide-signed Collection Membership.
 *
 * Mirrors KeyleSSH's tideSsh.ts pattern:
 *   1. Build canonical membership string for a collection
 *   2. Create a BasicCustomRequest with Policy:1 auth flow (implicit — no popup)
 *   3. Add doken as authorizer + committed policy for contract validation
 *   4. createTideRequest → executeSignRequest → Ed25519 signature
 *   5. Return the membership data + base64 signature
 *
 * The signed membership proves that an org owner authorized the exact
 * set of users and their access levels.
 */

import { TideCloakService } from "@bitwarden/common/key-management/tidecloak/abstractions/tidecloak.service";

// Lazy-loaded Tide libraries
let BaseTideRequest: any;
let TideMemory: any;
let tideLibsLoaded = false;
let tideLibsAvailable = false;

async function ensureTideLibs(): Promise<void> {
  if (tideLibsLoaded) {
    if (!tideLibsAvailable) {
      throw new Error("Tide libraries (asgard-tide, heimdall-tide) not available");
    }
    return;
  }
  try {
    const asgard = await import("asgard-tide");
    const heimdall = await import("heimdall-tide");
    BaseTideRequest = asgard.BaseTideRequest;
    TideMemory = heimdall.TideMemory;
    tideLibsAvailable = true;
  } catch {
    tideLibsAvailable = false;
  }
  tideLibsLoaded = true;
  if (!tideLibsAvailable) {
    throw new Error("Tide libraries (asgard-tide, heimdall-tide) not available");
  }
}

export interface MemberEntry {
  userId: string;
  accessLevel: string;
}

export interface CanonicalMembership {
  collection: string;
  members: { vuid: string; role: string }[];
}

/**
 * Build a canonical membership JSON string for a collection.
 * collection field is "name:ownerVuid" format.
 * Members sorted by vuid — deterministic for signing.
 */
export function buildCanonicalMembership(
  collectionName: string,
  signerVuid: string,
  members: MemberEntry[],
): string {
  const sorted = [...members].sort((a, b) => a.userId.localeCompare(b.userId));
  const obj: CanonicalMembership = {
    collection: `${collectionName}:${signerVuid}`,
    members: sorted.map((m) => ({ vuid: m.userId, role: m.accessLevel })),
  };
  return JSON.stringify(obj);
}

/**
 * Parse a canonical membership JSON string back into its components.
 */
export function parseCanonicalMembership(data: string): CanonicalMembership {
  return JSON.parse(data) as CanonicalMembership;
}

/**
 * Sign a collection membership list via the Tide enclave.
 *
 * Uses BasicCustomRequest with Policy:1 (implicit flow — no operator popup).
 * The committed policy's Forseti contract validates that the signer has
 * the orgOwner role.
 *
 * @param collectionName - Human-readable collection name (for validation)
 * @param members - Full membership list (all users + levels for this collection)
 * @param tideCloakService - TideCloak service for enclave operations
 * @param committedPolicyData - Base64-encoded committed policy request data (optional)
 * @returns The canonical membership string + base64 Ed25519 signature
 * @throws Error if signing fails (caller must block the access change)
 */
export interface DynamicPolicyData {
  /** Executor's org role, e.g. "org:{orgUuid}:owner" */
  executorRole: string;
  /** Previous UserContext JSON (empty string if new user) */
  previousUserContext?: string;
  /** VVK signature over previous UserContext (base64) */
  previousUcSignature?: string;
  /** VVK public key (base64) */
  vvkPublicKey?: string;
}

export async function signCollectionMembership(
  collectionName: string,
  members: MemberEntry[],
  tideCloakService: TideCloakService,
  committedPolicyData: string | null,
  dynamicData?: DynamicPolicyData,
): Promise<{ membershipData: string; signature: string }> {
  console.info("[TideWarden] [1/7] Loading Tide libraries...");
  await ensureTideLibs();
  console.info("[TideWarden] [1/7] Tide libraries loaded OK");

  console.info("[TideWarden] [2/7] Ensuring TideCloak enclave is initialized...");
  const ready = await tideCloakService.ensureInitialized();
  console.info("[TideWarden] [2/7] ensureInitialized returned:", ready);
  if (!ready) {
    const hasConfig = await tideCloakService.hasPersistedConfig();
    throw new Error(
      `[TideWarden] TideCloak enclave not initialized — cannot sign membership. ` +
      `hasPersistedConfig=${hasConfig}, isInitialized=${tideCloakService.isInitialized()}`,
    );
  }

  // 3. Get signer's vuid from doken and build canonical membership string
  const rawDoken = tideCloakService.getDoken();
  let signerVuid = "";
  if (rawDoken) {
    try {
      const payload = JSON.parse(atob(rawDoken.split(".")[1]));
      signerVuid = payload.vuid || "";
    } catch {
      try {
        const payload = JSON.parse(rawDoken);
        signerVuid = payload.vuid || "";
      } catch { /* ignore */ }
    }
  }
  const membershipData = buildCanonicalMembership(collectionName, signerVuid, members);
  const draftBytes = new TextEncoder().encode(membershipData);
  console.info(
    `[TideWarden] [3/7] Built canonical membership: ${members.length} member(s), ` +
    `data="${membershipData.substring(0, 80)}${membershipData.length > 80 ? "..." : ""}"`,
  );

  // 4. Create BasicCustomRequest with dynamic data
  // Dynamic data layout: [0] executor role, [1] previous UC, [2] VVK sig, [3] VVK pubkey
  const encoder = new TextEncoder();
  const dynParts: Uint8Array[] = [
    encoder.encode(dynamicData?.executorRole || ""),
    encoder.encode(dynamicData?.previousUserContext || ""),
    dynamicData?.previousUcSignature
      ? Uint8Array.from(atob(dynamicData.previousUcSignature), (c) => c.charCodeAt(0))
      : new Uint8Array(0),
    dynamicData?.vvkPublicKey
      ? Uint8Array.from(atob(dynamicData.vvkPublicKey), (c) => c.charCodeAt(0))
      : new Uint8Array(0),
  ];
  const dynamicMemory = TideMemory.CreateFromArray(dynParts);
  console.info(`[TideWarden] [4/7] Dynamic data: executorRole="${dynamicData?.executorRole || ""}", prevUC=${(dynamicData?.previousUserContext?.length || 0)} bytes`);

  // Model ID must match the policy's model ID: UserContext:1
  const tideRequest = new BaseTideRequest(
    "UserContext",
    "1",
    "Policy:1",
    draftBytes,
    dynamicMemory,
  );
  console.info("[TideWarden] [4/7] UserContext sign request created");

  // 5. Add doken as authorizer
  const doken = tideCloakService.getDoken();
  console.info("[TideWarden] [5/7] getDoken returned:", doken ? `string(${doken.length} chars)` : "null");
  if (!doken) {
    throw new Error("[TideWarden] No doken available for signing — user may not be logged in via TideCloak");
  }
  const dokenBytes = new TextEncoder().encode(doken);
  const dokenMemory = TideMemory.CreateFromArray([dokenBytes]);
  tideRequest.addAuthorizer(dokenMemory);
  console.info("[TideWarden] [5/7] Doken added as authorizer");

  // 6. Attach the VVK-signed policy (if available).
  // committedPolicyData is a base64-encoded VVK-signed Policy bytes:
  // TideMemory([dataToVerify, vvkSignature]) — ready to use directly with addPolicy().
  if (committedPolicyData) {
    try {
      const policyBytes = Uint8Array.from(atob(committedPolicyData), (c) => c.charCodeAt(0));
      if (policyBytes.length > 0) {
        tideRequest.addPolicy(policyBytes);
        console.info(`[TideWarden] [6/7] Attached VVK-signed policy (${policyBytes.length} bytes)`);
      } else {
        console.warn("[TideWarden] [6/7] Committed policy data is empty");
      }
    } catch (e) {
      console.warn("[TideWarden] [6/7] Failed to decode committed policy:", e);
    }
  } else {
    console.info("[TideWarden] [6/7] No committed policy available, signing without it");
  }

  // 7a. Initialize request via enclave
  const encodedRequest = tideRequest.encode();
  console.info(`[TideWarden] [7a/7] Encoded request: ${encodedRequest.byteLength || encodedRequest.length} bytes, calling createTideRequest...`);
  const initializedBytes = await tideCloakService.createTideRequest(
    encodedRequest instanceof Uint8Array ? encodedRequest : new Uint8Array(encodedRequest),
  );
  console.info(`[TideWarden] [7a/7] createTideRequest returned ${initializedBytes?.byteLength || initializedBytes?.length} bytes`);

  // 7b. Execute sign request → get Ed25519 signature
  console.info("[TideWarden] [7b/7] Calling executeSignRequest...");
  const sigs = await tideCloakService.executeSignRequest(initializedBytes);
  console.info("[TideWarden] [7b/7] executeSignRequest returned:", sigs?.length, "signature(s)");
  const sig = sigs?.[0];
  if (!(sig instanceof Uint8Array)) {
    throw new Error(`[TideWarden] Tide enclave did not return a signature. Got: ${typeof sig}, sigs array: ${JSON.stringify(sigs?.map((s: any) => typeof s))}`);
  }
  if (sig.length !== 64) {
    throw new Error(`[TideWarden] Unexpected signature length: ${sig.length} (expected 64)`);
  }

  // 8. Base64-encode the signature
  const signature = btoa(String.fromCharCode(...sig));
  console.info(`[TideWarden] Membership signed successfully (${sig.length} bytes)`);

  return { membershipData, signature };
}
