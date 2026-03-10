/**
 * Tide Policy Workflow for TideWarden.
 *
 * Mirrors KeyleSSH's sshPolicy.ts:
 *   1. Create a PolicySignRequest with a Forseti contract
 *   2. Initialize (sign) it via the TideCloak enclave
 *   3. Encode to base64 for backend storage
 *
 * Uses heimdall-tide and asgard-tide (lazy-loaded).
 */

// Lazy-loaded Tide libraries
let PolicyV3: any; // @tideorg/js Policy (version 3) — modelIds as array
let PolicySignRequest: any;
let TideMemory: any;
let ApprovalType: any;
let ExecutionType: any;
let tideLibsLoaded = false;
let tideLibsAvailable = false;

export async function loadTideLibs(): Promise<boolean> {
  if (tideLibsLoaded) {
    return tideLibsAvailable;
  }
  try {
    const heimdall = await import("heimdall-tide");
    const asgard = await import("asgard-tide");
    const tideorgJs = await import("@tideorg/js/dist/Models/Policy.js");
    PolicyV3 = tideorgJs.Policy;       // latestVersion = "3", modelIds as array
    PolicySignRequest = heimdall.PolicySignRequest;
    TideMemory = asgard.TideMemory;
    ApprovalType = asgard.ApprovalType;
    ExecutionType = asgard.ExecutionType;
    tideLibsAvailable = true;
  } catch {
    tideLibsAvailable = false;
  }
  tideLibsLoaded = true;
  return tideLibsAvailable;
}

export function areTideLibsAvailable(): boolean {
  return tideLibsAvailable;
}

// Model IDs — same pattern as KeyleSSH
export const MODEL_IDS = {
  USER_CONTEXT: "UserContext:1",
  BASIC: "BasicCustom<Role>:BasicCustom<1>",
  DYNAMIC: "DynamicCustom<Role>:DynamicCustom<1>",
  DYNAMIC_APPROVED: "DynamicApprovedCustom<Role>:DynamicApprovedCustom<1>",
  ENCRYPTION: "PolicyEnabledEncryption:1",
  DECRYPTION: "PolicyEnabledDecryption:1",
} as const;


export interface RolePolicyConfig {
  roleName: string;
  threshold: number;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  modelId?: string | string[];
  resource: string;
  vendorId: string;
  contractCode: string;
  templateParams?: Record<string, any>;
}

/**
 * Compute the contract ID (SHA-512 hash of source code).
 * Must match what Ork computes.
 */
export async function computeContractId(source: string): Promise<string> {
  const data = new TextEncoder().encode(source);
  const hashBuffer = await crypto.subtle.digest("SHA-512", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/**
 * Detect the entry class name from C# contract source.
 */
function detectEntryType(source: string): string | null {
  const match = source.match(/public\s+class\s+(\w+)\s*:\s*IAccessPolicy/);
  return match ? match[1] : null;
}

/**
 * Creates a PolicySignRequest, initializes it via the TideCloak enclave,
 * and returns the base64-encoded initialized request.
 *
 * Initialization happens here at creation time so the request is ready for
 * the sign/approve step. Commit should NOT re-initialize (no double init).
 */
export async function createSignedPolicyRequest(
  config: RolePolicyConfig,
  tideCloakService: { createTideRequest: (data: Uint8Array) => Promise<Uint8Array> },
): Promise<{ policyRequestBase64: string; contractId: string }> {
  if (!tideLibsAvailable) {
    throw new Error("Tide libraries (heimdall-tide, asgard-tide) not loaded. Call loadTideLibs() first.");
  }

  // 1. Compute contract ID from source (SHA-512 hash)
  const contractId = await computeContractId(config.contractCode);

  // 2. Detect entry type from contract source
  const entryType = detectEntryType(config.contractCode) || "Contract";

  // 3. Create Policy object with parameters
  const policyParams = new Map<string, any>();
  policyParams.set("threshold", config.threshold);
  policyParams.set("Resource", config.resource);
  policyParams.set("approval_type", config.approvalType);
  policyParams.set("execution_type", config.executionType);

  // Auto-merge any extra template params into the policy
  if (config.templateParams) {
    for (const [key, value] of Object.entries(config.templateParams)) {
      policyParams.set(key, value);
    }
  }

  // Use v3 policy format (modelIds as array)
  const modelIdArray = Array.isArray(config.modelId)
    ? config.modelId
    : [config.modelId || MODEL_IDS.USER_CONTEXT];

  const policy = new PolicyV3({
    version: "3",
    modelId: modelIdArray,
    contractId: contractId,
    keyId: config.vendorId,
    approvalType: config.approvalType === "explicit" ? ApprovalType.EXPLICIT : ApprovalType.IMPLICIT,
    executionType: config.executionType === "private" ? ExecutionType.PRIVATE : ExecutionType.PUBLIC,
    params: policyParams,
  });

  // 4. Create PolicySignRequest
  const policyRequest = PolicySignRequest.New(policy);
  const policyBytes = policy.toBytes();

  // 5. Attach Forseti contract transport
  // Structure: [contractType, [empty, [sourceCode, entryType]]]
  const contractTypeBytes = new TextEncoder().encode("forseti");
  const sourceCodeBytes = new TextEncoder().encode(config.contractCode);
  const entryTypeBytes = new TextEncoder().encode(entryType);
  const innerPayload = TideMemory.CreateFromArray([sourceCodeBytes, entryTypeBytes]);
  const forsetiData = TideMemory.CreateFromArray([new Uint8Array(0), innerPayload]);
  const contractTransport = TideMemory.CreateFromArray([contractTypeBytes, forsetiData]);

  const draftWithContract = TideMemory.CreateFromArray([policyBytes, contractTransport]);
  policyRequest.draft = draftWithContract;
  policyRequest.setCustomExpiry(604800); // 7 days

  // 6. Initialize via TideCloak enclave (createTideRequest).
  // This sets up ORK nonces/session data so the request is ready for sign/approve.
  // Commit must NOT re-initialize — no double initialization.
  const encodedRequest = policyRequest.encode();
  const initializedBytes = await tideCloakService.createTideRequest(encodedRequest);
  const initializedRequest = PolicySignRequest.decode(initializedBytes);
  const policyRequestBase64 = bytesToBase64(initializedRequest.encode());

  return { policyRequestBase64, contractId };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
