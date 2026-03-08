import { ApiService } from "@bitwarden/common/abstractions/api.service";

export function createBackendTemplateAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/templates`;

  return {
    getTemplates: async () => {
      return await apiService.send("GET", basePath, null, true, true);
    },

    getTemplate: async (id: string) => {
      return await apiService.send("GET", `${basePath}/${id}`, null, true, true);
    },

    createTemplate: async (data: any) => {
      return await apiService.send("POST", basePath, data, true, true);
    },

    updateTemplate: async (id: string, data: any) => {
      return await apiService.send("PUT", `${basePath}/${id}`, data, true, true);
    },

    deleteTemplate: async (id: string) => {
      await apiService.send("DELETE", `${basePath}/${id}`, null, true, false);
    },
  };
}

export function createBackendPolicyApprovalsAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/policy-approvals`;

  return {
    getPendingPolicies: async () => {
      return await apiService.send("GET", basePath, null, true, true);
    },

    createApproval: async (data: {
      roleId: string;
      threshold: number;
      policyRequestData: string;
      contractCode?: string;
      requestedByEmail?: string;
    }) => {
      return await apiService.send("POST", basePath, data, true, true);
    },

    approve: async (id: string, rejected?: boolean, username?: string, policyRequestData?: string) => {
      await apiService.send("POST", `${basePath}/${id}/approve`, { rejected, username, policyRequestData }, true, false);
    },

    revoke: async (id: string, username?: string) => {
      await apiService.send("POST", `${basePath}/${id}/revoke`, { username }, true, false);
    },

    commit: async (id: string, signedPolicyData?: string, signedPolicySignature?: string) => {
      await apiService.send("POST", `${basePath}/${id}/commit`, { signedPolicyData, signedPolicySignature }, true, false);
    },

    cancel: async (id: string) => {
      await apiService.send("POST", `${basePath}/${id}/cancel`, null, true, false);
    },
  };
}

export function createBackendAccessMetadataAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/access-metadata`;

  return {
    getMetadata: async (changeSetId: string) => {
      try {
        return await apiService.send("GET", `${basePath}/${changeSetId}`, null, true, true);
      } catch {
        return null;
      }
    },

    getAllMetadata: async () => {
      return await apiService.send("GET", basePath, null, true, true);
    },

    saveMetadata: async (record: any) => {
      await apiService.send("POST", basePath, record, true, false);
    },

    deleteMetadata: async (changeSetId: string) => {
      await apiService.send("DELETE", `${basePath}/${changeSetId}`, null, true, false);
    },
  };
}

export function createBackendAdminAPI(apiService: ApiService, orgId: string): any {
  const rolesPath = `/organizations/${orgId}/tide/roles`;
  const usersPath = `/organizations/${orgId}/tide/users`;

  return {
    // Role management
    getRoles: async () => {
      return await apiService.send("GET", rolesPath, null, true, true);
    },

    getRole: async (roleName: string) => {
      const roles = await apiService.send("GET", rolesPath, null, true, true);
      return roles.find((r: any) => r.name === roleName) || null;
    },

    createRole: async (role: any) => {
      return await apiService.send("POST", rolesPath, role, true, true);
    },

    updateRole: async (roleName: string, role: any) => {
      const id = role.id || roleName;
      return await apiService.send("PUT", `${rolesPath}/${id}`, role, true, true);
    },

    deleteRole: async (roleName: string) => {
      return await apiService.send("DELETE", `${rolesPath}/${roleName}`, null, true, false);
    },

    // User management
    getUsers: async () => {
      return await apiService.send("GET", usersPath, null, true, true);
    },

    createUser: async (user: any) => {
      return await apiService.send("POST", usersPath, user, true, true);
    },

    updateUser: async (userId: string, user: any) => {
      return await apiService.send("PUT", `${usersPath}/${userId}`, user, true, true);
    },

    deleteUser: async (userId: string) => {
      await apiService.send("DELETE", `${usersPath}/${userId}`, null, true, false);
    },

    addUserRoles: async (userId: string, roles: any[]) => {
      const roleNames = roles.map((r: any) => (typeof r === "string" ? r : r.name));
      return await apiService.send(
        "POST",
        `${usersPath}/${userId}/roles`,
        { roles: roleNames },
        true,
        true,
      );
    },

    removeUserRoles: async (userId: string, roles: any[]) => {
      const roleNames = roles.map((r: any) => (typeof r === "string" ? r : r.name));
      return await apiService.send(
        "DELETE",
        `${usersPath}/${userId}/roles`,
        { roles: roleNames },
        true,
        true,
      );
    },

    setUserEnabled: async (userId: string, enabled: boolean) => {
      return await apiService.send(
        "PUT",
        `${usersPath}/${userId}/enabled`,
        { enabled },
        true,
        true,
      );
    },

    getTideLinkUrl: async (userId: string, redirectUri: string, _lifespan?: number) => {
      return await apiService.send(
        "POST",
        `${usersPath}/${userId}/tide-link`,
        { redirectUri },
        true,
        true,
      );
    },
  };
}

export function createBackendPolicyAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/role-policies`;

  return {
    getPolicy: async (roleName: string) => {
      try {
        const result = await apiService.send("GET", `${basePath}/${roleName}`, null, true, true);
        return result;
      } catch {
        return null;
      }
    },

    upsertPolicy: async (policy: any) => {
      return await apiService.send("POST", basePath, policy, true, true);
    },

    deletePolicy: async (roleName: string) => {
      await apiService.send("DELETE", `${basePath}/${roleName}`, null, true, false);
    },
  };
}

export function createBackendCollectionAccessAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide`;

  return {
    getCollections: async () => {
      return await apiService.send("GET", `${basePath}/collections`, null, true, true);
    },

    getUserAccess: async (userId: string) => {
      return await apiService.send(
        "GET",
        `${basePath}/users/${userId}/collection-access`,
        null,
        true,
        true,
      );
    },

    setUserAccess: async (
      userId: string,
      collectionId: string,
      accessLevel: string,
      membershipData?: string,
      signature?: string,
    ) => {
      return await apiService.send(
        "POST",
        `${basePath}/users/${userId}/collection-access`,
        { collectionId, accessLevel, membershipData, signature },
        true,
        true,
      );
    },

    removeUserAccess: async (
      userId: string,
      collectionId: string,
      membershipData?: string,
      signature?: string,
    ) => {
      await apiService.send(
        "POST",
        `${basePath}/users/${userId}/collection-access/remove`,
        { collectionId, membershipData, signature },
        true,
        false,
      );
    },

    getCommittedPolicy: async (roleName: string) => {
      return await apiService.send(
        "GET",
        `${basePath}/committed-policies/${encodeURIComponent(roleName)}`,
        null,
        true,
        true,
      );
    },

    getAdminPolicy: async () => {
      return await apiService.send("GET", `${basePath}/admin-policy`, null, true, true);
    },

    resetCryptoPolicy: async () => {
      return await apiService.send("DELETE", `${basePath}/crypto-policy`, null, true, true);
    },

    getMembershipSig: async (collectionId: string) => {
      return await apiService.send(
        "GET",
        `${basePath}/collection-membership-sig/${collectionId}`,
        null,
        true,
        true,
      );
    },

    storeMembershipSig: async (
      collectionId: string,
      membershipData: string,
      signature: string,
    ) => {
      return await apiService.send(
        "POST",
        `${basePath}/collection-membership-sig`,
        { collectionId, membershipData, signature },
        true,
        true,
      );
    },

    getTideUserContext: async (tcUserId: string, clientId: string) => {
      return await apiService.send(
        "GET",
        `${basePath}/user-context/${encodeURIComponent(tcUserId)}/${encodeURIComponent(clientId)}`,
        null,
        true,
        true,
      );
    },

    getVvkPublic: async () => {
      return await apiService.send("GET", `${basePath}/vvk-public`, null, true, true);
    },
  };
}

export function createBackendPolicyLogsAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/policy-logs`;

  return {
    getPolicyLogs: async (params: { first: number; max: number }) => {
      return await apiService.send(
        "GET",
        `${basePath}?first=${params.first}&max=${params.max}`,
        null,
        true,
        true,
      );
    },

    addLog: async (log: any) => {
      await apiService.send("POST", basePath, log, true, false);
    },
  };
}

export function createBackendChangeRequestAPI(apiService: ApiService, orgId: string): any {
  const basePath = `/organizations/${orgId}/tide/change-requests`;

  return {
    getPendingChangeSets: async () => {
      const [users, roles, clients] = await Promise.all([
        apiService.send("GET", `${basePath}/users`, null, true, true).catch((): any[] => []),
        apiService.send("GET", `${basePath}/roles`, null, true, true).catch((): any[] => []),
        apiService.send("GET", `${basePath}/clients`, null, true, true).catch((): any[] => []),
      ]);
      return [...(users || []), ...(roles || []), ...(clients || [])];
    },

    approveChangeSet: async (changeSet: any) => {
      return await apiService.send("POST", `${basePath}/sign`, changeSet, true, true);
    },

    commitChangeSet: async (changeSet: any) => {
      return await apiService.send("POST", `${basePath}/commit`, changeSet, true, true);
    },

    cancelChangeSet: async (changeSet: any) => {
      return await apiService.send("POST", `${basePath}/cancel`, changeSet, true, true);
    },

    getRawChangeSetRequest: async (changeSet: any) => {
      const result = await apiService.send("POST", `${basePath}/sign`, changeSet, true, true);
      if (Array.isArray(result)) return result;
      return [result];
    },

    approveChangeSetWithSignature: async (changeSet: any, signedRequest: string) => {
      // Step 1: Record the approval (add-review) with signed request data
      await apiService.send(
        "POST",
        `${basePath}/add-review`,
        {
          changeSetId: changeSet.changeSetId,
          changeSetType: changeSet.changeSetType,
          actionType: changeSet.actionType,
          requests: [signedRequest],
        },
        true,
        false,
      );
      // Step 2: Commit the change set
      await apiService.send(
        "POST",
        `${basePath}/commit`,
        changeSet,
        true,
        false,
      );
    },

    addReview: async (changeSet: any, signedRequests: string[]) => {
      await apiService.send(
        "POST",
        `${basePath}/add-review`,
        {
          changeSetId: changeSet.changeSetId,
          changeSetType: changeSet.changeSetType,
          actionType: changeSet.actionType,
          requests: signedRequests,
        },
        true,
        false,
      );
    },

    addRejection: async (changeSet: any) => {
      await apiService.send(
        "POST",
        `${basePath}/add-rejection`,
        {
          changeSetId: changeSet.changeSetId,
          changeSetType: changeSet.changeSetType,
          actionType: changeSet.actionType,
        },
        true,
        false,
      );
    },
  };
}
