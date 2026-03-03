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

    approve: async (id: string, rejected?: boolean, username?: string) => {
      await apiService.send("POST", `${basePath}/${id}/approve`, { rejected, username }, true, false);
    },

    revoke: async (id: string, username?: string) => {
      await apiService.send("POST", `${basePath}/${id}/revoke`, { username }, true, false);
    },

    commit: async (id: string) => {
      await apiService.send("POST", `${basePath}/${id}/commit`, null, true, false);
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

    setUserAccess: async (userId: string, collectionId: string, accessLevel: string) => {
      return await apiService.send(
        "POST",
        `${basePath}/users/${userId}/collection-access`,
        { collectionId, accessLevel },
        true,
        true,
      );
    },

    removeUserAccess: async (userId: string, collectionId: string) => {
      await apiService.send(
        "DELETE",
        `${basePath}/users/${userId}/collection-access/${collectionId}`,
        null,
        true,
        false,
      );
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
