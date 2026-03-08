/**
 * Org Owner Access Policy for TideWarden.
 *
 * Ensures the executor can only grant roles scoped to their own org.
 * Trusts pre-existing roles from previous UserContext.
 *
 * PolicyParam:
 *   Resource — allowed resource_access key (e.g. "tidewarden")
 *
 * DynamicData layout:
 *   [0] = executor role (e.g. "org:abc123:owner")
 *   [1] = previous UserContext JSON bytes (empty if new user)
 *   [2] = VVK signature over previous UserContext
 *   [3] = VVK public key
 */

export const ORG_OWNER_CONTRACT = `using Cryptide.Key;
using Ork.Forseti.Sdk;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

public class Contract : IAccessPolicy
{
	[PolicyParam(Required = true, Description = "Allowed resource_access key (e.g. tidewarden)")]
	public string Resource { get; set; }

	private static bool TryExtractOrgId(string role, out string orgId)
	{
		orgId = "";
		if (!role.StartsWith("org:", StringComparison.Ordinal)) return false;
		var secondColon = role.IndexOf(':', 4);
		if (secondColon <= 4) return false;
		orgId = role.Substring(4, secondColon - 4);
		return orgId.Length > 0;
	}

	private static HashSet<string> CollectResourceRoles(JsonElement root, string resource)
	{
		var roles = new HashSet<string>(StringComparer.Ordinal);
		if (root.TryGetProperty("resource_access", out var ra) &&
			ra.TryGetProperty(resource, out var client) &&
			client.TryGetProperty("roles", out var arr) &&
			arr.ValueKind == JsonValueKind.Array)
		{
			foreach (var r in arr.EnumerateArray())
			{
				var s = r.GetString();
				if (s != null) roles.Add(s);
			}
		}
		return roles;
	}

	/// <summary>
	/// Read TideMemory field at index from byte[].
	/// Each field: 4-byte LE length prefix + data.
	/// startOffset lets callers skip a TideMemory version header (4 bytes).
	/// </summary>
	private static bool TryReadField(byte[] buffer, int index, out byte[] result, int startOffset = 0)
	{
		result = Array.Empty<byte>();
		int offset = startOffset;
		for (int i = 0; i <= index; i++)
		{
			if (offset + 4 > buffer.Length) return false;
			int len = BitConverter.ToInt32(buffer, offset);
			offset += 4;
			if (len < 0 || offset + len > buffer.Length) return false;
			if (i == index)
			{
				result = new byte[len];
				Array.Copy(buffer, offset, result, 0, len);
				return len > 0;
			}
			offset += len;
		}
		return false;
	}

	public PolicyDecision ValidateData(DataContext ctx)
	{
		if (ctx.Data == null || ctx.Data.Length == 0)
			return PolicyDecision.Deny("No data provided");
		if (ctx.DynamicData == null || ctx.DynamicData.Length == 0)
			return PolicyDecision.Deny("Dynamic data is empty");

		// [0] executor role -> extract org UUID
		if (!TryReadField(ctx.DynamicData, 0, out var roleBytes))
			return PolicyDecision.Deny("Role missing from dynamic data[0]");

		var executorRole = Encoding.UTF8.GetString(roleBytes);
		if (!TryExtractOrgId(executorRole, out var allowedOrgId))
			return PolicyDecision.Deny($"Cannot extract org UUID from role '{executorRole}'");

		var ownOrgPrefix = "org:" + allowedOrgId + ":";

		// [1] previous UC, [2] signature, [3] VVK public key
		HashSet<string> previousRoles;
		bool hasPreviousUc = TryReadField(ctx.DynamicData, 1, out var prevUcBytes);

		if (hasPreviousUc)
		{
			if (!TryReadField(ctx.DynamicData, 2, out var sigBytes))
				return PolicyDecision.Deny("Previous UC signature missing from dynamic data[2]");
			if (!TryReadField(ctx.DynamicData, 3, out var vvkPubBytes))
				return PolicyDecision.Deny("VVK public key missing from dynamic data[3]");

			try
			{
				var vvkKey = TideKey.From((ReadOnlyMemory<byte>)vvkPubBytes);
				if (!vvkKey.Verify((ReadOnlyMemory<byte>)prevUcBytes, (ReadOnlyMemory<byte>)sigBytes))
					return PolicyDecision.Deny("Previous UserContext signature verification failed");
			}
			catch (Exception ex)
			{
				return PolicyDecision.Deny($"Signature verification error: {ex.Message}");
			}

			JsonDocument prevDoc;
			try { prevDoc = JsonDocument.Parse(prevUcBytes); }
			catch (JsonException)
			{
				return PolicyDecision.Deny("Previous UserContext is not valid JSON");
			}
			using (prevDoc) { previousRoles = CollectResourceRoles(prevDoc.RootElement, Resource); }
		}
		else
		{
			previousRoles = new HashSet<string>(StringComparer.Ordinal);
		}

		// Validate each new UserContext in Draft
		int i = 0;
		bool found = false;

		while (TryReadField(ctx.Data, i, out var ucBytes, 4))
		{
			found = true;
			if (ucBytes.Length == 0) { i++; continue; }

			JsonDocument doc;
			try { doc = JsonDocument.Parse(ucBytes); }
			catch (JsonException)
			{
				return PolicyDecision.Deny($"UserContext[{i}] is not valid JSON");
			}

			using (doc)
			{
				var root = doc.RootElement;

				if (root.TryGetProperty("resource_access", out var resAccess) &&
					resAccess.ValueKind == JsonValueKind.Object &&
					resAccess.TryGetProperty(Resource, out var resourceClient))
				{
					if (!resourceClient.TryGetProperty("roles", out var roles) ||
						roles.ValueKind != JsonValueKind.Array)
						return PolicyDecision.Deny(
							$"UserContext[{i}] resource_access.{Resource}.roles missing or not an array");

					foreach (var role in roles.EnumerateArray())
					{
						var r = role.GetString();
						if (r == null)
							return PolicyDecision.Deny($"UserContext[{i}] contains null role");

						// Skip global roles (not org-scoped)
						if (r.Equals("orgOwner", StringComparison.Ordinal))
							continue;
						if (r.Equals("orgUser", StringComparison.Ordinal))
							continue;
						if (r.Equals("appUser", StringComparison.Ordinal))
							continue;

						if (r.StartsWith(ownOrgPrefix, StringComparison.Ordinal))
							continue;

						if (previousRoles.Contains(r))
							continue;

						return PolicyDecision.Deny(
							$"UserContext[{i}] role '{r}' is not scoped to org '{allowedOrgId}' and not pre-existing");
					}
				}

				// Ensure non-org pre-existing roles are preserved
				var newRoles = CollectResourceRoles(root, Resource);
				foreach (var prev in previousRoles)
				{
					if (prev.StartsWith(ownOrgPrefix, StringComparison.Ordinal))
						continue;

					if (!newRoles.Contains(prev))
						return PolicyDecision.Deny(
							$"UserContext[{i}] cannot remove pre-existing role '{prev}'");
				}
			}

			i++;
		}

		if (!found) return PolicyDecision.Deny("No UserContexts found in data");
		return PolicyDecision.Allow();
	}

	public PolicyDecision ValidateApprovers(ApproversContext ctx)
	{
		if (ctx.DynamicData == null || ctx.DynamicData.Length == 0)
			return PolicyDecision.Deny("Dynamic data is empty");

		if (!TryReadField(ctx.DynamicData, 0, out var roleBytes))
			return PolicyDecision.Deny("Role missing from dynamic data[0]");

		var role = Encoding.UTF8.GetString(roleBytes);
		if (string.IsNullOrWhiteSpace(role))
			return PolicyDecision.Deny("Role in dynamic data is empty");

		var approvers = DokenDto.WrapAll(ctx.Dokens);
		return Decision
			.Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
			.RequireAnyWithRole(approvers, Resource, role);
	}

	public PolicyDecision ValidateExecutor(ExecutorContext ctx)
	{
		if (ctx.DynamicData == null || ctx.DynamicData.Length == 0)
			return PolicyDecision.Deny("Dynamic data is empty");

		if (!TryReadField(ctx.DynamicData, 0, out var roleBytes))
			return PolicyDecision.Deny("Role missing from dynamic data[0]");

		var role = Encoding.UTF8.GetString(roleBytes);
		if (string.IsNullOrWhiteSpace(role))
			return PolicyDecision.Deny("Role in dynamic data is empty");

		if (!TryExtractOrgId(role, out _))
			return PolicyDecision.Deny($"Executor role '{role}' does not follow org:uuid:role pattern");

		var executor = new DokenDto(ctx.Doken);
		return Decision
			.RequireNotExpired(executor)
			.RequireRole(executor, Resource, role);
	}
}`;
