/**
 * Org Crypto Access Policy for TideWarden.
 *
 * Realm-wide policy attached to the appUser role.
 * Controls encryption and decryption based on collection-scoped roles.
 *
 * Model IDs:
 *   PolicyEnabledEncryption:1 — encrypt data scoped to an org+collection
 *   PolicyEnabledDecryption:1 — decrypt data scoped to an org+collection
 *
 * Tags (embedded in draft):
 *   Each encrypt/decrypt request embeds tags like "org:{orgUuid}:collection:{collUuid}"
 *   in the TideMemory draft entries, identifying which org+collection the data belongs to.
 *
 * Role requirements:
 *   Encryption  → executor must have org:{orgUuid}:collection:{collUuid}:write OR :manage
 *   Decryption  → executor must have org:{orgUuid}:collection:{collUuid}:read, :write, OR :manage
 *
 * PolicyParam:
 *   Resource — the TideCloak client name (e.g. "tidewarden")
 */

export const ORG_CRYPTO_CONTRACT = `using Ork.Forseti.Sdk;
using Cryptide.Tools;
using Ork.Shared.Models.Contracts;
using System;
using System.Collections.Generic;
using System.Text;

public class Contract : IAccessPolicy
{
	[PolicyParam(Required = true, Description = "TideCloak client name (e.g. tidewarden)")]
	public string Resource { get; set; }

	private bool isEncryptionRequest = false;
	private List<string> DataTags = new();

	public PolicyDecision ValidateData(DataContext ctx)
	{
		if (ctx.RequestId == "PolicyEnabledEncryption:1")
		{
			isEncryptionRequest = true;
		}
		else if (ctx.RequestId == "PolicyEnabledDecryption:1")
		{
			isEncryptionRequest = false;
		}
		else
		{
			return PolicyDecision.Deny("This contract must only be used with PolicyEnabledEncryption/Decryption requests");
		}

		ReadOnlyMemory<byte> data = ctx.Data;
		if (isEncryptionRequest)
		{
			var time = data.GetValue(0);
			ReadOnlyMemory<byte> firstEntry = data.GetValue(1);

			// Tags start at index 2 in encryption entries: [C1, EphemeralKeySig, tag0, tag1, ...]
			for (int i = 2; firstEntry.TryGetValue(i, out var tag); i++)
			{
				DataTags.Add(Encoding.UTF8.GetString(tag.Span));
			}
		}
		else
		{
			ReadOnlyMemory<byte> firstEntry = data.GetValue(0);

			// Tags start at index 3 in decryption entries: [C1, Signature, Timestamp, tag0, tag1, ...]
			for (int i = 3; firstEntry.TryGetValue(i, out var tag); i++)
			{
				DataTags.Add(Encoding.UTF8.GetString(tag.Span));
			}
		}

		if (DataTags.Count == 0)
			return PolicyDecision.Deny("At least one data tag is required");

		// Validate all tags are valid collection scopes
		foreach (var tag in DataTags)
		{
			if (!IsValidCollectionScope(tag))
				return PolicyDecision.Deny("Invalid scope tag: " + tag + " — expected org:{uuid}:collection:{uuid}");
		}

		return PolicyDecision.Allow();
	}

	public PolicyDecision ValidateApprovers(ApproversContext ctx)
	{
		// Implicit approval — policy is VVK-signed, no per-request approver needed
		return PolicyDecision.Allow();
	}

	public PolicyDecision ValidateExecutor(ExecutorContext ctx)
	{
		var executor = new DokenDto(ctx.Doken);

		if (executor.IsNull || executor.IsExpired)
			return PolicyDecision.Deny("Credential is missing or expired");

		// For each scope tag extracted in ValidateData, verify collection role
		foreach (var scope in DataTags)
		{
			if (isEncryptionRequest)
			{
				// Encryption requires write or manage role on the collection
				if (!executor.HasAnyRole(Resource, scope + ":write", scope + ":manage"))
					return PolicyDecision.Deny(
						"Encryption denied: executor lacks write or manage role for " + scope + " on " + Resource);
			}
			else
			{
				// Decryption requires read, write, or manage role on the collection
				if (!executor.HasAnyRole(Resource, scope + ":read", scope + ":write", scope + ":manage"))
					return PolicyDecision.Deny(
						"Decryption denied: executor lacks read, write, or manage role for " + scope + " on " + Resource);
			}
		}

		return PolicyDecision.Allow();
	}

	private static bool IsValidCollectionScope(string tag)
	{
		// Expected format: org:{uuid}:collection:{uuid}
		if (!tag.StartsWith("org:", StringComparison.Ordinal)) return false;
		var collIdx = tag.IndexOf(":collection:", 4, StringComparison.Ordinal);
		if (collIdx <= 4) return false;
		var collUuidStart = collIdx + ":collection:".Length;
		return collUuidStart < tag.Length;
	}
}`;
