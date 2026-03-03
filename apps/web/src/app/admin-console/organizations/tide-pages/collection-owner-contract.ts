/**
 * Default Forseti policy contract for the collectionOwner role.
 *
 * This contract enforces that only users with the "collectionOwner" role
 * (on the configured resource) can approve or execute vault operations.
 *
 * ValidateData: allows all data (no payload-specific validation needed).
 * ValidateApprovers: requires at least one approver with the collectionOwner role.
 * ValidateExecutor: requires the executor to have the collectionOwner role and not be expired.
 */

export const COLLECTION_OWNER_CONTRACT = `using Ork.Forseti.Sdk;
using System.Collections.Generic;

/// <summary>
/// Collection Owner Access Policy for TideWarden.
/// Grants access to users with the collectionOwner role.
/// </summary>
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for collection owner access")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check")]
    public string Resource { get; set; }

    public PolicyDecision ValidateData(DataContext ctx)
    {
        if (string.IsNullOrWhiteSpace(Role))
            return PolicyDecision.Deny("Role parameter is missing.");

        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, "tide-realm-admin");
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
    }
}`;

/** The role name this contract is designed for */
export const COLLECTION_OWNER_ROLE = "collectionOwner";
