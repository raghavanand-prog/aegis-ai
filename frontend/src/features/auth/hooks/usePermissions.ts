import { useAuth } from "./useAuth";

/**
 * What the signed-in role may do.
 *
 * Used to hide controls the user cannot use. This is a usability measure only:
 * the backend enforces the same matrix on every request, so a hidden button and
 * a forged request are both refused.
 */
export function usePermissions() {
  const { user } = useAuth();
  const permissions = user?.permissions ?? [];

  const can = (permission: string): boolean => permissions.includes(permission);

  return {
    permissions,
    can,
    canPromoteEvents: can("events:promote"),
    canUpdateIncidents: can("incidents:update"),
    canRespond: can("incidents:respond"),
    // V9: requesting containment and signing one off are separate authorities,
    // and closing an incident is separate from working it.
    canApproveResponse: can("incidents:respond_approve"),
    canCloseIncidents: can("incidents:close"),
    canRunEvaluation: can("detection:evaluate"),
    canManageUsers: can("users:manage"),
    isReadOnly: permissions.length > 0 && !can("events:promote"),
  };
}
