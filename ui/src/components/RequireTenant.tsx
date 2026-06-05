import type { ReactNode } from "react";
import { useTenant } from "@/lib/tenant-context";
import { EmptyState, LoadingState } from "./ui";

/**
 * Gate for tenant-scoped pages: most control-plane endpoints require a
 * `{tenant_id}`. This resolves the currently-selected tenant and only
 * renders the page body once one is available, so individual pages can
 * assume a non-null tenant id.
 */
export function RequireTenant({
  children,
}: {
  children: (tenantId: string) => ReactNode;
}) {
  const { selectedTenantId, isLoading, tenants } = useTenant();
  if (isLoading) return <LoadingState label="Loading tenants…" />;
  if (!selectedTenantId || tenants.length === 0) {
    return (
      <EmptyState
        icon="◳"
        title="No tenant selected"
        hint="Create a tenant or pick one from the switcher in the top bar to manage its configuration."
      />
    );
  }
  return <>{children(selectedTenantId)}</>;
}
