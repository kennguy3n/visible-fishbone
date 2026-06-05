import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useListTenants } from "@/api/generated/endpoints/tenants/tenants";
import type { TenantResponse } from "@/api/generated/model";

interface TenantState {
  tenants: TenantResponse[];
  selectedTenantId: string | null;
  selectedTenant: TenantResponse | null;
  setSelectedTenantId: (id: string) => void;
  isLoading: boolean;
}

const TenantContext = createContext<TenantState | null>(null);

const STORAGE_KEY = "sng.selected_tenant";

export function TenantProvider({ children }: { children: ReactNode }) {
  const { data, isLoading } = useListTenants();
  const tenants = useMemo<TenantResponse[]>(
    () => data?.items ?? [],
    [data],
  );

  const [selectedTenantId, setSelected] = useState<string | null>(() =>
    typeof localStorage !== "undefined"
      ? localStorage.getItem(STORAGE_KEY)
      : null,
  );

  // Default to the first tenant once the list loads if nothing is
  // selected or the stored selection is no longer present.
  useEffect(() => {
    if (tenants.length === 0) return;
    const stillExists =
      selectedTenantId && tenants.some((t) => t.id === selectedTenantId);
    if (!stillExists) {
      setSelected(tenants[0].id ?? null);
    }
  }, [tenants, selectedTenantId]);

  const setSelectedTenantId = useCallback((id: string) => {
    setSelected(id);
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, id);
    }
  }, []);

  const value = useMemo<TenantState>(
    () => ({
      tenants,
      selectedTenantId,
      selectedTenant:
        tenants.find((t) => t.id === selectedTenantId) ?? null,
      setSelectedTenantId,
      isLoading,
    }),
    [tenants, selectedTenantId, setSelectedTenantId, isLoading],
  );

  return (
    <TenantContext.Provider value={value}>{children}</TenantContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTenant(): TenantState {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error("useTenant must be used within TenantProvider");
  return ctx;
}
