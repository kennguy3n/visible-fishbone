import { useEffect, useMemo } from "react";
import { useListMSPs } from "@/api/generated/endpoints/msps/msps";

export function MspPicker({
  value,
  onChange,
}: {
  value: string | null;
  onChange: (mspId: string) => void;
}) {
  const list = useListMSPs(undefined);
  const items = useMemo(() => list.data?.items ?? [], [list.data?.items]);

  useEffect(() => {
    if (!value && items.length > 0) onChange(items[0].id);
  }, [value, items, onChange]);

  return (
    <label className="field" style={{ maxWidth: 320 }}>
      <span>Managed service provider</span>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        disabled={list.isLoading || items.length === 0}
      >
        {items.length === 0 && <option value="">No MSPs available</option>}
        {items.map((m) => (
          <option key={m.id} value={m.id}>
            {m.name} ({m.slug})
          </option>
        ))}
      </select>
    </label>
  );
}
