import { useEffect, useMemo } from "react";
import { useIntl } from "react-intl";
import { useListMSPs } from "@/api/generated/endpoints/msps/msps";
import { M } from "./lane-b6.messages";
import { LabelText } from "./_lane";

export function MspPicker({
  value,
  onChange,
}: {
  value: string | null;
  onChange: (mspId: string) => void;
}) {
  const { formatMessage: fm } = useIntl();
  const list = useListMSPs(undefined);
  const items = useMemo(() => list.data?.items ?? [], [list.data?.items]);

  useEffect(() => {
    if (!value && items.length > 0) onChange(items[0].id);
  }, [value, items, onChange]);

  const isEmpty = !list.isLoading && items.length === 0;

  return (
    <label className="field" style={{ maxWidth: 360 }}>
      <LabelText help={fm(M.pickerHelp)} helpTitle={fm(M.pickerLabel)}>
        {fm(M.pickerLabel)}
      </LabelText>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        disabled={list.isLoading || items.length === 0}
        aria-describedby={isEmpty ? "msp-picker-empty" : undefined}
      >
        {list.isLoading && <option value="">{fm(M.pickerLoading)}</option>}
        {isEmpty && <option value="">{fm(M.pickerEmpty)}</option>}
        {items.map((m) => (
          <option key={m.id} value={m.id}>
            {m.name} ({m.slug})
          </option>
        ))}
      </select>
      {isEmpty && (
        <p id="msp-picker-empty" className="muted" style={{ marginTop: 6 }}>
          {fm(M.pickerEmptyHint)}
        </p>
      )}
    </label>
  );
}
