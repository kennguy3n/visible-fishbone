import { useRef, useState } from "react";
import { aiTroubleshoot, aiNLPolicyQuery } from "@/api/generated/endpoints/ai/ai";
import { PageHeader, Badge } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";

type Mode = "troubleshoot" | "policy";

interface ChatMsg {
  role: "user" | "ai";
  text: string;
  meta?: string;
}

export function Assistant() {
  return (
    <RequireTenant>{(tenantId) => <AssistantInner tenantId={tenantId} />}</RequireTenant>
  );
}

function AssistantInner({ tenantId }: { tenantId: string }) {
  const [mode, setMode] = useState<Mode>("troubleshoot");
  const [log, setLog] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const scrollDown = () =>
    requestAnimationFrame(() => {
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
    });

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setLog((l) => [...l, { role: "user", text }]);
    setBusy(true);
    scrollDown();
    try {
      if (mode === "troubleshoot") {
        const res = await aiTroubleshoot(tenantId, { query: text });
        const body =
          res.suggestions.length > 0
            ? res.suggestions.map((s, i) => `${i + 1}. ${s}`).join("\n")
            : "No suggestions returned.";
        const refs =
          res.referenced_docs.length > 0
            ? `\n\nReferences: ${res.referenced_docs.join(", ")}`
            : "";
        setLog((l) => [
          ...l,
          {
            role: "ai",
            text: body + refs,
            meta: `${res.ai_generated ? res.model_id ?? "model" : "heuristic"} · confidence ${(
              res.confidence * 100
            ).toFixed(0)}%`,
          },
        ]);
      } else {
        const res = await aiNLPolicyQuery(tenantId, { question: text });
        const matched =
          res.matched_rules && res.matched_rules.length > 0
            ? `\n\nMatched rules: ${res.matched_rules.join(", ")}`
            : "";
        setLog((l) => [
          ...l,
          {
            role: "ai",
            text: `Verdict: ${res.verdict}\n\n${res.explanation}${matched}`,
            meta: `${res.evaluation_mode ?? "evaluated"} · ${
              res.ai_generated ? res.model_id ?? "model" : "deterministic"
            }`,
          },
        ]);
      }
    } catch (err) {
      setLog((l) => [
        ...l,
        {
          role: "ai",
          text: err instanceof Error ? err.message : "Request failed.",
          meta: "error",
        },
      ]);
    } finally {
      setBusy(false);
      scrollDown();
    }
  };

  return (
    <>
      <PageHeader
        title="AI assistant"
        subtitle="Natural-language troubleshooting and policy queries grounded in tenant context."
      />
      <div className="pill-tabs">
        <button
          className={mode === "troubleshoot" ? "active" : ""}
          onClick={() => setMode("troubleshoot")}
        >
          Troubleshooting
        </button>
        <button
          className={mode === "policy" ? "active" : ""}
          onClick={() => setMode("policy")}
        >
          NL policy query
        </button>
      </div>

      <div className="card chat">
        <div className="chat__log" ref={logRef}>
          {log.length === 0 && (
            <p className="muted">
              {mode === "troubleshoot"
                ? "Ask why a device can't reach an app, why a tunnel is flapping, etc."
                : "Ask what the policy says, e.g. “can contractors reach the finance app?”"}
            </p>
          )}
          {log.map((m, i) => (
            <div
              key={i}
              className={`chat__msg chat__msg--${m.role === "user" ? "user" : "ai"}`}
            >
              {m.text}
              {m.meta && (
                <div style={{ marginTop: 6 }}>
                  <Badge tone={m.meta === "error" ? "danger" : "neutral"}>
                    {m.meta}
                  </Badge>
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="chat__composer">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") send();
            }}
            placeholder={busy ? "Thinking…" : "Type your question…"}
            disabled={busy}
          />
          <button className="btn btn--primary" onClick={send} disabled={busy || !input.trim()}>
            Send
          </button>
        </div>
      </div>
    </>
  );
}
