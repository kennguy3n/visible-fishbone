import { useRef, useState } from "react";
import { useIntl } from "react-intl";
import { aiTroubleshoot, aiNLPolicyQuery } from "@/api/generated/endpoints/ai/ai";
import { PageHeader, Badge } from "@/components/ui";
import { RequireTenant } from "@/components/RequireTenant";
import { LanePage } from "./lane-b5";
import { assistantMsg as M } from "./lane-b5.messages";

type Mode = "troubleshoot" | "policy";

interface ChatMsg {
  role: "user" | "ai";
  text: string;
  meta?: string;
  isError?: boolean;
}

export function Assistant() {
  return (
    <RequireTenant>{(tenantId) => <AssistantInner tenantId={tenantId} />}</RequireTenant>
  );
}

function AssistantInner({ tenantId }: { tenantId: string }) {
  const intl = useIntl();
  const [mode, setMode] = useState<Mode>("troubleshoot");
  const [log, setLog] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const scrollDown = () =>
    requestAnimationFrame(() => {
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
    });

  const ask = async (question: string) => {
    const text = question.trim();
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
            : intl.formatMessage(M.noSuggestions);
        const refs =
          res.referenced_docs.length > 0
            ? `\n\n${intl.formatMessage(M.references, {
                docs: res.referenced_docs.join(", "),
              })}`
            : "";
        const source = res.ai_generated
          ? res.model_id ?? intl.formatMessage(M.assistant)
          : intl.formatMessage(M.heuristic);
        setLog((l) => [
          ...l,
          {
            role: "ai",
            text: body + refs,
            meta: `${source} · ${intl.formatMessage(M.confidence, {
              pct: (res.confidence * 100).toFixed(0),
            })}`,
          },
        ]);
      } else {
        const res = await aiNLPolicyQuery(tenantId, { question: text });
        const matched =
          res.matched_rules && res.matched_rules.length > 0
            ? `\n\n${intl.formatMessage(M.matchedRules, {
                rules: res.matched_rules.join(", "),
              })}`
            : "";
        const source = res.ai_generated
          ? res.model_id ?? intl.formatMessage(M.assistant)
          : intl.formatMessage(M.deterministic);
        setLog((l) => [
          ...l,
          {
            role: "ai",
            text: `${intl.formatMessage(M.verdict)}: ${res.verdict}\n\n${res.explanation}${matched}`,
            meta: `${res.evaluation_mode ?? intl.formatMessage(M.evaluated)} · ${source}`,
          },
        ]);
      }
    } catch {
      setLog((l) => [
        ...l,
        {
          role: "ai",
          text: intl.formatMessage(M.errorGeneric),
          meta: intl.formatMessage(M.errorMeta),
          isError: true,
        },
      ]);
    } finally {
      setBusy(false);
      scrollDown();
    }
  };

  const examples =
    mode === "troubleshoot"
      ? [M.exTrouble1, M.exTrouble2, M.exTrouble3]
      : [M.exPolicy1, M.exPolicy2, M.exPolicy3];

  const switchMode = (next: Mode) => {
    setMode(next);
    setLog([]);
  };

  return (
    <LanePage>
      <PageHeader
        title={intl.formatMessage(M.title)}
        subtitle={intl.formatMessage(M.subtitle)}
      />
      <div className="pill-tabs" role="group" aria-label={intl.formatMessage(M.title)}>
        <button
          className={mode === "troubleshoot" ? "active" : ""}
          aria-pressed={mode === "troubleshoot"}
          disabled={busy}
          onClick={() => switchMode("troubleshoot")}
        >
          {intl.formatMessage(M.tabTroubleshoot)}
        </button>
        <button
          className={mode === "policy" ? "active" : ""}
          aria-pressed={mode === "policy"}
          disabled={busy}
          onClick={() => switchMode("policy")}
        >
          {intl.formatMessage(M.tabPolicy)}
        </button>
      </div>

      <div className="card chat">
        <div
          className="chat__log"
          ref={logRef}
          role="log"
          aria-live="polite"
          aria-label={intl.formatMessage(M.logAria)}
        >
          {log.length === 0 ? (
            <div className="lane-empty-chat">
              <div className="lane-empty-chat__title">
                {intl.formatMessage(
                  mode === "troubleshoot" ? M.emptyTroubleshoot : M.emptyPolicy,
                )}
              </div>
              <div>{intl.formatMessage(M.tryAsking)}</div>
              <div className="lane-suggest">
                {examples.map((ex) => {
                  const label = intl.formatMessage(ex);
                  return (
                    <button
                      key={ex.id}
                      className="btn btn--sm"
                      onClick={() => ask(label)}
                      disabled={busy}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            log.map((m, i) => (
              <div
                key={i}
                className={`chat__msg chat__msg--${m.role === "user" ? "user" : "ai"}`}
              >
                <div className="lane-msg-role">
                  {intl.formatMessage(m.role === "user" ? M.you : M.assistant)}
                </div>
                {m.text}
                {m.meta && (
                  <div className="lane-msg-meta">
                    <Badge tone={m.isError ? "danger" : "neutral"}>{m.meta}</Badge>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
        <div className="chat__composer">
          <input
            value={input}
            aria-label={intl.formatMessage(M.composerPlaceholder)}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") ask(input);
            }}
            placeholder={
              busy
                ? intl.formatMessage(M.composerBusy)
                : intl.formatMessage(M.composerPlaceholder)
            }
            disabled={busy}
          />
          <button
            className="btn btn--primary"
            onClick={() => ask(input)}
            disabled={busy || !input.trim()}
          >
            {intl.formatMessage(M.send)}
          </button>
        </div>
      </div>
    </LanePage>
  );
}
