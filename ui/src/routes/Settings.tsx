import { useState } from "react";
import { PageHeader, Card } from "@/components/ui";
import { Icon } from "@/components/Icon";
import {
  getStoredChoice,
  resolveTheme,
  setTheme,
  type ThemeChoice,
} from "@/lib/theme";

const THEME_OPTIONS: {
  value: ThemeChoice;
  label: string;
  hint: string;
}[] = [
  { value: "light", label: "Light", hint: "Always use the light theme." },
  { value: "dark", label: "Dark", hint: "Always use the dark theme." },
  {
    value: "system",
    label: "System",
    hint: "Follow your operating system's appearance setting.",
  },
];

export function Settings() {
  const [choice, setChoice] = useState<ThemeChoice>(() => getStoredChoice());

  const select = (next: ThemeChoice) => {
    setChoice(next);
    setTheme(next);
  };

  const resolved = resolveTheme(choice);

  return (
    <>
      <PageHeader
        title="Settings"
        subtitle="Console preferences for this browser."
      />
      <div className="grid grid--2">
        <Card
          title="Appearance"
          subtitle="Choose how the console looks. Your choice is saved in this browser."
        >
          <div
            className="theme-toggle"
            role="radiogroup"
            aria-label="Theme"
          >
            {THEME_OPTIONS.map((opt) => {
              const active = choice === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  className={`theme-toggle__option${active ? " active" : ""}`}
                  onClick={() => select(opt.value)}
                >
                  <Icon
                    name={
                      opt.value === "dark"
                        ? "browser"
                        : opt.value === "light"
                          ? "dashboard"
                          : "settings"
                    }
                    size={18}
                  />
                  <b>{opt.label}</b>
                  <span className="muted">{opt.hint}</span>
                </button>
              );
            })}
          </div>
          <p className="muted" style={{ marginTop: 14, fontSize: 12 }}>
            {choice === "system" ? (
              <>
                Following your system preference — currently{" "}
                <b>{resolved === "dark" ? "dark" : "light"}</b>.
              </>
            ) : (
              <>
                Theme locked to <b>{choice}</b>.
              </>
            )}
          </p>
        </Card>
      </div>
    </>
  );
}
