import { useEffect, useId, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { FormattedMessage, useIntl } from "react-intl";
import { useAuth } from "@/auth/auth-context";
import { LaneB1Intl } from "./lane-b1-intl";
import "./lane-b1.css";

export function Login() {
  return (
    <LaneB1Intl>
      <LoginInner />
    </LaneB1Intl>
  );
}

function LoginInner() {
  const intl = useIntl();
  const { authMode, loginWithToken, loginWithOidc, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const tokenFieldId = useId();
  const helpId = useId();
  const errorId = useId();

  // Redirect away from the login screen once authenticated. Navigation is a
  // side effect, so it must run in an effect rather than during render.
  useEffect(() => {
    if (isAuthenticated) {
      navigate({ to: "/" });
    }
  }, [isAuthenticated, navigate]);

  const onJwtSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const trimmed = token.trim();
    if (!trimmed) {
      setError(intl.formatMessage({ id: "b1.login.error.empty" }));
      return;
    }
    // On success the isAuthenticated effect handles the redirect; on failure
    // we surface feedback instead of bouncing to "/" and silently back.
    if (!loginWithToken(trimmed)) {
      setError(intl.formatMessage({ id: "b1.login.error.invalid" }));
    }
  };

  const onOidc = async () => {
    setError(null);
    try {
      await loginWithOidc();
    } catch {
      setError(intl.formatMessage({ id: "b1.login.error.oidc" }));
    }
  };

  return (
    <div className="login lane-b1">
      <main className="login__card">
        <div className="login__brand">
          <span className="sidebar__logo" style={{ width: 36, height: 36 }} aria-hidden>
            S
          </span>
          <div>
            <h1 style={{ fontWeight: 700, fontSize: 18, margin: 0 }}>
              <FormattedMessage id="b1.login.brand" />
            </h1>
            <div className="muted" style={{ fontSize: 12 }}>
              <FormattedMessage id="b1.login.subtitle" />
            </div>
          </div>
        </div>

        {authMode === "oidc" ? (
          <>
            <p className="muted">
              <FormattedMessage id="b1.login.oidc.intro" />
            </p>
            <button
              className="btn btn--primary"
              style={{ width: "100%", justifyContent: "center" }}
              onClick={onOidc}
            >
              <FormattedMessage id="b1.login.oidc.cta" />
            </button>
          </>
        ) : (
          <form onSubmit={onJwtSubmit} noValidate>
            <label className="field" htmlFor={tokenFieldId}>
              <span>
                <FormattedMessage id="b1.login.jwt.label" />
              </span>
            </label>
            <textarea
              id={tokenFieldId}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={intl.formatMessage({ id: "b1.login.jwt.placeholder" })}
              rows={4}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? `${errorId} ${helpId}` : helpId}
            />
            <button
              className="btn btn--primary"
              type="submit"
              style={{ width: "100%", justifyContent: "center", marginTop: 4 }}
            >
              <FormattedMessage id="b1.login.jwt.cta" />
            </button>
            <p id={helpId} className="muted" style={{ fontSize: 12, marginTop: 12 }}>
              <FormattedMessage id="b1.login.jwt.help" />
            </p>
          </form>
        )}
        {error && (
          <p id={errorId} className="error-text" role="alert">
            {error}
          </p>
        )}
      </main>
    </div>
  );
}
