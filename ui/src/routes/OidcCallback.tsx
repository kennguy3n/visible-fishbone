import { useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { FormattedMessage, useIntl } from "react-intl";
import { completeOidcLogin } from "@/auth/oidc";
import { useAuth } from "@/auth/auth-context";
import { LoadingState } from "@/components/ui";
import { LaneB1Intl } from "./lane-b1-intl";
import "./lane-b1.css";

// The callback can fail in two operator-meaningful ways: the identity provider
// returned a token the console can't use, or sign-in was interrupted before it
// finished. Both map to plain-language guidance rather than a raw error string.
type CallbackError = "unusable" | "generic";

export function OidcCallback() {
  return (
    <LaneB1Intl>
      <OidcCallbackInner />
    </LaneB1Intl>
  );
}

function OidcCallbackInner() {
  const intl = useIntl();
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<CallbackError | null>(null);
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    completeOidcLogin(window.location.search)
      .then(({ accessToken }) => {
        // setSession rejects a malformed/expired token. The PKCE material is
        // already consumed (cleared in completeOidcLogin's finally), so this
        // callback can't be retried — surface an error instead of bouncing to
        // "/" and silently back to the login screen.
        if (setSession(accessToken)) {
          navigate({ to: "/" });
        } else {
          // setSession only rejects a token it can't decode as a JWT or that
          // is already expired — usually an IdP issuing an opaque access token
          // the JWT-bearer API can't use either.
          setError("unusable");
        }
      })
      .catch(() => setError("generic"));
  }, [setSession, navigate]);

  if (error) {
    return (
      <div className="login lane-b1">
        <main className="login__card">
          <div className="state" role="alert">
            <div className="state__icon" style={{ color: "var(--danger)" }} aria-hidden>
              ⚠
            </div>
            <p style={{ fontWeight: 600, color: "var(--text)" }}>
              <FormattedMessage id="b1.oidc.error.title" />
            </p>
            <p>
              <FormattedMessage
                id={
                  error === "unusable"
                    ? "b1.oidc.error.unusable"
                    : "b1.oidc.error.generic"
                }
              />
            </p>
          </div>
          <button
            className="btn btn--primary"
            style={{ width: "100%", justifyContent: "center", marginTop: 14 }}
            onClick={() => navigate({ to: "/login" })}
          >
            <FormattedMessage id="b1.oidc.back" />
          </button>
        </main>
      </div>
    );
  }

  return (
    <div className="login lane-b1">
      <main className="login__card">
        <LoadingState label={intl.formatMessage({ id: "b1.oidc.loading" })} />
      </main>
    </div>
  );
}
