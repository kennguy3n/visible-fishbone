import { useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { completeOidcLogin } from "@/auth/oidc";
import { useAuth } from "@/auth/auth-context";
import { LoadingState, ErrorState } from "@/components/ui";

export function OidcCallback() {
  const { setSession } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
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
          setError(
            new Error(
              "The identity provider returned an invalid or expired access token.",
            ),
          );
        }
      })
      .catch(setError);
  }, [setSession, navigate]);

  if (error) {
    return (
      <div className="login">
        <div className="login__card">
          <ErrorState error={error} />
          <button
            className="btn"
            style={{ width: "100%", justifyContent: "center" }}
            onClick={() => navigate({ to: "/login" })}
          >
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="login">
      <div className="login__card">
        <LoadingState label="Completing sign-in…" />
      </div>
    </div>
  );
}
