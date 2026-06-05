import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/auth/auth-context";

export function Login() {
  const { authMode, loginWithToken, loginWithOidc, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);

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
      setError("Paste a bearer token to continue.");
      return;
    }
    // On success the isAuthenticated effect handles the redirect; on failure
    // we surface feedback instead of bouncing to "/" and silently back.
    if (!loginWithToken(trimmed)) {
      setError("That token is invalid or expired. Paste a current bearer token.");
    }
  };

  const onOidc = async () => {
    setError(null);
    try {
      await loginWithOidc();
    } catch (err) {
      setError(err instanceof Error ? err.message : "OIDC login failed");
    }
  };

  return (
    <div className="login">
      <div className="login__card">
        <div className="login__brand">
          <span className="sidebar__logo" style={{ width: 36, height: 36 }}>
            S
          </span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 18 }}>ShieldNet Gateway</div>
            <div className="muted" style={{ fontSize: 12 }}>
              Operator console
            </div>
          </div>
        </div>

        {authMode === "oidc" ? (
          <>
            <p className="muted">
              Sign in with your organization identity provider.
            </p>
            <button
              className="btn btn--primary"
              style={{ width: "100%", justifyContent: "center" }}
              onClick={onOidc}
            >
              Continue with SSO
            </button>
          </>
        ) : (
          <form onSubmit={onJwtSubmit}>
            <label className="field">
              <span>Bearer JWT (development)</span>
              <textarea
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiІ..."
                rows={4}
              />
            </label>
            <button
              className="btn btn--primary"
              type="submit"
              style={{ width: "100%", justifyContent: "center" }}
            >
              Sign in
            </button>
            <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
              The control plane verifies the HMAC-signed operator JWT
              (config <code>Auth.JWTSecret</code>). In production this screen
              switches to the OIDC redirect flow.
            </p>
          </form>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
