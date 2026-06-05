import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { runtimeConfig } from "@/lib/runtime-config";
import {
  clearAccessToken,
  getAccessToken,
  setAccessToken,
} from "./token-store";
import { UNAUTHORIZED_EVENT } from "@/api/http-client";
import { decodeJwt, isExpired, type JwtClaims } from "./jwt";
import { beginOidcLogin } from "./oidc";

interface AuthState {
  authMode: "jwt" | "oidc";
  isAuthenticated: boolean;
  claims: JwtClaims | null;
  /** Dev mode: set the bearer token directly (operator pastes a JWT). */
  loginWithToken: (token: string) => void;
  /** Prod mode: start the OIDC redirect. */
  loginWithOidc: () => Promise<void>;
  /** Used by the OIDC callback route after token exchange. */
  setSession: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

function deriveClaims(): JwtClaims | null {
  const token = getAccessToken();
  if (!token) return null;
  const claims = decodeJwt(token);
  if (isExpired(claims)) {
    clearAccessToken();
    return null;
  }
  return claims;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const cfg = runtimeConfig();
  const [claims, setClaims] = useState<JwtClaims | null>(() => deriveClaims());

  const setSession = useCallback((token: string) => {
    setAccessToken(token);
    setClaims(decodeJwt(token));
  }, []);

  const logout = useCallback(() => {
    clearAccessToken();
    setClaims(null);
  }, []);

  // A 401 from any API call means the token is stale/invalid — drop it
  // so the route guard bounces the operator back to the login screen.
  useEffect(() => {
    const onUnauthorized = () => setClaims(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      authMode: cfg.authMode,
      isAuthenticated: claims !== null,
      claims,
      loginWithToken: setSession,
      loginWithOidc: beginOidcLogin,
      setSession,
      logout,
    }),
    [cfg.authMode, claims, setSession, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
