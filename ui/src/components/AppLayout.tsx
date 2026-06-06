import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { NAV } from "./nav";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { useAuth } from "@/auth/auth-context";
import { TenantProvider, useTenant } from "@/lib/tenant-context";

function TenantSwitcher() {
  const { tenants, selectedTenantId, setSelectedTenantId, isLoading } =
    useTenant();
  if (isLoading)
    return (
      <span className="muted">
        <FormattedMessage id="topbar.tenant.loading" />
      </span>
    );
  if (tenants.length === 0)
    return (
      <span className="muted">
        <FormattedMessage id="topbar.tenant.none" />
      </span>
    );
  return (
    <div className="tenant-switcher">
      <span className="muted" style={{ fontSize: 12 }}>
        <FormattedMessage id="topbar.tenant" />
      </span>
      <select
        value={selectedTenantId ?? ""}
        onChange={(e) => setSelectedTenantId(e.target.value)}
      >
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </div>
  );
}

function Sidebar() {
  const { location } = useRouterState();
  const path = location.pathname;
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__logo">S</span>
        <span>
          ShieldNet
          <small>
            <FormattedMessage id="app.subtitle" />
          </small>
        </span>
      </div>
      <nav>
        {NAV.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group__label">{group.label}</div>
            {group.items.map((item) => {
              const active =
                item.to === "/"
                  ? path === "/"
                  : path === item.to || path.startsWith(`${item.to}/`);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`nav-link${active ? " active" : ""}`}
                >
                  <span className="nav-link__icon">{item.icon}</span>
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
    </aside>
  );
}

function Topbar() {
  const { claims, logout } = useAuth();
  const intl = useIntl();
  const name = claims?.name || claims?.email || claims?.sub || "Operator";
  return (
    <header className="topbar">
      <TenantSwitcher />
      <div className="topbar__spacer" />
      <LanguageSwitcher />
      <div className="topbar__user">
        <b>{name}</b>
        <span className="muted">{claims?.iss ?? "shieldnet"}</span>
      </div>
      <button
        className="btn btn--ghost btn--sm"
        onClick={logout}
        aria-label={intl.formatMessage({ id: "topbar.signOut" })}
      >
        <FormattedMessage id="topbar.signOut" />
      </button>
    </header>
  );
}

export function AppLayout() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate({ to: "/login" });
    }
  }, [isAuthenticated, navigate]);

  if (!isAuthenticated) return null;

  return (
    <TenantProvider>
      <div className="app-shell">
        <Sidebar />
        <div className="main">
          <Topbar />
          <div className="content">
            <Outlet />
          </div>
        </div>
      </div>
    </TenantProvider>
  );
}
