import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { NAV } from "./nav";
import { Icon } from "./Icon";
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
                  <span className="nav-link__icon">
                    <Icon name={item.icon} size={17} />
                  </span>
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
    </aside>
  );
}

function Topbar({ onToggleNav }: { onToggleNav: () => void }) {
  const { claims, logout } = useAuth();
  const intl = useIntl();
  const name = claims?.name || claims?.email || claims?.sub || "Operator";
  const issuer = claims?.iss ?? "shieldnet";
  // Two-letter monogram for the identity avatar: initials of a display
  // name ("Ada Lovelace" -> "AL"), or the first two characters otherwise.
  const initials = (() => {
    const parts = name.trim().split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name.slice(0, 2).toUpperCase();
  })();
  // The dedicated identity block is hidden on the tablet icon-rail to reclaim
  // horizontal room, so surface the same "who am I signed in as" on the Sign
  // out button's tooltip/accessible name. This keeps the operator identity
  // reachable at every breakpoint (it's data, not translatable copy).
  const identity = `${name} · ${issuer}`;
  return (
    <header className="topbar">
      <button
        className="icon-btn"
        onClick={onToggleNav}
        aria-label={intl.formatMessage({ id: "topbar.menu" })}
      >
        <Icon name="menu" size={18} />
      </button>
      <TenantSwitcher />
      <div className="topbar__spacer" />
      <LanguageSwitcher />
      <div className="topbar__user">
        <span className="avatar" aria-hidden>
          {initials}
        </span>
        <span className="topbar__identity">
          <b>{name}</b>
          <span className="muted">{issuer}</span>
        </span>
      </div>
      <button
        className="btn btn--ghost btn--sm"
        onClick={logout}
        title={`${intl.formatMessage({ id: "topbar.signOut" })} — ${identity}`}
        aria-label={`${intl.formatMessage({ id: "topbar.signOut" })} — ${identity}`}
      >
        <Icon name="logout" size={15} />
        <FormattedMessage id="topbar.signOut" />
      </button>
    </header>
  );
}

export function AppLayout() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const { location } = useRouterState();
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      navigate({ to: "/login" });
    }
  }, [isAuthenticated, navigate]);

  // Close the mobile nav drawer whenever the route changes.
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  if (!isAuthenticated) return null;

  return (
    <TenantProvider>
      <div className={`app-shell${navOpen ? " nav-open" : ""}`}>
        <div
          className="sidebar__scrim"
          onClick={() => setNavOpen(false)}
          aria-hidden
        />
        <Sidebar />
        <div className="main">
          <Topbar onToggleNav={() => setNavOpen((v) => !v)} />
          <div className="content">
            <Outlet />
          </div>
        </div>
      </div>
    </TenantProvider>
  );
}
