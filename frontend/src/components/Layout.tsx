import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";

export function Layout() {
  const { user, logout } = useAuth();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">AG</span>
          <span>
            <strong>AegisGraph</strong>
            <small>AI Fraud Intelligence</small>
          </span>
        </div>
        <nav aria-label="Primary navigation">
          <NavLink to="/" end>
            <span aria-hidden="true">⌁</span> Command center
          </NavLink>
        </nav>
        <div className="sidebar__status">
          <span className="live-dot" />
          <span>
            <strong>Detection online</strong>
            <small>Monitoring payment events</small>
          </span>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Tenant</p>
            <strong>{user?.tenant_id}</strong>
          </div>
          <div className="topbar__user">
            <span className="avatar">{user?.display_name.slice(0, 1).toUpperCase()}</span>
            <span className="user-copy">
              <strong>{user?.display_name}</strong>
              <small>{user?.role.replaceAll("_", " ")}</small>
            </span>
            <button className="button button--ghost" type="button" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </header>
        <Outlet />
      </div>
    </div>
  );
}
