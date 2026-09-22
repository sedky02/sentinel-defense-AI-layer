const NAV_ITEMS = [
  { label: "Live Console", active: true },
];

export function Sidebar({ connected }: { connected: boolean }) {
  return (
    <aside className="sidebar">
      <div>
        <div className="sidebar-brand">
          <div className="sidebar-brand-mark">S</div>
          <div>
            <div className="sidebar-brand-title">SENTINEL</div>
            <div className="sidebar-brand-subtitle">DEFENSE SOC</div>
          </div>
        </div>
        <nav className="sidebar-nav">
          <div className="sidebar-nav-label">Workspace</div>
          {NAV_ITEMS.map((item) => (
            <button
              key={item.label}
              type="button"
              className={`sidebar-link ${item.active ? "active" : ""}`}
              disabled={!item.active}
              title={item.active ? undefined : "Not wired up in this build"}
            >
              <span className="dot" />
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-context">
          <span className="sidebar-context-kicker">MONITORING MODE</span>
          <strong>Provenance-aware defense</strong>
          <span>Live decisions, risk synthesis, and evidence trails.</span>
        </div>
      </div>

      <div className="sidebar-footer">
        <div className="sidebar-footer-row">
          <span className="sidebar-footer-label">Defense Engine</span>
        </div>
        <div className="sidebar-status">
          <span style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
            <span className={`pulse-dot ${connected ? "live" : "offline"}`} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
              {connected ? "STREAM LIVE" : "OFFLINE"}
            </span>
          </span>
        </div>
      </div>
    </aside>
  );
}
