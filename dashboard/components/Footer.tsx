export function Footer({ connected }: { connected: boolean }) {
  return (
    <footer className="footer">
      <div className="footer-group">
        <span style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
          <span className={`pulse-dot ${connected ? "live" : "offline"}`} />
          <strong>SSE: /api/stream</strong>
        </span>
        <span className="footer-divider">|</span>
        <span>
          Source: <strong>live JSONL trace</strong>
        </span>
      </div>
      <div className="footer-group">
        <span>
          Coverage: <strong>OWASP Top 10 + MITRE ATLAS scenarios</strong>
        </span>
        <span className="footer-divider">|</span>
        <span>SENTINEL Starter Kit v1</span>
      </div>
    </footer>
  );
}
