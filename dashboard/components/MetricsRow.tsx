import type { DecisionRecord } from "@/lib/types";

const BENIGN_FAMILIES = new Set(["benign", "hard-negative"]);

export function MetricsRow({ records }: { records: DecisionRecord[] }) {
  const total = records.length;
  const allow = records.filter((r) => r.outcome === "ALLOW").length;
  const block = records.filter((r) => r.outcome === "BLOCK").length;
  const escalate = records.filter((r) => r.outcome === "ESCALATE").length;
  const rewrite = records.filter((r) => r.outcome === "REWRITE").length;
  const benign = records.filter((r) => BENIGN_FAMILIES.has((r.metadata?.attack_family as string) || "")).length;

  const pct = (n: number) => (total ? (n / total) * 100 : 0);

  return (
    <div className="metrics-grid">
      <div className="metric-card">
        <div className="metric-head">
          <span className="metric-label">Evaluated Total</span>
        </div>
        <div>
          <div className="metric-value-row">
            <span className="metric-value">{total}</span>
          </div>
          <div className="metric-sub">{benign} tagged benign</div>
        </div>
        <div className="metric-bar">
          <div className="metric-bar-fill" style={{ width: "100%", background: "var(--text-ghost)" }} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-head">
          <span className="metric-label">Allow Rate</span>
          <span style={{ color: "var(--allow)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
            {pct(allow).toFixed(1)}%
          </span>
        </div>
        <div>
          <div className="metric-value-row">
            <span className="metric-value">{allow}</span>
          </div>
          <div className="metric-sub">clean state alignment</div>
        </div>
        <div className="metric-bar">
          <div className="metric-bar-fill" style={{ width: `${pct(allow)}%`, background: "var(--allow)" }} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-head">
          <span className="metric-label">Blocked Threats</span>
          <span style={{ color: "var(--block)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
            {pct(block).toFixed(1)}%
          </span>
        </div>
        <div>
          <div className="metric-value-row">
            <span className="metric-value">{block}</span>
          </div>
          <div className="metric-sub">adversarial actions intercepted</div>
        </div>
        <div className="metric-bar">
          <div className="metric-bar-fill" style={{ width: `${pct(block)}%`, background: "var(--block)" }} />
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-head">
          <span className="metric-label">Interventions</span>
          <span className="metric-sub">{escalate + rewrite} total</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", margin: "0.375rem 0" }}>
          <div>
            <div className="metric-label" style={{ color: "var(--text-ghost)" }}>
              Escalate
            </div>
            <div className="metric-value" style={{ fontSize: "18px" }}>
              {escalate}
            </div>
          </div>
          <div>
            <div className="metric-label" style={{ color: "var(--text-ghost)" }}>
              Rewrite
            </div>
            <div className="metric-value" style={{ fontSize: "18px" }}>
              {rewrite}
            </div>
          </div>
        </div>
        <div className="metric-bar">
          <div
            className="metric-bar-fill"
            style={{ width: `${pct(escalate + rewrite)}%`, background: "var(--escalate)" }}
          />
        </div>
      </div>
    </div>
  );
}
