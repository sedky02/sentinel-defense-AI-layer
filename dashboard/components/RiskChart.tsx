import type { DecisionRecord } from "@/lib/types";
import { OUTCOME_COLOR } from "@/lib/outcome";

const WIDTH = 740;
const HEIGHT = 128;
const WINDOW = 40;

export function RiskChart({ records }: { records: DecisionRecord[] }) {
  const series = records.slice(-WINDOW);

  return (
    <div className="panel chart-panel">
      <div className="chart-head">
        <div className="chart-title">
          <span className="pulse-dot live" />
          Risk Score Sequential Stream
          <span className="chart-title-tag">Last {series.length}</span>
        </div>
        <div className="chart-legend">
          <span>
            <span style={{ width: 8, height: 1, background: "var(--block)", display: "inline-block" }} />
            Block color
          </span>
          <span>
            <span className="pulse-dot live" />
            Live sync
          </span>
        </div>
      </div>

      {series.length < 2 ? (
        <div className="chart-empty">Waiting for enough decisions to plot a trend&hellip;</div>
      ) : (
        <>
          <div className="chart-body">
            <svg width="100%" height="100%" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none">
              <line x1="0" x2={WIDTH} y1={HEIGHT * 0.125} y2={HEIGHT * 0.125} stroke="var(--border-hairline)" strokeDasharray="3,3" />
              <line x1="0" x2={WIDTH} y1={HEIGHT * 0.5} y2={HEIGHT * 0.5} stroke="var(--border-hairline)" />
              <line x1="0" x2={WIDTH} y1={HEIGHT * 0.875} y2={HEIGHT * 0.875} stroke="var(--border-hairline)" strokeDasharray="3,3" />

              {(() => {
                const step = WIDTH / Math.max(series.length - 1, 1);
                const points = series.map((r, i) => {
                  const x = i * step;
                  const y = HEIGHT - r.risk_score * HEIGHT;
                  return { x, y, r };
                });
                const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
                const areaPath = `${linePath} L ${WIDTH},${HEIGHT} L 0,${HEIGHT} Z`;
                return (
                  <>
                    <defs>
                      <linearGradient id="riskGradient" x1="0%" x2="0%" y1="0%" y2="100%">
                        <stop offset="0%" stopColor="var(--rewrite)" stopOpacity="0.16" />
                        <stop offset="100%" stopColor="var(--rewrite)" stopOpacity="0" />
                      </linearGradient>
                    </defs>
                    <path d={areaPath} fill="url(#riskGradient)" />
                    <path d={linePath} fill="none" stroke="var(--rewrite)" strokeWidth="1.5" />
                    {points.map((p, i) => (
                      <circle
                        key={i}
                        cx={p.x}
                        cy={p.y}
                        r={p.r.risk_score >= 0.7 ? 3.5 : 2.5}
                        fill="var(--bg-surface-1)"
                        stroke={OUTCOME_COLOR[p.r.outcome] ?? "var(--text-ghost)"}
                        strokeWidth="1.5"
                      />
                    ))}
                  </>
                );
              })()}
            </svg>
          </div>
          <div className="chart-footer">
            <span>oldest shown</span>
            <span style={{ color: "var(--allow)" }}>most recent</span>
          </div>
        </>
      )}
    </div>
  );
}
