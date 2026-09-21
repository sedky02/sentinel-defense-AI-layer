import type { DecisionRecord, Outcome } from "@/lib/types";

const OUTCOMES: Outcome[] = ["ALLOW", "BLOCK", "ESCALATE", "REWRITE"];

export function SummaryBar({ records }: { records: DecisionRecord[] }) {
  const counts: Record<Outcome, number> = {
    ALLOW: 0,
    BLOCK: 0,
    ESCALATE: 0,
    REWRITE: 0,
  };
  for (const record of records) counts[record.outcome] = (counts[record.outcome] ?? 0) + 1;

  return (
    <div className="summary-bar">
      <div className="summary-counts">
        <span className="summary-total">{records.length} actions</span>
        {OUTCOMES.map((outcome) => (
          <span key={outcome} className={`summary-count outcome-${outcome.toLowerCase()}`}>
            {outcome} {counts[outcome]}
          </span>
        ))}
      </div>
      <div className="risk-timeline">
        {records.map((record) => (
          <div
            key={record.seq}
            className={`timeline-tick outcome-${record.outcome.toLowerCase()}`}
            style={{ height: `${Math.max(6, record.risk_score * 100)}%` }}
            title={`${record.action_type}: ${record.outcome} (${Math.round(record.risk_score * 100)}%)`}
          />
        ))}
      </div>
    </div>
  );
}
