import type { DecisionRecord } from "@/lib/types";
import { OutcomeBadge } from "./OutcomeBadge";
import { OUTCOME_COLOR } from "@/lib/outcome";

export function DecisionCard({
  record,
  selected,
  onSelect,
}: {
  record: DecisionRecord;
  selected: boolean;
  onSelect: () => void;
}) {
  const riskPct = Math.round(record.risk_score * 100);
  const family = (record.metadata?.attack_family as string) || null;
  const title = (record.metadata?.title as string) || record.action_type;

  return (
    <article
      className={`card ${selected ? "selected" : ""}`}
      style={{ ["--outcome-color" as string]: OUTCOME_COLOR[record.outcome] }}
      onClick={onSelect}
    >
      <div className="card-top">
        <div className="card-top-left">
          <OutcomeBadge outcome={record.outcome} />
          <span className="card-risk">
            Risk: <strong style={{ color: OUTCOME_COLOR[record.outcome] }}>{riskPct}%</strong>
          </span>
        </div>
        <div className="card-meta">
          {family && <span>{family}</span>}
          <strong>#{record.session_id}-{record.seq}</strong>
        </div>
      </div>

      <div className="card-action-row">
        <span className="k">Action</span>
        <span className="action">{record.action_type}</span>
        <span className="arrow">&rarr;</span>
        <span className="k">Target</span>
        <span className="target">{record.target}</span>
      </div>

      <p className="card-explanation">
        <strong style={{ color: "var(--text-strong)" }}>{title !== record.action_type ? `${title}: ` : ""}</strong>
        {record.explanation}
      </p>

      {record.rewritten_action && (
        <div className="card-rewrite">
          <span className="label">Substituted:</span>
          {record.rewritten_action.action_type} &rarr; <code>{record.rewritten_action.target}</code>
        </div>
      )}

      {record.reason_codes.length > 0 && (
        <div className="reason-codes">
          {record.reason_codes.map((code) => (
            <span key={code} className="reason-chip">
              {code}
            </span>
          ))}
        </div>
      )}

      {record.behavioral_signal && (
        <div className="signal-summary">
          <span className="signal-label">Behavioral</span>
          <span>similarity {record.behavioral_signal.similarity_score.toFixed(2)}</span>
          <span>{record.behavioral_signal.triggered ? "triggered" : record.behavioral_signal.reason}</span>
          {record.behavioral_signal.latency_seconds !== undefined && (
            <span>{Math.round(record.behavioral_signal.latency_seconds * 1000)} ms</span>
          )}
        </div>
      )}
      {(record.extracted_facts?.length ?? 0) > 0 && (
        <div className="signal-summary">
          <span className="signal-label">Extraction</span>
          <span>{record.extracted_facts?.length} allowlisted fact(s)</span>
        </div>
      )}
    </article>
  );
}
