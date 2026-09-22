import { Fragment } from "react";
import { OutcomeBadge } from "./OutcomeBadge";
import { OUTCOME_COLOR } from "@/lib/outcome";
import type { Outcome } from "@/lib/types";
import type { RequestSummary } from "@/lib/requestSummary";

export type PipelineState = "idle" | "sending" | "done" | "error";

export interface PipelineResult {
  decision: string;
  risk_score: number;
  reason_codes: string[];
  explanation: string;
}

const STAGES = [
  { key: "source", label: "You" },
  { key: "adapter", label: "SENTINEL Adapter" },
  { key: "policy", label: "Policy Engine" },
  { key: "decision", label: "Decision" },
] as const;

function isOutcome(value: string): value is Outcome {
  return value === "ALLOW" || value === "BLOCK" || value === "ESCALATE" || value === "REWRITE";
}

function nodeStatus(state: PipelineState, index: number): "idle" | "active" | "pending" | "done" | "error" {
  if (state === "idle") return "idle";
  if (state === "error") return index <= 1 ? "active" : "idle";
  if (state === "sending") return index === 0 ? "active" : "pending";
  return index === 3 ? "done" : "active";
}

function connectorStatus(state: PipelineState, index: number): "idle" | "active" | "sending" | "done" | "error" {
  if (state === "idle") return "idle";
  if (state === "error") return index === 0 ? "active" : index === 1 ? "error" : "idle";
  if (state === "sending") return "sending";
  return "done";
}

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="risk-synth-bar">
      <div className="risk-synth-bar-fill" style={{ width: `${Math.round(value * 100)}%`, background: color }} />
    </div>
  );
}

export function AttackPipeline({
  state,
  requestSummary,
  result,
  errorMessage,
}: {
  state: PipelineState;
  requestSummary: RequestSummary | null;
  result: PipelineResult | null;
  errorMessage: string | null;
}) {
  const outcome = result?.decision.toUpperCase() ?? "";
  const outcomeColor = isOutcome(outcome) ? OUTCOME_COLOR[outcome] : undefined;

  return (
    <div className="attack-pipeline-wrap">
      <div className="attack-pipeline">
        {STAGES.map((stage, i) => (
          <Fragment key={stage.key}>
            <div
              className={`attack-pipeline-node attack-pipeline-node-${nodeStatus(state, i)}`}
              style={i === 3 && state === "done" ? { color: outcomeColor } : undefined}
            >
              <span className="attack-pipeline-node-dot" />
              {stage.label}
            </div>
            {i < STAGES.length - 1 && (
              <div className={`attack-pipeline-connector attack-pipeline-connector-${connectorStatus(state, i)}`}>
                <span className="attack-pipeline-pulse" style={{ animationDelay: `${i * 0.15}s` }} />
              </div>
            )}
          </Fragment>
        ))}
      </div>

      {state === "idle" && (
        <p className="attack-pipeline-hint">Send an attack to watch it move through SENTINEL live.</p>
      )}
      {state === "error" && (
        <p className="attack-pipeline-hint attack-pipeline-hint-error">
          Connection lost{errorMessage ? ` — ${errorMessage}` : ""}
        </p>
      )}

      {(requestSummary || result) && (
        <div className="attack-pipeline-cards">
          <div className="card attack-pipeline-card">
            <div className="attack-pipeline-card-head">
              <span className="section-kicker">ATTACK SENT</span>
            </div>
            <div className="card-action-row">
              <span className="k">Tool</span>
              <span className="action">{requestSummary?.tool ?? "—"}</span>
              <span className="arrow">&rarr;</span>
              <span className="k">Source trust</span>
              <span className="target">{requestSummary?.trust ?? "—"}</span>
            </div>
            {requestSummary?.argsPreview && (
              <p className="card-explanation">{requestSummary.argsPreview}</p>
            )}
          </div>

          <div className="card attack-pipeline-card">
            <div className="attack-pipeline-card-head">
              <span className="section-kicker">SENTINEL DECISION</span>
              {isOutcome(outcome) && <OutcomeBadge outcome={outcome} />}
            </div>
            {result ? (
              <>
                <div className="risk-synth-row">
                  <div className="risk-synth-head">
                    <span>Risk score</span>
                    <strong>{result.risk_score.toFixed(2)}</strong>
                  </div>
                  <Bar value={result.risk_score} color={outcomeColor ?? "var(--text-ghost)"} />
                </div>
                {result.reason_codes.length > 0 && (
                  <div className="reason-codes">
                    {result.reason_codes.map((code) => (
                      <span key={code} className="reason-chip">{code}</span>
                    ))}
                  </div>
                )}
                <p className="card-explanation">{result.explanation}</p>
              </>
            ) : (
              <p className="provenance-empty">Waiting for a decision…</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
