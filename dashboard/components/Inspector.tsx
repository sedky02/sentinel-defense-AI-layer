"use client";

import { useState } from "react";
import type { DecisionRecord } from "@/lib/types";
import { OutcomeBadge } from "./OutcomeBadge";
import { ProvenanceList } from "./ProvenanceList";
import { TRUST_TIERS, actionCriticality, corroborationCredit, minTrust } from "@/lib/risk";

const REPLAY_COMMAND = "./run_demo.sh";

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="risk-synth-bar">
      <div className="risk-synth-bar-fill" style={{ width: `${Math.round(value * 100)}%`, background: color }} />
    </div>
  );
}

export function Inspector({ record }: { record: DecisionRecord | null }) {
  const [copied, setCopied] = useState(false);

  const copyReplay = async () => {
    try {
      await navigator.clipboard.writeText(REPLAY_COMMAND);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Ignore -- clipboard may be unavailable outside a secure context.
    }
  };

  if (!record) {
    return (
      <div className="inspector-col">
        <div className="panel">
          <p className="provenance-empty">Select a decision from the stream to inspect its provenance and risk breakdown.</p>
        </div>
      </div>
    );
  }

  const presentTrust = new Set([
    ...record.observations.map((o) => o.trust_label),
    ...record.memory.map((m) => m.trust_label),
  ]);

  const criticality = actionCriticality(record.action_type);
  const trust = minTrust(record);
  const corroboration = corroborationCredit(record);

  return (
    <div className="inspector-col">
      <div className="panel inspector-section">
        <div className="inspector-header">
          <div className="inspector-title">
            Trace Inspector <span className="dim">#{record.session_id}-{record.seq}</span>
          </div>
          <OutcomeBadge outcome={record.outcome} />
        </div>

        <div className="inspector-block">
          <span className="inspector-label">Provenance Trust Tiers Present</span>
          <div className="trust-tier-row">
            {TRUST_TIERS.map((tier) => (
              <span key={tier} className={`trust-tier-chip ${presentTrust.has(tier) ? "present" : ""}`}>
                <span className="pip" />
                {tier}
              </span>
            ))}
          </div>
        </div>

        <div className="inspector-block">
          <div className="risk-synth-head">
            <span className="inspector-label" style={{ marginBottom: 0 }}>
              Risk Synthesis
            </span>
            <strong style={{ color: "var(--text-strong)" }}>{record.risk_score.toFixed(3)}</strong>
          </div>

          <div className="risk-synth-row">
            <div className="risk-synth-head">
              <span>Action Impact Criticality</span>
              <strong>{criticality.toFixed(2)}</strong>
            </div>
            <Bar value={criticality} color="var(--block)" />
          </div>

          <div className="risk-synth-row">
            <div className="risk-synth-head">
              <span>Weakest Provenance Trust</span>
              <strong>{trust.toFixed(2)}</strong>
            </div>
            <Bar value={trust} color="var(--allow)" />
          </div>

          <div className="risk-synth-row">
            <div className="risk-synth-head">
              <span>Corroboration Credit</span>
              <strong>{corroboration.toFixed(2)}</strong>
            </div>
            <Bar value={corroboration} color="var(--rewrite)" />
          </div>
        </div>

        <div className="inspector-block">
          <span className="inspector-label">Justifying Observations &amp; Memory</span>
          <ProvenanceList record={record} />
        </div>

        {record.reason_codes.length > 0 && (
          <div className="inspector-block">
            <span className="inspector-label">Reason Codes</span>
            <div className="reason-codes">
              {record.reason_codes.map((code) => (
                <span key={code} className="reason-chip">
                  {code}
                </span>
              ))}
            </div>
          </div>
        )}

        {record.behavioral_signal && (
          <div className="inspector-block">
            <span className="inspector-label">Masked Re-execution</span>
            <div className="signal-summary">
              <span>Result: {record.behavioral_signal.triggered ? "triggered" : record.behavioral_signal.reason}</span>
              <span>Similarity: {record.behavioral_signal.similarity_score.toFixed(2)}</span>
              <span>Masked action: {record.behavioral_signal.masked_action ?? "none"}</span>
              {record.behavioral_signal.latency_seconds !== undefined && (
                <span>Latency: {Math.round(record.behavioral_signal.latency_seconds * 1000)} ms</span>
              )}
            </div>
          </div>
        )}

        {(record.extracted_facts?.length ?? 0) > 0 && (
          <div className="inspector-block">
            <span className="inspector-label">Allowlisted Extracted Facts</span>
            <div className="reason-codes">
              {record.extracted_facts?.map((fact) => (
                <span key={`${fact.source_observation_id}-${fact.field}`} className="reason-chip">
                  {fact.field} ({fact.extraction_confidence.toFixed(2)})
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="panel" style={{ display: "flex", flexDirection: "column", gap: "0.625rem" }}>
        <div className="inspector-label" style={{ display: "flex", justifyContent: "space-between" }}>
          <span>Replay Utility</span>
          <span style={{ color: "var(--allow)" }}>READY</span>
        </div>
        <div className="cli-row">
          <code>{REPLAY_COMMAND}</code>
          <button type="button" className="cli-copy" onClick={copyReplay}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
    </div>
  );
}
