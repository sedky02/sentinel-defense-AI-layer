"use client";

import { useState } from "react";
import { ATTACK_PRESETS } from "@/lib/attackPresets";
import { renderMarkdown } from "@/lib/markdown";
import { OUTCOME_COLOR, OUTCOME_LABEL } from "@/lib/outcome";
import type { Outcome } from "@/lib/types";

type SendResult = {
  decision: string;
  risk_score: number;
  confidence: number;
  reason_codes: string[];
  explanation: string;
};

type SendError = { error: string };

function isOutcome(value: string): value is Outcome {
  return value === "ALLOW" || value === "BLOCK" || value === "ESCALATE" || value === "REWRITE";
}

export function AttackConsole() {
  const [presetId, setPresetId] = useState(ATTACK_PRESETS[0].id);
  const [draft, setDraft] = useState(() => JSON.stringify(ATTACK_PRESETS[0].body, null, 2));
  const [parseError, setParseError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<SendResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportOpen, setReportOpen] = useState(false);

  const applyPreset = (id: string) => {
    setPresetId(id);
    const preset = ATTACK_PRESETS.find((p) => p.id === id);
    if (preset) setDraft(JSON.stringify(preset.body, null, 2));
    setParseError(null);
    setResult(null);
    setError(null);
  };

  const send = async () => {
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(draft);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Invalid JSON");
      return;
    }
    setParseError(null);
    setSending(true);
    setResult(null);
    setError(null);

    payload.run_id = `manual-${crypto.randomUUID()}`;

    try {
      const response = await fetch("/api/send-attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = (await response.json()) as SendResult | SendError;
      if (!response.ok || "error" in data) {
        setError("error" in data ? data.error : `HTTP ${response.status}`);
      } else {
        setResult(data);
      }
    } catch {
      setError("network_error");
    } finally {
      setSending(false);
    }
  };

  const generateReport = async () => {
    setReportOpen(true);
    setReportLoading(true);
    setReportError(null);
    try {
      const response = await fetch("/api/compliance-report", { method: "POST" });
      const data = (await response.json()) as { markdown?: string; error?: string; message?: string };
      if (!response.ok || !data.markdown) {
        setReportError(data.message ?? data.error ?? `HTTP ${response.status}`);
      } else {
        setReportMarkdown(data.markdown);
      }
    } catch {
      setReportError("network_error");
    } finally {
      setReportLoading(false);
    }
  };

  const outcome = result?.decision.toUpperCase() ?? "";

  return (
    <section className="panel attack-console">
      <div className="agentdojo-head">
        <div>
          <div className="section-kicker">MANUAL WORKFLOW CHECK</div>
          <h2>Attack Console</h2>
          <p>Send a crafted attack (or benign control) straight at the running adapter and watch the decision land here and in the stream below.</p>
        </div>
      </div>

      <div className="attack-console-controls">
        <select
          className="attack-console-select"
          value={presetId}
          onChange={(e) => applyPreset(e.target.value)}
        >
          {ATTACK_PRESETS.map((preset) => (
            <option key={preset.id} value={preset.id}>{preset.label}</option>
          ))}
        </select>
        <button className="attack-console-send" onClick={send} disabled={sending}>
          {sending ? "Sending..." : "Send attack"}
        </button>
      </div>

      <p className="attack-console-desc">
        {ATTACK_PRESETS.find((p) => p.id === presetId)?.description}
      </p>

      <textarea
        className="attack-console-textarea"
        value={draft}
        onChange={(e) => { setDraft(e.target.value); setParseError(null); }}
        spellCheck={false}
      />

      {parseError && <div className="attack-console-error">Invalid JSON: {parseError}</div>}

      {error === "adapter_unreachable" && (
        <div className="attack-console-error">
          Adapter not reachable — start it with <code>python -m sentinel_soc_defense.adapter --port 8080 --trace &lt;path&gt;</code>
        </div>
      )}
      {error && error !== "adapter_unreachable" && (
        <div className="attack-console-error">Send failed: {error}</div>
      )}

      {result && (
        <div className="attack-console-result">
          <span className="attack-console-result-label">Decision</span>
          <span
            className="attack-console-outcome"
            style={{ color: isOutcome(outcome) ? OUTCOME_COLOR[outcome] : undefined }}
          >
            {isOutcome(outcome) ? OUTCOME_LABEL[outcome] : outcome}
          </span>
          <span>risk {result.risk_score.toFixed(2)}</span>
          <span>{result.reason_codes.join(", ") || "no reason codes"}</span>
          <p>{result.explanation}</p>
        </div>
      )}

      <div className="attack-console-report">
        <button className="attack-console-report-button" onClick={generateReport} disabled={reportLoading}>
          {reportLoading ? "Generating report..." : "Generate & view EU AI Act alignment report"}
        </button>

        {reportOpen && (
          <div className="attack-console-report-body">
            {reportError && (
              <div className="attack-console-error">
                Report generation failed: {reportError}
              </div>
            )}
            {reportMarkdown && !reportLoading && (
              <div
                className="attack-console-report-markdown"
                dangerouslySetInnerHTML={{ __html: renderMarkdown(reportMarkdown) }}
              />
            )}
          </div>
        )}
      </div>
    </section>
  );
}
