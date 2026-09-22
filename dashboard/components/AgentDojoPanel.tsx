"use client";

import { useEffect, useState } from "react";

type AgentDojoSummary = {
  status: "executed" | "not_executed";
  suite?: string;
  attack?: string;
  model?: string;
  utility_pass_rate?: number;
  security_pass_rate?: number;
  utility_cases?: number;
  security_cases?: number;
  utility_failures?: { user_task: string; injection_task: string }[];
  security_failures?: { user_task: string; injection_task: string }[];
  failure_analysis?: string[];
};

export function AgentDojoPanel() {
  const [summary, setSummary] = useState<AgentDojoSummary | null>(null);

  useEffect(() => {
    let active = true;
    const load = () => fetch("/api/agentdojo", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : null)
      .then((data) => { if (active) setSummary(data); })
      .catch(() => { if (active) setSummary(null); });
    load();
    const timer = setInterval(load, 5000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const rate = (value?: number) => value === undefined ? "—" : `${(value * 100).toFixed(1)}%`;

  return (
    <section className="agentdojo-panel panel">
      <div className="agentdojo-head">
        <div>
          <div className="section-kicker">EXTERNAL EVALUATION</div>
          <h2>AgentDojo benchmark</h2>
          <p>Independent prompt-injection evaluation, scored separately from the live trace.</p>
        </div>
        <span className={`agentdojo-status ${summary ? "complete" : "pending"}`}>
          {summary ? "RESULT AVAILABLE" : "NOT EXECUTED"}
        </span>
      </div>

      {!summary ? (
        <div className="agentdojo-empty">
          <strong>No AgentDojo result has been recorded.</strong>
          <span>Run <code>python run_agentdojo.py --provider groq</code> after setting <code>GROQ_API_KEY</code>.</span>
        </div>
      ) : (
        <>
          <div className="agentdojo-meta">
            <span>{summary.suite} suite</span>
            <span>{summary.attack} attack</span>
            <span>{summary.model}</span>
          </div>
          <div className="agentdojo-metrics">
            <div><span>Utility pass rate</span><strong>{rate(summary.utility_pass_rate)}</strong><small>{summary.utility_cases} cases</small></div>
            <div><span>Security pass rate</span><strong>{rate(summary.security_pass_rate)}</strong><small>{summary.security_cases} cases</small></div>
            <div><span>Utility failures</span><strong>{summary.utility_failures?.length ?? 0}</strong><small>task completion</small></div>
            <div><span>Security failures</span><strong>{summary.security_failures?.length ?? 0}</strong><small>injection exposure</small></div>
          </div>
          <div className="agentdojo-analysis">
            <div className="section-kicker">FAILURE ANALYSIS</div>
            {(summary.failure_analysis ?? ["No analysis was recorded."]).map((item) => <p key={item}>{item}</p>)}
          </div>
        </>
      )}
    </section>
  );
}
