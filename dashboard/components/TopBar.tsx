"use client";

import { useState } from "react";

const DEMO_COMMAND = "python -m sentinel_soc_defense.demo";

export function TopBar({
  connected,
  paused,
  onTogglePause,
  onClear,
  totalCount,
  recentCount,
}: {
  connected: boolean;
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  totalCount: number;
  recentCount: number;
}) {
  const [copied, setCopied] = useState(false);

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(DEMO_COMMAND);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access denied (e.g. insecure context) -- nothing to fall back to.
    }
  };

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-pill">
          <span className={`pulse-dot ${connected ? "live" : "offline"}`} />
          {connected ? "Active Defense Grid" : "Stream Offline"}
        </span>
        <div className="topbar-divider" />
        <span className="topbar-stat">
          Total: <strong>{totalCount}</strong>
        </span>
        <span className="topbar-stat">
          Last 60s: <strong>{recentCount}</strong>
        </span>
      </div>
      <div className="topbar-right">
        <div className="topbar-controls">
          <button type="button" className="btn" onClick={onTogglePause} title="Pause/resume applying new decisions">
            {paused ? "Resume" : "Pause"}
          </button>
          <button type="button" className="btn" onClick={onClear} title="Clear the displayed feed">
            Clear
          </button>
          <button type="button" className="btn primary" onClick={copyCommand} title="Copy the demo run command">
            {copied ? "Copied!" : "Copy Demo Cmd"}
          </button>
        </div>
      </div>
    </header>
  );
}
