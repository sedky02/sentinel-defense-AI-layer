import path from "node:path";

/**
 * Single source of truth for where the trace file lives. Defaults to the
 * repo root next to `dashboard/`, matching where demo.py / TraceLogger
 * write `sentinel_decisions.jsonl` by default. Override with TRACE_PATH
 * if you point demo.py at a different file.
 */
export function resolveTracePath(): string {
  const configured = process.env.TRACE_PATH;
  if (configured) return path.resolve(configured);
  return path.resolve(process.cwd(), "..", "sentinel_decisions.jsonl");
}
