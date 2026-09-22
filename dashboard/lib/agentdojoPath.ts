import path from "node:path";

export function resolveAgentDojoSummaryPath(): string {
  const configured = process.env.AGENTDOJO_SUMMARY_PATH;
  if (configured) return path.resolve(configured);
  return path.resolve(process.cwd(), "..", "results", "agentdojo_summary.json");
}
