import { trustScore } from "@/lib/risk";

export interface RequestSummary {
  tool: string;
  trust: string | null;
  argsPreview: string;
}

/** Best-effort summary of a candidate_action request body, for display only. */
export function deriveRequestSummary(payload: Record<string, unknown>): RequestSummary {
  const candidateAction = (payload.candidate_action ?? {}) as Record<string, unknown>;
  const tool = typeof candidateAction.tool === "string" ? candidateAction.tool : "—";
  const args = (candidateAction.arguments ?? {}) as Record<string, unknown>;
  const argsPreview = Object.entries(args)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(", ");

  const provenanceList = Array.isArray(payload.provenance) ? payload.provenance : [];
  let lowestLabel: string | null = null;
  let lowestScore = Infinity;
  for (const entry of provenanceList) {
    const provenance = (entry as Record<string, unknown> | null)?.provenance as Record<string, unknown> | undefined;
    const level = provenance?.trust_level;
    if (typeof level !== "string") continue;
    const label = level.toUpperCase();
    const score = trustScore(label);
    if (score < lowestScore) {
      lowestScore = score;
      lowestLabel = label;
    }
  }

  return { tool, trust: lowestLabel, argsPreview };
}
