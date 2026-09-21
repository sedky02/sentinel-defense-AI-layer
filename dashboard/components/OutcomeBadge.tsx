import type { Outcome } from "@/lib/types";
import { OUTCOME_COLOR, OUTCOME_LABEL } from "@/lib/outcome";

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const color = OUTCOME_COLOR[outcome] ?? "var(--text-muted)";
  return (
    <span className="outcome-badge" style={{ color }}>
      <span className="pip" />
      {OUTCOME_LABEL[outcome] ?? outcome}
    </span>
  );
}
