import type { DecisionRecord, Outcome } from "@/lib/types";
import { OUTCOME_COLOR } from "@/lib/outcome";

export type FamilyFilter = "all" | "benign" | "attacks";
export type OutcomeFilter = "all" | Outcome;

const BENIGN_FAMILIES = new Set(["benign", "hard-negative"]);
const OUTCOMES: Outcome[] = ["ALLOW", "BLOCK", "ESCALATE", "REWRITE"];

export function ControlBar({
  records,
  familyFilter,
  onFamilyFilterChange,
  outcomeFilter,
  onOutcomeFilterChange,
  query,
  onQueryChange,
}: {
  records: DecisionRecord[];
  familyFilter: FamilyFilter;
  onFamilyFilterChange: (value: FamilyFilter) => void;
  outcomeFilter: OutcomeFilter;
  onOutcomeFilterChange: (value: OutcomeFilter) => void;
  query: string;
  onQueryChange: (value: string) => void;
}) {
  const benignCount = records.filter((r) => BENIGN_FAMILIES.has((r.metadata?.attack_family as string) || "")).length;
  const attackCount = records.length - benignCount;
  const outcomeCounts: Record<Outcome, number> = { ALLOW: 0, BLOCK: 0, ESCALATE: 0, REWRITE: 0 };
  for (const r of records) outcomeCounts[r.outcome] = (outcomeCounts[r.outcome] ?? 0) + 1;

  return (
    <div className="control-bar">
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.5rem" }}>
        <div className="segmented">
          <button
            type="button"
            className={`segmented-btn ${familyFilter === "all" ? "active" : ""}`}
            onClick={() => onFamilyFilterChange("all")}
          >
            All Events <span className="count">{records.length}</span>
          </button>
          <button
            type="button"
            className={`segmented-btn ${familyFilter === "benign" ? "active" : ""}`}
            onClick={() => onFamilyFilterChange("benign")}
          >
            Benign <span className="count">{benignCount}</span>
          </button>
          <button
            type="button"
            className={`segmented-btn ${familyFilter === "attacks" ? "active" : ""}`}
            onClick={() => onFamilyFilterChange("attacks")}
            style={familyFilter === "attacks" ? { color: "var(--block)" } : undefined}
          >
            <span style={{ width: 6, height: 6, borderRadius: "999px", background: "var(--block)", display: "inline-block" }} />
            Threats <span className="count">{attackCount}</span>
          </button>
        </div>

        <div className="outcome-filter">
          <span className="outcome-filter-label">Outcome:</span>
          <button
            type="button"
            className={`outcome-chip ${outcomeFilter === "all" ? "active" : ""}`}
            onClick={() => onOutcomeFilterChange("all")}
          >
            All
          </button>
          {OUTCOMES.map((outcome) => (
            <button
              key={outcome}
              type="button"
              className={`outcome-chip ${outcomeFilter === outcome ? "active" : ""}`}
              style={{ color: outcomeFilter === outcome ? OUTCOME_COLOR[outcome] : undefined }}
              onClick={() => onOutcomeFilterChange(outcome)}
            >
              {outcome} ({outcomeCounts[outcome]})
            </button>
          ))}
        </div>
      </div>

      <div className="search-wrap">
        <input
          className="search-input"
          type="text"
          placeholder="filter by action, target, reason code..."
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
        />
      </div>
    </div>
  );
}
