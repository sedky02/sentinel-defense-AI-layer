import type { DecisionRecord, Outcome } from "@/lib/types";
import { OUTCOME_COLOR } from "@/lib/outcome";

export type FamilyFilter = "all" | "benign" | "attacks";
export type OutcomeFilter = "all" | Outcome;
export type MethodFilter = "all" | "behavioral" | "legacy" | "extraction" | "unavailable";

const BENIGN_FAMILIES = new Set(["benign", "hard-negative"]);
const OUTCOMES: Outcome[] = ["ALLOW", "BLOCK", "ESCALATE", "REWRITE"];
const METHOD_LABELS: Array<{ value: MethodFilter; label: string }> = [
  { value: "all", label: "All methods" },
  { value: "behavioral", label: "Behavioral" },
  { value: "legacy", label: "Legacy pattern" },
  { value: "extraction", label: "Extraction" },
  { value: "unavailable", label: "Unavailable" },
];

function matchesMethod(record: DecisionRecord, method: MethodFilter): boolean {
  if (method === "all") return true;
  if (method === "behavioral") return record.reason_codes.includes("BEHAVIORAL_DIVERGENCE_DETECTED") || record.reason_codes.includes("PARTIAL_OVERLAP_BENIGN");
  if (method === "legacy") return record.reason_codes.includes("LEGACY_PATTERN_MATCHED") || record.reason_codes.includes("INSTRUCTION_PATTERN_DETECTED");
  if (method === "extraction") return (record.extracted_facts?.length ?? 0) > 0;
  return record.reason_codes.some((code) => code.startsWith("BEHAVIORAL_SIGNAL_UNAVAILABLE"));
}

export function ControlBar({
  records,
  familyFilter,
  onFamilyFilterChange,
  outcomeFilter,
  onOutcomeFilterChange,
  methodFilter,
  onMethodFilterChange,
  query,
  onQueryChange,
}: {
  records: DecisionRecord[];
  familyFilter: FamilyFilter;
  onFamilyFilterChange: (value: FamilyFilter) => void;
  outcomeFilter: OutcomeFilter;
  onOutcomeFilterChange: (value: OutcomeFilter) => void;
  methodFilter: MethodFilter;
  onMethodFilterChange: (value: MethodFilter) => void;
  query: string;
  onQueryChange: (value: string) => void;
}) {
  const benignCount = records.filter((r) => BENIGN_FAMILIES.has((r.metadata?.attack_family as string) || "")).length;
  const attackCount = records.length - benignCount;
  const outcomeCounts: Record<Outcome, number> = { ALLOW: 0, BLOCK: 0, ESCALATE: 0, REWRITE: 0 };
  for (const r of records) outcomeCounts[r.outcome] = (outcomeCounts[r.outcome] ?? 0) + 1;
  const methodCounts = Object.fromEntries(
    METHOD_LABELS.map(({ value }) => [value, value === "all" ? records.length : records.filter((r) => matchesMethod(r, value)).length]),
  ) as Record<MethodFilter, number>;

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

        <div className="outcome-filter method-filter">
          <span className="outcome-filter-label">Method:</span>
          {METHOD_LABELS.map(({ value, label }) => (
            <button
              key={value}
              type="button"
              className={`outcome-chip ${methodFilter === value ? "active" : ""}`}
              onClick={() => onMethodFilterChange(value)}
            >
              {label} ({methodCounts[value]})
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
