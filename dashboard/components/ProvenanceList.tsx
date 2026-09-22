import type { DecisionRecord } from "@/lib/types";

const UNTRUSTED = new Set(["UNTRUSTED_INTERNAL", "UNTRUSTED_EXTERNAL", "ADVERSARY_CONTROLLED"]);

export function ProvenanceList({ record }: { record: DecisionRecord }) {
  const items = [
    ...record.observations.map((o) => ({
      label: o.source || "observation",
      trust: o.trust_label,
      content: o.content,
    })),
    ...record.memory.map((m) => ({
      label: "memory",
      trust: m.trust_label,
      content: m.content,
    })),
  ];

  if (items.length === 0) {
    return <p className="provenance-empty">No justifications recorded for this action.</p>;
  }

  return (
    <ul className="provenance-list">
      {items.map((item, index) => (
        <li key={index} className={`provenance-item ${UNTRUSTED.has(item.trust) ? "untrusted" : ""}`}>
          <div className="provenance-head">
            <span className="provenance-source">{item.label}</span>
            <span className="provenance-trust">{item.trust}</span>
          </div>
          <p className="provenance-content">{item.content}</p>
        </li>
      ))}
    </ul>
  );
}
