import type { Outcome } from "@/lib/types";

export const OUTCOME_COLOR: Record<Outcome, string> = {
  ALLOW: "var(--allow)",
  BLOCK: "var(--block)",
  ESCALATE: "var(--escalate)",
  REWRITE: "var(--rewrite)",
};

export const OUTCOME_TINT: Record<Outcome, string> = {
  ALLOW: "var(--allow-tint)",
  BLOCK: "var(--block-tint)",
  ESCALATE: "var(--escalate-tint)",
  REWRITE: "var(--rewrite-tint)",
};

export const OUTCOME_LABEL: Record<Outcome, string> = {
  ALLOW: "ALLOWED",
  BLOCK: "BLOCKED",
  ESCALATE: "ESCALATED",
  REWRITE: "REWRITTEN",
};
