export type Outcome = "ALLOW" | "BLOCK" | "ESCALATE" | "REWRITE";

export interface ObservationRecord {
  content: string;
  source?: string;
  trust_label: string;
  sensitivity?: string;
}

export interface MemoryRecord {
  content: string;
  trust_label: string;
  derived_from?: string[];
  written_at?: string;
}

export interface RewrittenAction {
  action_type: string;
  target: string;
  params: Record<string, unknown>;
}

export interface DecisionRecord {
  session_id: string;
  action_type: string;
  target: string;
  outcome: Outcome;
  risk_score: number;
  reason_codes: string[];
  explanation: string;
  rewritten_action: RewrittenAction | null;
  observations: ObservationRecord[];
  memory: MemoryRecord[];
  metadata: Record<string, unknown>;
  /** Assigned client-side / server-side as the line index in the trace file. */
  seq: number;
}
