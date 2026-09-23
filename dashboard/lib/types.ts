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

export interface BehavioralSignalRecord {
  triggered: boolean;
  similarity_score: number;
  reason: string;
  latency_seconds?: number;
  masked_action?: string | null;
}

export interface ExtractedFactRecord {
  field: string;
  value: string;
  source_observation_id: string;
  trust_label: string;
  extraction_confidence: number;
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
  behavioral_signal?: BehavioralSignalRecord | null;
  extracted_facts?: ExtractedFactRecord[];
  payload_sensitivity?: number;
  effective_criticality?: number | null;
  intent_drift_penalty?: number;
  sensitivity_findings?: string[];
  metadata: Record<string, unknown>;
  /** Assigned client-side / server-side as the line index in the trace file. */
  seq: number;
}
