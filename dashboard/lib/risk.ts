import type { DecisionRecord } from "@/lib/types";

/**
 * Mirrors sentinel_soc_defense/trust.py and risk_actions.py so the inspector
 * panel can show the real inputs to decide()'s risk formula for a given
 * record, without the server exposing internal scoring state over the wire.
 * Keep in sync with those files if the registries change.
 */
export const TRUST_SCORES: Record<string, number> = {
  SYSTEM_POLICY: 1.0,
  AUTHENTICATED_USER: 0.85,
  TRUSTED_INTERNAL: 0.7,
  UNTRUSTED_INTERNAL: 0.3,
  UNTRUSTED_EXTERNAL: 0.2,
  ADVERSARY_CONTROLLED: 0.0,
};

export const TRUST_TIERS = [
  "SYSTEM_POLICY",
  "AUTHENTICATED_USER",
  "TRUSTED_INTERNAL",
  "UNTRUSTED_INTERNAL",
  "UNTRUSTED_EXTERNAL",
  "ADVERSARY_CONTROLLED",
] as const;

const HIGH_RISK_ACTIONS: Record<string, number> = {
  close_incident: 0.9,
  disable_monitoring: 1.0,
  suppress_alert: 0.9,
  run_remediation: 0.85,
  change_asset_criticality: 0.8,
  modify_correlation_rule: 0.9,
};

const LOW_RISK_ACTIONS: Record<string, number> = {
  summarize: 0.1,
  add_comment: 0.1,
  correlate_intel: 0.2,
};

const DEFAULT_CRITICALITY = 0.3;

const TRUSTED_CORROBORATION_MINIMUM = 0.7;
const CORROBORATION_CREDIT = 0.1;
const MAX_CORROBORATION_SOURCES = 2;

export function trustScore(label: string): number {
  return TRUST_SCORES[label] ?? 0.0;
}

export function actionCriticality(actionType: string): number {
  return HIGH_RISK_ACTIONS[actionType] ?? LOW_RISK_ACTIONS[actionType] ?? DEFAULT_CRITICALITY;
}

export function minTrust(record: DecisionRecord): number {
  const scores = [
    ...record.observations.map((o) => trustScore(o.trust_label)),
    ...record.memory.map((m) => trustScore(m.trust_label)),
  ];
  return scores.length ? Math.min(...scores) : 0.0;
}

export function corroborationCredit(record: DecisionRecord): number {
  const trustedSources = [
    ...record.observations.map((o) => trustScore(o.trust_label)),
    ...record.memory.map((m) => trustScore(m.trust_label)),
  ].filter((score) => score >= TRUSTED_CORROBORATION_MINIMUM).length;
  return Math.min(trustedSources, MAX_CORROBORATION_SOURCES) * CORROBORATION_CREDIT;
}
