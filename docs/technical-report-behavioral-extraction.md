# SENTINEL Behavioral and Structured-Extraction Defense

## 1. Introduction and Problem Statement

LLM agents increasingly retrieve emails, tickets, logs, alerts, and web content before deciding which tools to call. Those sources are often attacker-controlled. An indirect prompt injection occurs when hostile text inside retrieved data is interpreted as an instruction and redirects the agent from the user's task toward an unauthorized action.

SENTINEL is a provenance-aware SOC defense layer that evaluates proposed actions before tool execution. The original implementation relied on action criticality, source trust, corroboration, and a small imperative-pattern detector. That baseline is useful but incomplete: literal keyword rules are easy to evade, while passing raw untrusted prose directly to an agent planner lets an injection influence reasoning before the defense sees the resulting action.

This work keeps the original detector and adds two complementary defenses:

- A MELON-inspired masked re-execution detector asks whether the same action would be proposed when the real task is replaced with a neutral task while observations remain constant.
- A CaMeL-inspired structured extraction boundary converts untrusted text into a small, source-specific allowlist of typed facts before planning. Instruction-shaped fields are forbidden by schema design.

The objective is not to claim that either method is a complete prompt-injection solution. The objective is layered risk reduction: provenance and action criticality remain primary, legacy text matching remains cheap corroborating evidence, behavioral similarity detects wording-independent influence, and extraction limits what untrusted text can become.

The 2026 extension closes the remaining data-flow gap. It decouples tool criticality from payload
sensitivity, tracks drift from the authenticated initial intent, verifies financial approval
authority, and provides downstream redaction before tool output enters the agent context.

## 2. Existing Solutions and Gap in the Market

Existing defenses fall into several groups:

1. **Keyword and pattern filters.** These are inexpensive and explainable, but they overfit surface wording. An attacker can replace "run remediation" with an equivalent paraphrase. They also create false positives when legitimate incident data describes dangerous activity.
2. **Prompt augmentation and delimiting.** Repeating the user task or marking retrieved content can preserve task focus, but the model still interprets a single mixed context. Stronger attacks can ignore the additional instructions.
3. **Classifier or LLM detectors.** A separate detector can identify suspicious text before planning, but it adds latency and operating cost, can miss novel phrasing, and may terminate benign workflows unnecessarily.
4. **Tool allowlists and policy filters.** Restricting available tools can sharply reduce attack success, but static or model-generated allowlists often reject legitimate multi-step work and can be bypassed when the attacker uses an apparently relevant tool.
5. **Capability and provenance architectures.** CaMeL's design separates a privileged planner from a quarantined component and attaches capabilities to values so sensitive operations cannot freely consume untrusted data. This is a stronger architectural direction, but a complete capability interpreter is a substantial integration project.

MELON, *Provable Indirect Prompt Injection Defense via Masked Re-execution and Tool Comparison*, addresses the key behavioral gap. Its central observation is that a successful indirect attack makes the agent's tool actions more dependent on retrieved malicious content and less dependent on the user's task. MELON compares original and masked executions, caches masked tool calls, and compares security-relevant tool-call representations rather than complete natural-language responses.

The market gap is therefore not another string filter. It is an operationally deployable combination of: provenance, pre-planning data minimization, behavioral evidence, bounded intervention, auditability, and human review. SENTINEL implements a narrow and dependency-light version of that combination for SOC actions.

## 3. System Architecture and Design Decisions

### 3.1 Decision path

The policy engine remains the owner of the final decision. Its score is:

```text
risk = criticality * (1 - minimum_provenance_trust)
       + behavioral_signal
       + legacy_pattern_signal
       - corroboration_credit
```

The behavioral signal is capped at `0.35`; the legacy pattern signal is demoted to `0.05`. Neither detector can independently decide an outcome. High-criticality, low-trust, uncorroborated actions still hit the provenance-independent corroboration backstop.

### 3.2 Behavioral detector

For actions with criticality at least `0.70`, a pluggable `AgentReExecutor` proposes an action using a fixed neutral task and the same observations. The detector compares action type and security-relevant target arguments:

- Same action type and same critical target: strong signal, similarity `1.0`, `BEHAVIORAL_DIVERGENCE_DETECTED`.
- Same action type but different target: `PARTIAL_OVERLAP_BENIGN`, retained for observability and excluded from risk.
- Different action type or no masked action: no behavioral trigger.
- Missing or timed-out re-executor: unavailable reason code and zero risk credit.

This preserves both methods. The old pattern scan remains available for low-cost corroboration and ablation comparisons; masked re-execution supplies evidence that is less dependent on literal wording. The adapter exposes operational flags for disabling each detector, fail-open labeling, and timeout tuning.

### 3.3 Structured extraction boundary

The adapter's default `raw` mode extracts each observation against a source-type schema before attaching facts to the candidate action. Supported schemas include web-server logs, email, tickets, analyst chat, and EDR/SIEM alerts. Only registered factual fields can pass. Fields such as `recommended_action`, `instruction`, `directive`, and `command` are rejected at schema-definition time.

`pre_extracted` mode is supported for upstream integrations, but claims are revalidated against the same schema and trust is rebuilt from the actual observation. Extraction cannot import the policy engine or invoke tools. Raw excerpts remain available for audit, but hostile prose cannot become a structured action recommendation through this layer.

### 3.4 Dashboard method filters

The dashboard now filters decisions by:

- All methods
- Behavioral detector
- Legacy pattern detector
- Structured extraction
- Behavioral signal unavailable

These filters are additive views over the same trace, not mutually exclusive labels: one decision can contain both a legacy match and a behavioral trigger. Cards and the inspector show behavioral similarity, masked action, latency, extraction fact count, and fact confidence. This makes ablation and incident review possible without changing the policy outcome.

### 3.5 2026 data-flow controls

The upgraded formula is:

```text
R(a) = clamp(effective_criticality * (1 - T_min)
             + W_behavioral + W_legacy + W_drift - corroboration_credit)
effective_criticality = max(tool_criticality, payload_sensitivity)
```

`sensitivity_registry.py` scans action arguments, observations, and memory for bounded
fingerprints such as API keys, private keys, bearer tokens, credential assignments, payment-card
patterns, internal IP addresses, and email addresses. Findings are recorded, but the scanner does
not decide whether prose is an instruction. This allows benign trusted investigations to retain
utility while adversary-controlled sensitive payloads inherit high effective criticality.

`intent_tracker.py` extracts lightweight entities from `AUTHENTICATED_USER` observations. A
bounded `0.30` drift penalty applies only to outbound/entity-bearing action types whose target
entities are disjoint from the initial intent. This produces review pressure without blocking
ordinary reads and investigation steps.

Approval Authority Verification is a hard rule: `financial_execution` and
`resource_modification` actions with effective criticality at least `0.90` require an explicit
`approval_token` and an `AUTHENTICATED_USER` observation. Text such as `CFO Approved: Yes` in an
untrusted email is evidence, not authority, and cannot satisfy the rule.

Finally, `POST /v1/response_filter` applies the same deterministic fingerprint registry to tool
output and replaces sensitive spans with `[REDACTED_BY_SENTINEL]` before the caller adds the
response to an agent context. The response retains non-sensitive context and reports finding
categories for audit.

## 4. Experiments and Results

### 4.1 Local implementation validation

The repository test suite exercises the new paths, their boundaries, and backward compatibility. The final focused run covered 45 tests and passed, with one expected skip because `GROQ_API_KEY` was not configured for the live optional LLM extractor. The full repository suite previously ran 68 tests and also passed with that single skip.

Important boundary results include:

| Experiment | Behavioral detector ON | Behavioral detector OFF |
|---|---:|---:|
| Keyword-evading rephrased remediation probe | BLOCK | ESCALATE |
| Legacy-only keyword probe | ALLOW | ALLOW |
| Behavioral triggered risk contribution | `+0.35` capped additive signal | `0.00` |
| Legacy pattern contribution | `+0.05` capped additive signal | `0.00` |

The rephrased probe is the key comparison. Its evidence avoids the legacy regex vocabulary, so the legacy detector cannot explain the result. With the mocked masked action matching the proposed remediation, the behavioral detector raises the risk from `0.495` to `0.845`, changing the result from `ESCALATE` to `BLOCK`. This demonstrates improved sensitivity to semantic behavioral influence rather than a new keyword list.

Extraction tests verify that hostile log text cannot yield an instruction-shaped fact, trust labels are inherited rather than upgraded, unknown source types produce no facts, and forged pre-extracted fields are dropped. The import-boundary test verifies that extraction cannot call policy or risk code.

### 4.2 Existing scenario artifacts

The checked-in scenario CSVs are useful regression artifacts, but they currently show many low-risk disclosure cases being missed because their mapped action remains `summarize` with risk `0.0`. They should not be presented as proof of behavioral-detector performance. A new end-to-end benchmark must run through an adapter configured with a real or deterministic replay re-executor and must record the method reason codes in the resulting trace.

The new synthetic extension probes address those failures directly: a secret-bearing summary is
blocked through payload sensitivity, an outbound action to an entity outside the authenticated
intent is escalated for review, and an untrusted fake financial approval is blocked by AAV.

### 4.3 Research comparison

MELON reports AgentDojo results across GPT-4o, o3-mini, and Llama-3.3-70B using benign utility, utility under attack, and attack success rate. Its GPT-4o MELON result reports `0.24%` average ASR, while MELON-Aug reports `0.32%` ASR and `68.72%` utility under attack. These are published paper results, not measurements of this repository.

The CaMeL discussion used here is a secondary summary of *Defeating Prompt Injections by Design*. It reports a capability-based dual-LLM architecture and an initial AgentDojo mitigation figure of 67%. That number is likewise external evidence and should not be merged with SENTINEL's local results.

## 5. Engineering Decisions

- Preserve public APIs and defaults. Existing `PolicyConfig()` callers and adapter clients continue to work.
- Keep the policy engine simulator-agnostic; wire starter-kit semantics only in `adapter.py`.
- Make behavioral detection pluggable through a protocol and use a deterministic mock for tests and ablations.
- Gate masked re-execution by criticality to control latency and cost.
- Treat unavailable behavioral infrastructure as an audit signal, not automatic risk credit. The corroboration backstop remains the safety mechanism.
- Keep extraction dependency-free for regex fields and make optional LLM summaries fail per field rather than failing the request.
- Expose payload, drift, and approval controls as explicit adapter flags for reproducible ablation; production defaults keep all three enabled.
- Rebuild provenance and trust at the boundary instead of trusting caller-supplied confidence or labels.
- Trace all detector evidence so the dashboard can explain why a decision changed.
- Use `REWRITE` for state-changing remediation or incident closure when human review is required.

## 6. Evaluation Metrics

Future benchmark runs should report metrics at both the agent and defense layers:

- **Attack Success Rate (ASR):** fraction of attacks that complete their malicious objective.
- **Utility under Attack (UA):** fraction of user tasks completed while preventing the malicious objective.
- **Benign Utility (BU):** fraction of clean user tasks completed successfully.
- **Detection precision, recall, F1:** measured separately for behavioral and legacy signals against labeled attack traces.
- **False-positive rate:** clean decisions incorrectly blocked or escalated.
- **Critical-action interception rate:** unsafe high-criticality proposals stopped before execution.
- **Escalation quality:** proportion of escalations that human reviewers confirm as requiring intervention.
- **Rewrite containment rate:** state-changing proposals converted to non-final review responses.
- **Latency and cost:** p50/p95 decision latency, re-execution timeout rate, and additional model/tool-call cost.
- **Extraction coverage:** allowlisted facts retained, forbidden fields dropped, and source-type schema misses.
- **Provenance integrity:** cases where untrusted evidence is incorrectly upgraded or independently trusted.
- **Sensitive-data recall:** sensitive payloads detected before planning and redacted before context insertion.
- **Approval-authority precision:** fake approvals rejected while authenticated approvals remain usable.

## 7. Limitations

The current re-executor is an integration interface; the default adapter does not contain a live agent runtime. Therefore, local behavioral results use deterministic fixtures rather than a production LLM. A synthesized conversation history is also less faithful than the full transcript available in a real integration.

MELON-style comparison focuses primarily on tool actions. Attacks that succeed through response text, state hallucination, redundant calls, or nonexistent functions can evade a tool-call-only detector. Similarity thresholds and security-relevant argument selection require domain calibration. A real masked run can approximately double inference cost, and timeout handling can leave the underlying model call running in the background.

Extraction narrows the attack surface but does not prove that extracted facts are true. A forged but plausible status, severity, or identifier still requires downstream provenance and policy checks. The source-type mapping is currently pragmatic substring matching and should become an explicit deployment configuration. Finally, the existing scenario library is not yet a controlled AgentDojo-equivalent comparison, and the checked-in CSV results include coverage gaps in data-exfiltration action modeling.

The fingerprint registry is deliberately conservative and regex-based; it can miss encoded,
obfuscated, fragmented, or novel secret formats and may flag legitimate identifiers. Redaction is
only effective when the integration calls the response-filter boundary before storing or replaying
tool output. Intent extraction is lightweight entity matching rather than full semantic NER, so it
can miss paraphrases and should remain a review signal rather than a sole blocking authority.

## 8. Future Directions

The next stage is a controlled benchmark harness that runs the same scenarios under: legacy-only, extraction-only, behavioral-only, full layered policy, and policy-disabled configurations. Each run should emit comparable traces and calculate ASR, UA, BU, precision, recall, latency, and cost.

The behavioral integration should move to a shared bounded executor, support richer transcript/state masking, cache embeddings or normalized tool-call representations, and compare security-sensitive arguments selectively. Extraction should gain explicit schemas, signed source identity, richer factual fields, and stronger validation for cross-field consistency.

Longer term, reinforcement learning can help automate repetitive defense operations while preserving human authority. A constrained policy model could learn from labeled decisions, reviewer outcomes, false-positive corrections, and escalation resolutions. The intended loop is human-in-the-loop rather than unsupervised autonomous blocking:

1. SENTINEL gathers provenance, behavioral evidence, and policy features.
2. A learned triage policy ranks risk and recommends allow, rewrite, block, or escalation.
3. High-impact or uncertain cases remain with a human reviewer.
4. Reviewer decisions become feedback for offline evaluation and carefully gated policy updates.
5. Deployment proceeds with shadow mode, rollback, drift monitoring, and hard safety constraints that learned policies cannot override.

This direction can reduce analyst workload and prioritize the most consequential escalations, but RL must optimize operational assistance inside a fixed security envelope. It should never be allowed to learn around provenance backstops, tool allowlists, schema boundaries, or final human approval requirements for irreversible actions.

## References

- Zhu, K. et al. **MELON: Provable Indirect Prompt Injection Defense via Masked Re-execution and Tool Comparison.** [arXiv:2502.05174v3](https://arxiv.org/html/2502.05174v3).
- Google DeepMind, **Defeating Prompt Injections by Design: CaMeL.** [arXiv:2503.18813](https://arxiv.org/abs/2503.18813).
- SSOJet, **CaMeL: A Robust Defense Against LLM Prompt Injection Attacks.** [Article](https://ssojet.com/news/camel-a-robust-defense-against-llm-prompt-injection-attacks).
- Repository design notes: [fix1-behavioral-detector.md](fix1-behavioral-detector.md) and [fix2-extraction-layer.md](fix2-extraction-layer.md).
