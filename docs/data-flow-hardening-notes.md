# Data-Flow Hardening Notes

## Summary

This document captures the additional protection work added after the original behavioral-detector and extraction-layer changes. The core idea is simple: a model may be able to block obvious malicious tool calls, but that is not enough if sensitive data can still flow freely into an agent context, if intent drift is not tracked, or if fake approval text is treated as real authorization.

The update keeps the earlier layered defense model and adds a tighter data-flow layer around the decision path:

- action criticality is no longer treated as the only measure of risk
- payload sensitivity is treated as a first-class risk signal
- outbound actions are checked against the authenticated user intent
- approval authority is verified before financial or resource-changing actions proceed
- tool output is redacted before it is persisted or replayed into an agent context
- telemetry and UI filters expose which method produced the evidence, instead of hiding it behind a single aggregate score

This is intentionally additive. The behavioral detector and extraction boundary remain in place; they are not replaced by the new controls.

## What changed

### 1. Payload sensitivity as an effective-risk input

The risk engine now computes a stronger effective criticality value based on both the action type and the sensitivity of the data it touches.

In practice:

- tool criticality is still important
- sensitive payloads (tokens, keys, credentials, payment strings, internal identifiers, email-like values, private IPs) raise the effective action criticality
- sensitive content can increase the action score even when the tool itself is not obviously dangerous

This closes a common gap: a seemingly benign summary or lookup can become an exfiltration or disclosure event when the content is high-value and attacker-controlled.

### 2. Intent-drift detection

The defense now tracks whether an outbound action is still consistent with the authenticated starting intent.

Examples:

- initial task: review an incident for a customer outage
- outbound action: send a customer database dump to an unknown external email or contact

This is not purely a keyword problem. The goal is to ensure the agent does not silently expand the scope of the original task into unrelated or unauthorized actions.

The implementation uses a bounded review penalty rather than a universal hard block, so it remains useful without disrupting normal workflows.

### 3. Approval authority verification

For critical or irreversible operations, the model now checks whether the request includes a real approval signal and whether that approval belongs to the authenticated user context.

This is important for actions such as:

- financial execution
- resource modification
- privileged operational changes

Text like “CFO approved” inside untrusted chat history is not a valid approval token by itself. Approval authority is treated as a structural requirement, not a prose artifact.

### 4. Downstream response filtering

The adapter exposes a response filter boundary for tool output before it enters a downstream agent context.

This is critical because raw tool output can contain:

- secrets
- internal addresses
- customer identifiers
- leaked credentials
- high-sensitivity snippets that should never be re-used as context without review

The response filter uses deterministic pattern matching and replacement to obfuscate sensitive spans while leaving non-sensitive surrounding context intact. This preserves auditability without allowing sensitive values to flow unchecked.

### 5. UI method visibility

The dashboard now exposes the multi-method view more explicitly:

- behavioral detector
- legacy pattern detector
- extraction boundary
- detector unavailable / fail-open view
- risk breakdown and provenance inspection

This is important because the final safety decision is not just “risk score high.” The user must be able to see why the risk was elevated and which evidence path was used.

## Debugging notes

### Common issues encountered during implementation

1. Wrong working directory for dashboard tasks

The frontend build must be run from the dashboard directory, not from the repository root. The repository root does not contain the Next.js app dependencies, and experience showed repeated “next: command not found” errors when the command was launched from the wrong place.

Correct pattern:

- cd dashboard
- npm install
- npm run build

2. Optional dependency behavior

The extraction layer intentionally fails softly when optional components are missing. The openai integration is lazy and per-field; a missing key or missing package must not kill all extraction work for that observation.

This is a desirable behavior for production stability, but it is easy to misread during debugging if the expectation is that every extraction field must always appear.

3. Distinguishing policy logic from UI logic

The dashboard is a consumer of traces and results. It should not reimplement the defense logic. Debugging gets much easier when the model is treated as a single source of truth and the UI is treated as a reporting layer.

4. Understanding the central risk path

When a result looks wrong, the first place to inspect is the policy risk composition and its provenance trust floor, not the UI card alone. This includes:

- criticality
- minimum trust label among observations and memory
- corroboration count
- behavioral signal
- legacy pattern signal
- payload sensitivity and drift adjustment
- approval requirements

5. Trace-level investigation is essential

A decision can appear surprising when read in isolation. The fully traced request and response metadata usually explain the true issue: source provenance, memory trust, sensitive payload, or missing approval token.

### Useful validation flow

The most useful checks during debugging are:

- run the unit suite
- inspect the trace JSONL output
- validate a few adversarial cases through the adapter
- verify that metadata and reason codes reflect the real trigger, not a broad generic explanation

The project was validated using the repo’s test runner and relevant scenario/adversarial probes. Those commands should be used as the baseline before broader changes.

## Refactoring notes

### Keep the policy engine clean

The core policy should remain simulator-agnostic. The HTTP contract and simulator translation belong in the adapter boundary. This separation is important because the business logic should not be coupled to a single spec or JSON wire format.

If this logic grows further, the right refactor is to isolate:

- trust construction
- sensitive-data scanning
- intent tracking
- approval verification
- final decision scoring

rather than embedding all of them in a monolithic function.

### Separate evidence collection from final decisioning

Evidence should be captured in a structured way, then merged into a final decision. This makes debugging and test design much cleaner.

Good pattern:

- evidence collection: provenance, payload findings, drift, pattern hits, behavioral execution, approval state
- scoring: combine evidence into a risk decision
- output: decision and reason codes

This reduces the chance of hidden conditionals and makes a future learned policy easier to add in a constrained way.

### Keep method filters additive

The UI and trace representations should treat method evidence as additive. A single action can be influenced by more than one signal at a time.

This matters because:

- a legacy keyword detector may flag a text snippet
- behavioral similarity may independently confirm the compromised direction
- extraction may confirm that fields were allowed or blocked before planning

A good trace record should allow the user to see all of those signals without needing a single winner-takes-all label.

### Preserve default safety posture

The repository intentionally keeps production defaults conservative and measurement-friendly. The ablation flags exist for comparison, not as a recommended runtime operating mode.

If future refactoring is done, make sure the default path still enforces the same safety behaviors and that ablation toggles are clearly labeled as diagnostics only.

## Limitations and required changes

### 1. Behavioral detection is still a bounded integration problem

The current behavioral detector is a useful detector, but it depends on a pluggable re-execution interface. Without a real runtime or deterministic re-executor, it is not a full in-the-wild guarantee.

The next step should be a bounded production execution environment that supports:

- controlled masked task replay
- timeout handling
- deterministic comparison of security-relevant tool arguments
- structured audit trail of masked vs. real proposals

### 2. Sensitive-data detection remains heuristic

The current pattern-based sensitive-data registry is intentionally conservative, but it is not complete. It can miss:

- encoded or obfuscated values
- fragmented secrets spread across multiple fields
- evolved credential formats
- novel exfiltration patterns
- domain-specific business secrets

Therefore, the current check acts as a strong early-warning layer rather than a complete data-loss prevention system.

### 3. Intent tracking is lightweight by design

It is intentionally not a full semantic understanding layer. It captures the authenticated user intent and checks target drift using bounded entity matching.

This means it may miss subtle semantic drift, paraphrased targets, or multi-step indirect tasks. It should remain a risk amplifier and escalation trigger rather than the sole authority for blocking.

### 4. Response redaction is only as good as the integration point

The response filter is effective only when it runs before tool output is inserted into the agent context. If a runtime stores or replays tool output outside this boundary, the benefit can be bypassed.

The required follow-through is:

- ensure every tool-call output goes through the filter
- keep the redacted version in the trace
- preserve a safe summary for downstream reasoning

### 5. Scenario coverage still has gaps

The public scenario library and the static artifact outputs are useful but not enough as a final benchmark for all attack types. In particular, coverage is still uneven for:

- exfiltration-heavy workflows
- hidden data-flow leakage
- complex red-team prompts that do not map cleanly to a single tool call

A stronger benchmark should include a set of deterministic, traceable challenge cases with explicit labels for:

- sensitive data exposures
- drift and scope violations
- fake approvals
- tool misuse
- mixed benign-and-malicious evidence

## Recommended next changes

### A. Formalize policy feature documentation

Every policy feature should have a short, explicit contract:

- input data
- signal semantics
- allowed values
- failure mode
- whether it is additive or blocking

This makes maintenance much easier and prevents hidden logic drift as the system expands.

### B. Standardize trace metadata fields

Trace records should carry a consistent set of fields for:

- method signals used
- provenance trust labels
- sensitive-data hits
- tool allowlist state
- approval verification result
- intent-drift status
- final reason codes

This makes both human review and dashboard filtering easier and more reliable.

### C. Expand benchmark coverage

The next benchmark should compare clean behavior vs. attack behavior under:

- full policy
- behavioral detector off
- legacy detector off
- extraction disabled
- intent-drift off
- payload sensitivity off
- approval verification off

That comparison should generate a compact report with ASR, benign utility, false positives, escalation quality, and latency numbers.

### D. Make redaction auditable and reversible only by authorized operators

Sensitive text replacement should remain visible to reviewers and retain a structured reason code indicating which categories were redacted. This helps incident review without exposing the raw secret to the rest of the system.

### E. Treat the 2026 controls as a minimum bar, not the final state

The improvements in this patch are a strong hardening step, but they should not be treated as complete security. They create a more robust governance layer around agent actions, while preserving room for future improvements in benchmark quality, integration safety, and deployment-grade policy enforcement.

## Final takeaway

The key design principle in this update is that unsafe behavior is not only a tool-selection problem; it is also a data-flow and authority problem.

The defense is stronger when it enforces the following chain:

1. untrusted observations are treated as untrusted
2. only allowlisted structured facts survive extraction
3. the action must match the authenticated user intent
4. the payload sensitivity is evaluated, not ignored
5. approval authority is checked before privileged changes
6. tool output is redacted before re-entry into the agent context
7. the final decision is explained in the trace and the dashboard

This is the design that closes the remaining gap left by the behavioral and extraction layers alone.
