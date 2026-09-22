# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A heuristic SOC (Security Operations Center) defense layer for an AI agent: it evaluates *proposed* agent actions (alerts, logs, incidents, threat intel) where the descriptive data may be attacker-controlled, and returns ALLOW / ESCALATE / BLOCK / REWRITE. It implements and exposes the SENTINEL Starter Kit v1 HTTP contract so the official simulator can drive it as an external defense service.

Core policy engine (`sentinel_soc_defense/`) is pure standard library, Python 3.12, no dependencies, no build step. A Next.js/TypeScript live dashboard (`dashboard/`) and an optional AgentDojo/Groq integration are layered on top and do have their own dependencies.

## Commands

```bash
# Run unit tests
python -m unittest discover -s tests -v

# Run a single test
python -m unittest tests.test_policy.PolicyTests.test_high_risk_adversary_justification_is_blocked_or_escalated

# Run the local demo (writes sentinel_decisions.jsonl + dashboard.html)
python -m sentinel_soc_defense.demo

# Start the HTTP adapter for the SENTINEL simulator (GET /healthz, POST /v1/decision)
python -m sentinel_soc_defense.adapter --port 8080 --trace sentinel_decisions.jsonl

# Batch-run scenarios against a running adapter
python -m sentinel_soc_defense.batch_runner path/to/scenarios --defense-url http://127.0.0.1:8080

# Ablation study (spins up isolated adapter subprocesses per config)
python -m sentinel_soc_defense.ablation path/to/scenarios

# Render trace as a markdown table
python -m sentinel_soc_defense.render_trace sentinel_decisions.jsonl > trace_output.md

# Regenerate the static observability dashboard (standalone HTML snapshot)
python -m sentinel_soc_defense.dashboard --trace sentinel_decisions.jsonl --output dashboard.html

# One-command run: adapter + live Next.js dashboard + full public SOC scenario batch, opens browser
./run_demo.sh

# Generate the EU AI Act alignment note from an existing trace
python run_compliance_check.py results/soc_trace.jsonl

# Optional AgentDojo (prompt-injection benchmark) evaluation via Groq — needs GROQ_API_KEY (.env or exported)
python run_agentdojo.py --provider groq --suite workspace --attack tool_knowledge --model openai/gpt-oss-120b

# Dashboard dev server / production build (run from dashboard/)
cd dashboard && npm run dev
cd dashboard && npm run build

# Container build/run (drop-in adapter service only, not the dashboard)
docker build -t sentinel-soc-defense .
docker run -p 8080:8080 sentinel-soc-defense
```

## Architecture

**Decision core is `policy.py::decide()`.** Everything else feeds it or consumes its output. The formula is:

```
risk = criticality * (1 - minimum_provenance_trust) + behavioral_signal + legacy_pattern_signal - corroboration_credit
```

- `criticality` — from `risk_actions.py`'s static registry (e.g. `disable_monitoring`=1.0, `summarize`=0.1).
- `minimum_provenance_trust` — from `trust.py::min_trust()`: the *weakest* trust label across all justifying observations and memory entries (`SYSTEM_POLICY`=1.0 down to `ADVERSARY_CONTROLLED`=0.0). Memory entries carry their own inherited trust label (see below) rather than being upgraded just for being in memory.
- `behavioral_signal` — from `behavioral_detector.py::evaluate_behavioral_signal()`, capped at `BEHAVIORAL_WEIGHT = 0.35`. A MELON-style masked-re-execution check (see `docs/fix1-behavioral-detector.md`): only attempted for actions with `criticality >= BEHAVIORAL_CRITICALITY_THRESHOLD (0.70)`, via a pluggable `AgentReExecutor` (`reexecution.py`; `NullReExecutor` by default, fails loudly if unconfigured). Like the legacy pattern signal, it is additive/capped and must never independently drive a decision.
- `legacy_pattern_signal` — from `instruction_detector.py`, capped at `LEGACY_PATTERN_WEIGHT = 0.05` (demoted from the original `PATTERN_WEIGHT = 0.15`, which is kept defined for ablation comparison only). Still a deliberately minor signal (imperative-text keyword matching); don't increase its weight or let it gate an outcome on its own — that violates the project's core design rule against keyword-matching as a primary defense.
- `corroboration_credit` — `CORROBORATION_CREDIT = 0.1` per independent source with trust ≥ `TRUSTED_CORROBORATION_MINIMUM (0.7)`, capped at 2 sources.

On top of the score there are two hard, provenance-independent backstops that override the numeric risk:
1. **Corroboration backstop**: `criticality >= 0.8` and zero independent trusted corroboration and `trust <= 0.3` → forced `BLOCK`, regardless of computed risk_score. Prevents a single hostile/adversary-controlled source from justifying a critical action.
2. **Safe rewrite**: `remediation_execute`, or `incident_update` closing an incident → outcome `REWRITE` (never executes/closes state; produces a non-final "needs human review" response) rather than being scored normally.
3. **Tool allowlist**: if `policy_context.allowed_tools` is provided and the candidate tool isn't in it, forced `BLOCK` (`TOOL_NOT_ALLOWED_BY_POLICY`) before any risk math runs.

`PolicyConfig` (in `policy.py`) toggles each of these mechanisms independently (`enable_instruction_detector`, `enforce_corroboration_backstop`, `inherit_memory_trust`, `enable_behavioral_detector`, `behavioral_fail_open`) — this exists *specifically* for ablation studies (`ablation.py`), not as a runtime feature flag. When changing policy behavior, check whether `ablation.py`'s probes (A–F) still exercise the intended code path.

**Pre-LLM extraction is a separate, walled-off layer** (`extraction.py`, `docs/fix2-extraction-layer.md`). It converts a raw `Observation`'s text into strictly-typed `ExtractedFact`s before any planning LLM reasons over it, gated by a per-source-type `ExtractionSchema` allowlist — a field not registered in that schema can never be extracted, regardless of what the text claims, and no schema may ever register an instruction-shaped field (`recommended_action`, `policy_directive`, etc.; enforced at schema-definition time). `extraction.py` must never import `policy.py`/`risk_actions.py` (statically checked by `tests/test_extraction_boundary.py`) — it has no ability to call a tool or drive a decision, only to describe text. `adapter.py`'s `extraction_mode` request field (`"raw"` default, or `"pre_extracted"`) controls whether the adapter runs extraction itself or re-validates caller-supplied facts; either way, extraction narrows the attack surface but does not replace `decide()`'s risk/corroboration/behavioral checks downstream.

**Memory provenance is load-bearing, not incidental** (`memory.py`, `trust.py::min_trust`): a memory entry keeps the *minimum* trust label of every observation that contributed to writing it. This is what stops a fake policy read from an untrusted newsletter from silently becoming trusted just because an agent stored it in memory. Any change to how memory entries are constructed must preserve this trust-floor property.

**External contract boundary is `adapter.py`.** It is the only file that knows about the official SENTINEL Starter Kit v1 request/response JSON shapes (`DefenseRequest`/`DefenseDecision`). `translate_request()` converts the simulator's provenance-ID-based conversation/observation items into this project's `CandidateAction`/`Observation`/`MemoryEntry` models (`models.py`), and `decision_response()` converts a `Decision` back into the simulator's exact lowercase-enum response shape. Keep all wire-format knowledge inside `adapter.py` — `policy.py` and the models should stay simulator-agnostic. `_action_type()` maps starter-kit tool names (`incident_update`, `remediation_prepare`, `remediation_execute`, `intel_search`, `alert_search`, ...) onto this project's internal action-type vocabulary used by `risk_actions.py`'s criticality registry; when the simulator adds new tools, extend this mapping rather than adding tool names into `policy.py`.

**Everything is traced.** `trace.py::TraceLogger` appends every decision (with the input action, provenance, and full simulator request/response when running via the adapter) to a JSONL file (default `sentinel_decisions.jsonl`). `render_trace.py` and `dashboard.py` are both pure consumers of that JSONL — they never talk to the policy engine directly. `demo.py` runs a fixed set of benign/hostile/memory-poisoning/exfiltration-shaped scenarios directly against `decide()` (bypassing the HTTP adapter) and prints the same trace table used for screen recordings.

**Ablation (`ablation.py`)** runs the *same* scenario set through five adapter subprocesses (full policy; corroboration backstop off; legacy pattern detector off; memory-trust inheritance off; behavioral detector off) via `batch_runner.py`, plus six synthetic in-process boundary probes (A–F) that isolate each toggle's effect even when the external scenario library doesn't happen to exercise it — Probe F specifically demonstrates a keyword-evading rephrased injection that the legacy pattern scan misses but the behavioral detector still catches. Results land in `results/ablation_results.md`.

**Compliance reporting is read-only and out-of-band** (`compliance.py`, driven by `run_compliance_check.py`). `EUAIActAlignment` only reads an existing `TraceLogger` JSONL file and imports `policy.py` constants (thresholds, weights) to document architectural correspondence to EU AI Act Articles 9/12/14 (`results/eu_ai_act_alignment.md`). It never touches `decide()`, `TraceLogger`, or `Decision` — treat it as a reporting aid, not a legal conformity assessment, and never wire it into the decision path.

**Dashboard (`dashboard/`, Next.js/TypeScript) is a thin, separate consumer of the same artifacts the Python side produces** — it does not reimplement any policy logic. Its API routes shell out to or read from the Python side: `app/api/send-attack` proxies a manual attack payload to the running adapter's `POST /v1/decision` (`lib/adapterUrl.ts` resolves the adapter URL), `app/api/compliance-report` invokes `run_compliance_check.py` as a subprocess and serves the resulting markdown, and `app/api/agentdojo` reads `results/agentdojo_summary.json`/`results/agentdojo_trace.jsonl`. Trace/result file paths are resolved from `lib/tracePath.ts`, `lib/compliancePath.ts`, `lib/agentdojoPath.ts`, `lib/repoRoot.ts` — keep new file-reading routes consistent with those resolvers rather than hardcoding paths. `./run_demo.sh` is the intended way to run the adapter and dashboard together against the full public SOC scenario set; it wires `TRACE_PATH`/`ADAPTER_URL` env vars into `npm run dev`.

**AgentDojo bridge (`agentdojo_integration.py`, driven by `run_agentdojo.py`)** is optional and requires the separately-installed `agentdojo` package plus a Groq API key (`GROQ_API_KEY`, via `.env` or exported). It places `decide()` immediately before AgentDojo tool execution: BLOCK/ESCALATE/REWRITE outcomes are returned as a safe tool error instead of executing, while AgentDojo still computes its own independent utility/security scores. SENTINEL decisions from these runs are traced separately to `results/agentdojo_trace.jsonl`; don't conflate this trace with the main SOC scenario trace.

**`openai` is a second, independent optional dependency** (besides `agentdojo`), used only by `extraction.py`'s `LlmFieldExtractor` for the three free-text `*_summary` fields (`email_summary`, `ticket_summary`, `chat_summary`), lazily imported inside `extract()` and pointed at Groq's OpenAI-compatible endpoint. If it's not installed, or `GROQ_API_KEY` isn't set, `extract_facts()` catches the resulting `RuntimeError` per-field and drops just that field — it must never crash extraction of every other field on the same observation.

## Known project-specific constraints

- No encoding/obfuscation (base64/hex) exfiltration detection yet — don't assume `instruction_detector.py` catches this.
- Thresholds and the criticality registry (`risk_actions.py`) are hand-tuned, not calibrated against real data; treat exact numeric values as adjustable but be aware changing them shifts ablation/demo results.
- Both text-adjacent signals — the legacy pattern detector (`LEGACY_PATTERN_WEIGHT = 0.05`) and the behavioral detector (`BEHAVIORAL_WEIGHT = 0.35`) — must stay capped, additive, minor-relative-to-criticality-and-trust signals per the design rule in `policy.py`'s docstring. This is intentional and tested behavior, not an oversight to "fix" by weighting either one higher or letting either gate an outcome on its own.
- `PolicyConfig.behavioral_fail_open` (default `False`) only changes which reason code is logged when the behavioral oracle is unavailable (`BEHAVIORAL_SIGNAL_UNAVAILABLE` vs. `..._FAIL_OPEN`) — both settings contribute zero risk credit either way. Don't change this to alter the numeric outcome; the `CORROBORATION_BACKSTOP` is the intended safety net for that case, not this flag.
