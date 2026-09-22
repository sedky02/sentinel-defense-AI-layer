# SENTINEL SOC Defense Agent

This is a heuristic baseline for a SOC defense layer. It evaluates proposed agent actions over alerts, logs, incidents, and threat intelligence, where descriptive data may be attacker-controlled. It includes a simulator-facing adapter, batch evidence runner, ablation runner, a live trace dashboard, and a documentation-only EU AI Act alignment report.

## Decision model

The core decision is driven by **action criticality × provenance trust × independent corroboration**:

`risk = criticality * (1 - minimum_trust) + pattern_signal - corroboration_credit`

Risk is clamped to `[0, 1]`. High-criticality actions justified only by low-trust, uncorroborated information are blocked as a backstop against fake approvals and hostile log text.

Instruction-pattern detection is explicitly a minor signal, not the core defense: **“This is a minor supporting signal only. It contributes a small weight to the risk score and must never independently justify a decision. Core decisions are driven by action criticality and provenance trust, per SENTINEL's rule against keyword-matching as a core defense.”** Its contribution is capped at `0.15`.

Outcomes are `ALLOW`, `ESCALATE`, `BLOCK`, or `REWRITE`. For selected state-changing tool calls with adequate provenance, `REWRITE` replaces execution with a non-final human-review response. Low-trust high-criticality actions still use the hard block backstop.

## Memory provenance

Memory has trust inheritance. A memory entry receives the minimum trust label of every observation used to write it, and this label is retained when it is read. Therefore, a fake policy from an untrusted newsletter cannot silently become a trusted policy source merely because the agent stored it in memory.

## Run

```bash
python -m unittest discover -s tests -v
```

For the complete local SOC demonstration, run the adapter against all 13 public SOC scenarios from the starter kit and open the live dashboard:

```bash
./run_demo.sh
```

This writes `results/soc_trace.jsonl` and `results/scenario_results.csv`. The current public SOC batch produces 64 decision actions across 13 scenario files. The dashboard shows actions, not scenarios: one scenario can produce several policy decisions.

For the smaller seven-action policy walkthrough, use:

```bash
python -m sentinel_soc_defense.demo --trace sentinel_decisions.jsonl
```

That demo includes benign and hard-negative work plus hostile-log, memory-poisoning, tool-output tampering, multi-step, and exfiltration-shaped actions.

## Official SENTINEL simulator adapter

Start the defense service in one terminal:

```bash
python -m sentinel_soc_defense.adapter --port 8080 --trace sentinel_decisions.jsonl
```

Then point the starter-kit simulator at it:

```bash
sentinel run --scenario path/to/scenario.yaml --defense-url http://127.0.0.1:8080
```

The adapter is stdlib HTTP and matches the inspected starter-kit v1 contract: `GET /healthz` and `POST /v1/decision`. It returns the strict lowercase `allow`/`block`/`escalate`/`rewrite` decision shape with risk score, confidence, reason codes, explanation, and metadata. `adapter.py` contains the external-schema translation boundary. Every request and response decision is retained in the trace, including provenance and agent state metadata.

For a containerized drop-in service:

```bash
docker build -t sentinel-soc-defense .
docker run -p 8080:8080 sentinel-soc-defense
```

## Scenario batch evidence

With the adapter running and the published scenario library available locally:

```bash
python -m sentinel_soc_defense.batch_runner path/to/scenarios --defense-url http://127.0.0.1:8080
```

This writes `results/scenario_results.csv`, prints pass rates by attack family and difficulty, and uses the simulator's machine-checkable outcome (`task_success`, `attack_success`, and `critical_violation`) rather than any scenario-specific expected result. It filters to declared SOC scenarios plus declarative hard-negative scenarios.

## Ablation study

```bash
python -m sentinel_soc_defense.ablation path/to/scenarios
```

This starts an isolated adapter subprocess for each of four configurations—full policy, corroboration
backstop disabled, instruction detector disabled, and memory-trust inheritance disabled—while holding
all other switches at their full-policy defaults.  It also runs five in-process synthetic boundary
probes that isolate each toggle's effect independently of whether the external simulator scenarios
happen to exercise that code path:

| Probe | What it tests |
|---|---|
| A — Corroboration backstop | High-criticality action, single untrusted source: BLOCK vs ESCALATE |
| B — Instruction detector | Adversary-controlled imperative text tips risk from ALLOW to ESCALATE |
| C — Memory-trust inheritance | Memory-only action from untrusted source: BLOCK vs ALLOW |
| D — Safe-rewrite path | `remediation_execute` with trusted provenance always produces REWRITE |
| E — Tool-permission enforcement | Tool outside `allowed_tools` always produces BLOCK |

The report is written to `results/ablation_results.md`.  `N/A` in the scenario batch means the
selected scenarios did not provide enough machine-scoreable examples of a given type; it is
deliberately not presented as a score.

## Observability dashboard

The recommended live dashboard workflow is:

```bash
./run_demo.sh
```

The live Next.js dashboard reads the trace selected by `TRACE_PATH` (the script uses `results/soc_trace.jsonl`). To render a standalone HTML snapshot from any trace:

```bash
python -m sentinel_soc_defense.dashboard \
  --trace results/soc_trace.jsonl \
  --output dashboard.html \
  --results results/scenario_results.csv
```

The dashboard provides a focused live console with outcome metrics, risk trend, filters, provenance inspection, reason codes, and scenario-family context. The standalone renderer produces an offline HTML snapshot with action/decision cards, risk gauges, outcome colors, reason codes, and visible observation/memory provenance.

The frontend can be built without network access:

```bash
cd dashboard
npm run build
```

## EU AI Act alignment note

`sentinel_soc_defense/compliance.py` is a read-only documentation/reporting aid. It does not participate in decision-making and does not change `policy.py`, `TraceLogger`, or `Decision` behavior. It maps existing policy thresholds and trace records to Articles 9 (risk management), 12 (record-keeping), and 14 (human oversight).

Generate the report for an existing trace with:

```bash
python run_compliance_check.py results/soc_trace.jsonl
```

The output is written to `results/eu_ai_act_alignment.md`. The report computes field coverage from the actual JSONL records; for example, the current trace format has no top-level timestamp field, so that gap is reported rather than inferred. This is an architectural correspondence note, not a legal conformity assessment.

## Focused ablation and readable trace

The final comparison removes only the high-criticality, low-trust corroboration backstop; all other policy logic stays identical:

```bash
python -m sentinel_soc_defense.ablation /tmp/sentinel_starter_kit/scenarios/public/soc
```

The report is written to `results/ablation_results.md` and compares attack catches/misses with hard-negative pass counts. To render the raw trace as a simple chronological table:

```bash
python -m sentinel_soc_defense.render_trace sentinel_decisions.jsonl > trace_output.md
```

`demo.py` prints this same table after its scenarios, so it is directly usable during a screen recording.

## Known limitations

- No encoding or obfuscation detection yet (for example base64/hex exfiltration).
- No adaptive or multi-step composition handling yet.
- Thresholds and registry weights are hand-tuned, not calibrated.
- The current `TraceLogger` schema does not emit a top-level timestamp; the Article 12 report records this as a coverage gap.

## Next iterations

- Richer corroboration weighting across independent trust sources.
- A provenance graph visualizer.
- An encoding-aware exfiltration detector.
- A learned risk model to replace the hand-tuned formula.
