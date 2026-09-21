# SENTINEL SOC Defense Agent

This is a v1 heuristic baseline for a SOC defense layer. It evaluates proposed agent actions over alerts, logs, incidents, and threat intelligence, where descriptive data may be attacker-controlled. It now includes a simulator-facing adapter, batch evidence runner, ablation runner, and a static video-ready trace dashboard.

## Decision model

The core decision is driven by **action criticality × provenance trust × independent corroboration**:

`risk = criticality * (1 - minimum_trust) + pattern_signal - corroboration_credit`

Risk is clamped to `[0, 1]`. High-criticality actions justified only by low-trust, uncorroborated information are blocked as a backstop against fake approvals and hostile log text.

Instruction-pattern detection is explicitly a minor signal, not the core defense: **“This is a minor supporting signal only. It contributes a small weight to the risk score and must never independently justify a decision. Core decisions are driven by action criticality and provenance trust, per SENTINEL's rule against keyword-matching as a core defense.”** Its contribution is capped at `0.15`.

Outcomes are `ALLOW`, `ESCALATE`, or `BLOCK` (`REWRITE` is reserved for a future remediation-oriented policy response).

## Memory provenance

Memory has trust inheritance. A memory entry receives the minimum trust label of every observation used to write it, and this label is retained when it is read. Therefore, a fake policy from an untrusted newsletter cannot silently become a trusted policy source merely because the agent stored it in memory.

## Run

```bash
python -m unittest discover -s tests -v
python -m sentinel_soc_defense.demo
```

The demo includes benign and hard-negative work plus hostile-log, memory-poisoning, tool-output tampering, multi-step, and exfiltration-shaped scenarios. It writes a clean `demo_trace.jsonl` and generates `dashboard.html` for screen recording.

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

This starts an isolated adapter for each configuration: full policy, detector disabled, corroboration backstop disabled, and memory-trust inheritance disabled. It writes `results/ablation_results.csv` with attack pass rate, hard-negative pass rate, and false-positive rate. `N/A` means the selected scenarios did not provide enough machine-scoreable examples; it is deliberately not presented as a score.

## Observability dashboard

```bash
python -m sentinel_soc_defense.dashboard --trace sentinel_decisions.jsonl --output dashboard.html
```

Open `dashboard.html` locally. It is a self-contained, offline static page with large action/decision cards, risk gauges, outcome colors, reason codes, and visible observation/memory provenance. If `results/scenario_results.csv` exists, it also displays batch pass rates by attack family.

## Focused ablation and readable trace

The final comparison removes only the high-criticality, low-trust corroboration backstop; all other policy logic stays identical:

```bash
python -m sentinel_soc_defense.ablation /tmp/sentinel_starter_kit/scenarios/public/soc
```

The report is written to `results/ablation_results.md` and compares attack catches/misses with hard-negative pass counts. To render the raw trace as a simple chronological table:

```bash
python -m sentinel_soc_defense.render_trace demo_trace.jsonl > trace_output.md
```

`demo.py` prints this same table after its scenarios, so it is directly usable during a screen recording.

## Known limitations

- No encoding or obfuscation detection yet (for example base64/hex exfiltration).
- No adaptive or multi-step composition handling yet.
- Thresholds and registry weights are hand-tuned, not calibrated.

## Next iterations

- Richer corroboration weighting across independent trust sources.
- A provenance graph visualizer.
- An encoding-aware exfiltration detector.
- A learned risk model to replace the hand-tuned formula.
