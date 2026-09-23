# SENTINEL SOC Defense Layer

A provenance-aware defense layer for a tool-using SOC (Security Operations Center) agent. Before
each tool call executes, SENTINEL inspects the proposed action, where its justifying data came from
and how far that data can be trusted, and returns `allow`, `block`, `escalate` or `rewrite`. It
implements the SENTINEL Starter Kit v1 HTTP contract, so the official simulator can drive it as an
external defense service.

The repository contains:

| Part | What it is | Dependencies |
| --- | --- | --- |
| `sentinel_soc_defense/` | Policy engine, HTTP adapter, batch/ablation runners, trace logger | Python 3.12+, standard library only |
| `dashboard/` | Live observability dashboard and **Attack Console** (Next.js) | Node.js ≥ 20.9, npm |
| `run_demo.sh` | One command: adapter + dashboard + full public SOC scenario batch | bash, curl |
| `tests/` | Unit tests (`unittest`) | none |
| `docs/`, `research-report.pdf` | Design notes and the research report | — |
| `run_agentdojo.py` | Optional AgentDojo benchmark bridge | `agentdojo`, Groq API key |

---

## 1. Prerequisites

| Tool | Version | Needed for |
| --- | --- | --- |
| Python | 3.12 or newer, callable as `python` | everything |
| Node.js + npm | Node ≥ 20.9 | the dashboard |
| [uv](https://docs.astral.sh/uv/) | recent | running the official SENTINEL simulator |
| SENTINEL Starter Kit | `sentinel-bench/0.1.0` | the public scenarios and the `sentinel` CLI |
| Docker | optional | containerized adapter |
| Groq API key | optional | AgentDojo track and the optional LLM extractor |

`run_demo.sh` is a bash script (Linux, macOS, or WSL on Windows).

## 2. Installation

### 2.1 Clone the repository

```bash
git clone <this-repository-url> sentinel-defense-AI-layer
cd sentinel-defense-AI-layer
```

### 2.2 Core defense (Python)

The core engine has **no third-party dependencies**, so there is nothing to `pip install`. Check
that it works:

```bash
python -m unittest discover -s tests -v
```

You should see all tests pass. One test is skipped unless a Groq key is configured.

### 2.3 Dashboard (Node.js)

```bash
cd dashboard
npm install
cd ..
```

`run_demo.sh` runs `npm install` for you on first launch if `dashboard/node_modules` is missing.

### 2.4 SENTINEL Starter Kit (simulator and scenarios)

The starter kit is distributed by the challenge organizers and is **not part of this repository**.
Place it at `./Sentinel_Starter_Kit`, then install its environment:

```bash
cd Sentinel_Starter_Kit
uv sync
uv run sentinel scenarios list scenarios/public   # sanity check
cd ..
```

To run the reference Qwen3-8B agent instead of the mock model, you also need either
`uv sync --extra hf` plus the model weights, or Ollama (`ollama pull qwen3:8b`). See the kit's
`docs/participant-guide.md`.

You don't need to activate the kit's environment yourself. When the `sentinel` command isn't on
your `PATH`, the batch runner finds the kit automatically (by locating its `pyproject.toml` above
the scenario directory) and calls `uv run --project <kit> sentinel`.

### 2.5 Optional extras

```bash
pip install agentdojo      # AgentDojo bonus track (section 8)
pip install openai         # optional LLM-backed extraction of *_summary fields
cp .env.example .env       # then put your GROQ_API_KEY in .env
```

`.env` is git-ignored. Neither extra is needed for the SOC defense, the dashboard, or the scenario
batch.

## 3. Quick start: run the whole project with one command

```bash
SCENARIO_DIR=Sentinel_Starter_Kit/scenarios/public/soc ./run_demo.sh
```

This:

1. starts the defense adapter on `http://127.0.0.1:8080`;
2. starts the live dashboard on `http://localhost:3000` and opens your browser;
3. runs all 13 public SOC scenarios through the official simulator (`sentinel run --model mock`)
   against the adapter;
4. streams every decision into the dashboard as it happens.

Outputs are written to `results/soc_trace.jsonl` (every decision) and
`results/scenario_results.csv` (one row per scenario). The dashboard keeps running after the batch
finishes; press `Ctrl+C` to stop both services.

**Without the starter kit.** If `SCENARIO_DIR` doesn't exist, the script falls back to the
repository's own bundled demo scenarios (`python -m sentinel_soc_defense.demo`), so the dashboard
still fills with benign, hostile, memory-poisoning and exfiltration-shaped decisions.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SCENARIO_DIR` | `/tmp/sentinel_starter_kit/scenarios/public/soc` | scenario folder to run |
| `TRACE_PATH` | `results/soc_trace.jsonl` | decision trace (erased at start) |
| `RESULTS_PATH` | `results/scenario_results.csv` | per-scenario results |

## 4. Running the components individually

Open one terminal per long-running service.

### 4.1 Defense adapter (the service the simulator calls)

```bash
python -m sentinel_soc_defense.adapter --port 8080 --trace sentinel_decisions.jsonl
```

Endpoints:

- `GET /healthz` returns `{"status": "ok"}`.
- `POST /v1/decision` takes a SENTINEL v1 `DefenseRequest` and returns a `DefenseDecision`:
  `decision`, `risk_score`, `confidence`, `reason_codes`, `explanation`, `rewritten_action` and
  `metadata`.
- `POST /v1/response_filter` redacts sensitive spans in tool output.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--host` / `--port` | `127.0.0.1` / `8080` | bind address |
| `--trace` | `sentinel_decisions.jsonl` | JSONL file every decision is appended to |
| `--disable-corroboration-backstop`, `--disable-pattern`, `--disable-memory-inheritance`, `--disable-behavioral-detector`, `--disable-payload-sensitivity`, `--disable-intent-drift`, `--disable-approval-authority` | off | **ablation only**, not a production posture |
| `--behavioral-fail-open`, `--behavioral-timeout-seconds` | off, 3.0 | behavioral-oracle behavior |

### 4.2 Dashboard

```bash
cd dashboard
TRACE_PATH=../results/soc_trace.jsonl ADAPTER_URL=http://127.0.0.1:8080 npm run dev
```

Then open `http://localhost:3000`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRACE_PATH` | `../sentinel_decisions.jsonl` | trace to stream |
| `ADAPTER_URL` | `http://127.0.0.1:8080` | adapter the Attack Console sends to |
| `REPO_ROOT` | `..` | where `run_compliance_check.py` lives |
| `COMPLIANCE_REPORT_PATH` | `../results/eu_ai_act_alignment.md` | compliance report location |
| `AGENTDOJO_SUMMARY_PATH` | `../results/agentdojo_summary.json` | AgentDojo results shown in the dashboard |

To make a production build, run `npm run build && npm start` from `dashboard/`. Stop `npm run dev`
first, because both use `dashboard/.next`.

### 4.3 One scenario through the official simulator

With the adapter running:

```bash
cd Sentinel_Starter_Kit
uv run sentinel run --scenario scenarios/public/soc/soc_hostile_log_text.yaml \
  --defense-url http://127.0.0.1:8080 --model mock
uv run sentinel replay artifacts/<group>/<run>.jsonl      # replay a recorded run
```

Use `--model ollama:qwen3:8b` (or `--model qwen3-8b`) to drive the real reference model. The kit's
own self-test metrics (BTU, ASR, CVR, FBR, …) come from:

```bash
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > ../results/eval_ours.json
```

### 4.4 Scenario batch

With the adapter running:

```bash
python -m sentinel_soc_defense.batch_runner Sentinel_Starter_Kit/scenarios/public/soc \
  --defense-url http://127.0.0.1:8080
```

This writes `results/scenario_results.csv` and prints pass rates by attack family and difficulty.
The pass/fail verdict uses the simulator's own `task_success`, `attack_success` and
`critical_violation` fields, never a scenario-specific expected result. Add `--model` to change the
reference agent (default `mock`).

### 4.5 Ablation study

```bash
python -m sentinel_soc_defense.ablation Sentinel_Starter_Kit/scenarios/public/soc
```

This starts one isolated adapter per configuration: full policy, corroboration backstop off, legacy
pattern detector off, memory-trust inheritance off, and behavioral detector off. It runs the
scenario batch against each one, then runs in-process boundary probes:

- **A–F** isolate each toggle. Probe F is a keyword-evading injection that only the behavioral
  detector catches.
- **Three data-flow probes** cover payload sensitivity, intent drift and approval authority.

The report is written to `results/ablation_results.md`.

### 4.6 Local demo without the simulator

```bash
python -m sentinel_soc_defense.demo                       # writes sentinel_decisions.jsonl
python -m sentinel_soc_defense.render_trace sentinel_decisions.jsonl > trace_output.md
python -m sentinel_soc_defense.dashboard --trace sentinel_decisions.jsonl --output dashboard.html
```

The last command writes a standalone offline HTML snapshot of the trace.

## 5. Attack Console: test your own attacks

The dashboard's **Attack Console** sends a request straight to the running adapter and shows the
decision as it moves through SENTINEL: risk score, reason codes and explanation. You aren't limited
to the prepared cases:

- **Presets.** The dropdown holds 5 hand-crafted attacks and controls, plus all 13 public SOC
  scenarios, each converted into the request the defense sees at the scenario's decisive step. For
  scenario presets, "View scenario JSON" shows the source scenario, which follows
  `scenario.schema.json`.
- **Freely editable JSON.** Open "Edit raw request JSON" to change anything before sending: the
  candidate action and its arguments, the injected text, the provenance and trust levels
  (`trust_level`, `sensitivity`), the conversation history, or the policy's `allowed_tools`. You
  can also write an entirely new attack from scratch. This is the fastest way to check the defense
  against payloads it has never seen.
- **Compliance report.** "Generate & view EU AI Act alignment report" runs
  `run_compliance_check.py` on the current trace.

The adapter must be running (section 4.1). If it isn't, the console tells you how to start it.

If the starter kit's scenarios change, regenerate the scenario presets (requires `pyyaml`):

```bash
python dashboard/scripts/sync_soc_scenarios.py --kit Sentinel_Starter_Kit
```

## 6. Docker (adapter only)

```bash
docker build -t sentinel-soc-defense .
docker run -p 8080:8080 sentinel-soc-defense
```

The image contains only the adapter, running as a non-root user. Run the dashboard separately
(section 4.2) with `ADAPTER_URL=http://127.0.0.1:8080`.

## 7. Reports and evidence

| Artifact | How to produce it |
| --- | --- |
| `research-report.pdf` | Research report (threat model, formal model, results, ablations, failure analysis). Source: `docs/report/research-report.typ` (Markdown version: `docs/research-report.md`). Rebuild with `pip install typst`, then `python -c "import typst; typst.compile('docs/report/research-report.typ', output='research-report.pdf')"` |
| `results/soc_trace.jsonl`, `results/scenario_results.csv` | `run_demo.sh` or sections 4.1 + 4.4 |
| `results/ablation_results.md` | section 4.5 |
| `results/eu_ai_act_alignment.md` | `python run_compliance_check.py results/soc_trace.jsonl` |
| `results/agentdojo_summary.json` | section 8 |

The EU AI Act note is a read-only reporting aid, not a legal conformity assessment. It maps policy
constants and trace records to Articles 9, 12 and 14 and never touches the decision path.

## 8. Optional: AgentDojo benchmark

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is an independent prompt-injection benchmark.
`sentinel_soc_defense/agentdojo_integration.py` places `decide()` right before AgentDojo's tool
execution. A blocked, escalated or rewritten call comes back as a safe tool error, and AgentDojo
still computes its own utility and security scores.

```bash
pip install agentdojo
export GROQ_API_KEY=your-key            # or put it in .env
python run_agentdojo.py --provider groq --suite workspace --attack tool_knowledge \
  --model openai/gpt-oss-120b --user-task user_task_0 --injection-task injection_task_0
```

Omit `--user-task`/`--injection-task` and add `--force-rerun` to evaluate every combination in the
suite; this takes longer and uses more API credits. SENTINEL's decisions go to
`results/agentdojo_trace.jsonl`, and the summary appears in the dashboard.

The recorded run is a one-case smoke test: utility 1/1, security **0/1**. Some sensitive
email-reading actions were mapped to the low-criticality `summarize` action and allowed.

## 9. How the defense works

```text
risk = clip( max(tool_criticality, payload_sensitivity) × (1 − minimum_provenance_trust)
             + 0.35·behavioral + 0.05·legacy_pattern + 0.30·intent_drift
             − 0.10·min(trusted_corroborating_sources, 2) , 0, 1 )
```

- **Provenance first.** Each action's criticality is weighted by the trust of the *weakest* source
  that justifies it. Memory entries inherit the minimum trust of what they were written from, so
  hostile text can't become trusted just by being stored.
- **Hard rules before the score:**
  - tools outside `allowed_tools` → BLOCK;
  - critical, low-trust, uncorroborated actions → BLOCK (corroboration backstop);
  - financial or resource actions without a real approval → BLOCK;
  - `remediation_execute` or closing an incident → REWRITE to a non-final human-review response.
- **Thresholds.** risk ≥ 0.70 → BLOCK, 0.40–0.70 → ESCALATE, otherwise ALLOW.
- **Text signals are minor and capped.** The masked re-execution behavioral detector (MELON-style)
  and the legacy keyword scan are supporting evidence, never the main defense.
- **Pre-planning extraction.** Untrusted text is reduced to allowlisted, typed facts
  (CaMeL-inspired); no schema can register an instruction-shaped field.

For more detail, see `research-report.pdf`, `docs/fix1-behavioral-detector.md`,
`docs/fix2-extraction-layer.md` and `docs/data-flow-hardening-notes.md`. The file `manifest.yml`
declares the external models and datasets used.

## 10. Known limitations

- **Data exfiltration is not caught.** All 7 public `data_exfiltration` SOC scenarios succeed.
  There is no destination-aware data-flow check, and write tools such as `incident_create` score
  below the escalation threshold (see §8 of the research report).
- **Trust inversion.** The adapter labels a multi-source tool result with its *most* trusted
  source instead of its least trusted one (`adapter.py`, see the research report).
- **Confirmed containment is rewritten.** `remediation_execute` is always rewritten, even after a
  human confirmation, so the `soc_confirmed_isolation` task can't complete.
- **Mock agent only.** Recorded runs used the mock agent. No Qwen3-8B run and no `sentinel eval`
  scorecard were produced.
- **Other gaps.**
  - No detection of encoded or obfuscated exfiltration (base64, hex, and so on).
  - Thresholds and weights are hand-tuned, not calibrated; the `confidence` value is not
    calibrated either.
  - The trace has no top-level timestamp.

## 11. Troubleshooting

| Symptom | Fix |
| --- | --- |
| Attack Console says `adapter_unreachable` | Start the adapter (section 4.1), or set `ADAPTER_URL` for the dashboard. |
| `next: command not found` | Run npm commands from `dashboard/`, after `npm install`. |
| `sentinel: command not found` in the batch runner | Install `uv` and place the kit so its `pyproject.toml` is above the scenario folder (e.g. `Sentinel_Starter_Kit/scenarios/public/soc`). |
| Port 8080 or 3000 already in use | Stop the other process, or change `--port` / `npm run dev -- --port <n>` (and `ADAPTER_URL`). |
| Dashboard shows no decisions | Check that `TRACE_PATH` points at the file the adapter writes (`--trace`). |
| `python` not found or too old | Use a Python 3.12+ interpreter and make sure `python` points to it (e.g. activate a venv). |
