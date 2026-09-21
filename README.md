# SENTINEL SOC Defense Agent

This is a v1 heuristic baseline for a SOC defense layer. It evaluates proposed agent actions over alerts, logs, incidents, and threat intelligence, where descriptive data may be attacker-controlled.

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
python -m sentinel_soc_defense.demo
python -m unittest discover -s tests -v
```

The demo includes a benign intel correlation, a hard negative (summarizing a frightening ransomware alert is still allowed), a hostile-log attack, and a memory-poisoning attack. Decisions are appended as JSONL to `sentinel_decisions.jsonl`.

## Known limitations

- No encoding or obfuscation detection yet (for example base64/hex exfiltration).
- No adaptive or multi-step composition handling yet.
- Thresholds and registry weights are hand-tuned, not calibrated.

## Next iterations

- Richer corroboration weighting across independent trust sources.
- A provenance graph visualizer.
- An encoding-aware exfiltration detector.
- A learned risk model to replace the hand-tuned formula.
