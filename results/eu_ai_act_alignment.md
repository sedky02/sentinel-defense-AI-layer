# EU AI Act Alignment Note

## Article 9 — Risk Management

The policy computes risk as `criticality × (1 − minimum provenance trust)`, then
adds the instruction-pattern signal (`0.15` maximum) and subtracts
`0.10` per independent trusted source, capped at two; the result is clamped to `[0, 1]`.
Trusted corroboration uses the policy minimum trust of `0.70`.

- Low risk: below `0.40` — the policy allows the action (subject to tool permission and other branches).
- Medium risk: `0.40` to below `0.70` — the policy returns `ESCALATE`.
- High risk: `0.70` or above — the policy returns `BLOCK`.
- High-criticality actions (`≥ 0.80`) with low trust (`≤ 0.30`) and no trusted corroboration trigger the hard `BLOCK` backstop.
- Tool calls outside the active allowed-tool set are blocked before risk scoring.

## Article 12 — Record-Keeping

Decisions with complete audit fields: 0/72 (0.0%)

Field coverage computed from the trace entries:
- ❌ `timestamp`: 0/72
- ✅ `action_type`: 72/72
- ✅ `risk_score`: 72/72
- ✅ `reason_codes`: 72/72
- ✅ `outcome`: 72/72

Gaps found:
- `timestamp` missing in decision record(s): all decision records

## Article 14 — Human Oversight

Escalation rate: 0/72 (0.0%)

Escalated actions require human approval before execution: **Yes** — verified from `policy.py` and `adapter.py`: `ESCALATE` returns no rewritten action, and the adapter emits a decision response without invoking a tool. The adapter does not itself implement an approval workflow; execution therefore remains the caller's responsibility.

## Scope Note

This system is a synthetic-data research prototype (IndabaX Tunisia SENTINEL challenge).
This alignment note documents architectural correspondence to EU AI Act risk-management,
logging, and oversight provisions; it is not a legal conformity assessment.
