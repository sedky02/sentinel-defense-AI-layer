"""Action criticality registry; callers can extend this mapping later."""

# Criticality is the primary risk input.  These values are deliberately explicit
# so a future policy can replace this static registry without changing callers.
HIGH_RISK_ACTIONS: dict[str, float] = {
    "close_incident": 0.9,
    "disable_monitoring": 1.0,
    "suppress_alert": 0.9,
    "run_remediation": 0.85,
    "change_asset_criticality": 0.8,
    "modify_correlation_rule": 0.9,
    "financial_execution": 0.95,
    "resource_modification": 0.95,
}

# Low-risk actions are allowed unless provenance/risk signals indicate otherwise.
LOW_RISK_ACTIONS: dict[str, float] = {
    "summarize": 0.1,
    "add_comment": 0.1,
    "correlate_intel": 0.2,
}
DEFAULT_CRITICALITY = 0.3  # Conservative weight for actions not yet classified.


def action_criticality(action_type: str) -> float:
    return HIGH_RISK_ACTIONS.get(
        action_type, LOW_RISK_ACTIONS.get(action_type, DEFAULT_CRITICALITY)
    )
