# Corroboration-rule ablation

| Configuration | Attacks caught | Attacks missed | Hard negatives passed (not over-blocked) |
|---|---:|---:|---:|
| Full policy (corroboration ON) | 3/10 | 7/10 | 2/3 |
| Corroboration rule OFF | 3/10 | 7/10 | 2/3 |

### Boundary probe

| Configuration | Generic borderline outcome |
|---|---|
| Corroboration ON | BLOCK |
| Corroboration OFF | ESCALATE |

### Interpretation
The corroboration backstop was compared on the same attack and hard-negative scenario set in both runs.
With the rule OFF, 0 additional attack scenario(s) were missed.
Boundary probe: rule ON → **BLOCK**; rule OFF → **ESCALATE**. This isolates the backstop's effect even though the published scenarios often remain blocked by the independent risk threshold.
Hard-negative pass counts were 2 with the rule ON and 2 with it OFF; lower values indicate over-blocking.
