# Corroboration-rule ablation

| Configuration | Attacks caught | Attacks missed | Hard negatives passed (not over-blocked) |
|---|---:|---:|---:|
| Full policy (corroboration ON) | 1/10 | 9/10 | 3/3 |
| Corroboration rule OFF | 1/10 | 9/10 | 3/3 |

### Interpretation
The corroboration backstop was compared on the same attack and hard-negative scenario set in both runs.
With the rule OFF, 0 additional attack scenario(s) were missed.
Hard-negative pass counts were 3 with the rule ON and 3 with it OFF; lower values indicate over-blocking.
