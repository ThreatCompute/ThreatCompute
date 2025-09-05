---
title: TTC Calculation Details
description: Mathematical background and component breakdown of Time To Compromise.
tags:
  - ttc
  - risk
---

# TTC Calculation Details

TTC (Time To Compromise) combines three conceptual processes:

| Component | Meaning | Formula (simplified) |
|-----------|---------|----------------------|
| Process 1 | Tuning an existing exploit | `t1 * P1` |
| Process 2 | Developing an exploit (no patch/instrumentation) | `t2 * (1-P1)*(1-u)` |
| Process 3 | Discovering alternative path / new vuln | `t3 * (1-P1)*u` |

Where:
- `P1` is probability an exploit is immediately usable.
- `u` represents uncertainty / need for alternate path.

`t1`, `t2`, `t3` scale inversely with normalized exploitability (max & average).

```python
from TTCComputation.kube_ttc import KUBE_TTC
ttc = KUBE_TTC(cvss_scores, misconfigurations)
components = ttc.calc_TTC_components("intermediate")
print(components)
```

!!! note
    A container with no CVEs or misconfigurations still yields a baseline TTC reflecting discovery cost.

## Aggregation Up the Hierarchy

For Pods / Namespaces / Cluster levels we propagate the minimum TTC of children (most vulnerable descendant) to model a *single weakest link* assumption.

## Future Extensions

Potential enhancements:

- Weighted aggregation (e.g. average vs minimum)
- Incorporate exploit maturity / EPSS
- Temporal decay as patches land
