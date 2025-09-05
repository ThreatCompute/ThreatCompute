# Time To Compromise (TTC)

TTC estimation assigns temporal difficulty or likelihood weightings to components and transitions.

Modules:
- `TTCComputation/system_ttc.py`
- `TTCComputation/kube_ttc.py`

Current implementation derives TTC from vulnerability / misconfiguration presence and simple aggregation heuristics.

See: [TTC Calculation Details](ttc_details.md) for formulas & component breakdown.

## Quick Programmatic Use

```python
from TTCComputation.system_ttc import calc_system_ttcs
ttc_map = calc_system_ttcs(system_graph, attacker_skill_level="novice")
for node_id, comp in ttc_map.items():
	print(node_id, comp["TTC"])
```

