# Attack Graph Generation

Attack graphs combine the synthesized threat model with TTC metrics to explore feasible attack paths.

Typical steps:
1. Build threat model (assets + tactics + techniques)
2. Compute TTC values for nodes
3. Feed into attack graph walker to enumerate or sample paths

Key module: `AttackGraphGeneration/attackgraph.py`.

## Minimal Example

```python
from AttackGraphGeneration.attackgraph import AttackGraph
ag = AttackGraph(threat_model=tm_graph, system_model=system_model, attacker_level="novice")
ag.generate_attack_graph(number_walks=10)
print(ag.get_shortest_path())
```

## Selecting the Shortest Successful Path

Shortest path = minimal sum of TTC over unique target instances in a successful walk.

```python
sp = ag.get_shortest_path()
if sp:
	for step in sp:
		print(step["technique"]["tactic"], step["technique"]["technique"])
```

See also: [Advanced Attack Graph Usage](attack_graph_advanced.md).

