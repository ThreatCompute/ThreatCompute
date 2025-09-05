---
title: Advanced Attack Graph Usage
description: Configuration patterns, weighting strategies, and programmatic APIs for attack graph generation.
tags:
  - attack-graph
  - advanced
---

# Advanced Attack Graph Usage

This page expands on the basics and shows how to:

1. Configure attacker skill / TTC weighting
2. Use progress callbacks & early stopping
3. Persist and reload graph statistics
4. Extract shortest successful paths
5. Perform aggregate impact analysis

## 1. Attacker Skill & TTC Weighting

TTC values bias random walk sampling: lower TTC => higher selection probability.

```python
from AttackGraphGeneration.attackgraph import AttackGraph

ag = AttackGraph(threat_model=tm, system_model=system_model, attacker_level="intermediate")
ag.generate_attack_graph(number_walks=25)
```

## 2. Progress Callback & Early Stop

```python
def on_progress(p):
    print(p)
    if p["completed_walks"] >= 5 and p["successful_walks"] >= 2:
        ag.request_stop()

ag = AttackGraph(threat_model=tm, system_model=system_model, progress_callback=on_progress)
ag.generate_attack_graph(number_walks=50)
```

## 3. Persist / Reload Statistics

```python
import json
with open("graph_stats.json", "w") as f:
    json.dump(ag.graph_statistics, f, indent=2)

ag2 = AttackGraph()
with open("graph_stats.json") as f:
    stats = json.load(f)
ag2.load_from_graph_statistics(stats)
```

## 4. Shortest Successful Path

```python
sp = ag.get_shortest_path()
for step in sp:
    print(step["technique"]["tactic"], "->", step["technique"]["technique"])
```

## 5. Impact Frequency Analysis

```python
impact_distribution = ag.get_graph_analysis()
for impact_type, pct in impact_distribution.items():
    print(f"{impact_type}: {pct:.2f}%")
```

## 6. Tips

!!! tip
    Use a deterministic random seed (e.g. `random.seed(1337)`) before `generate_attack_graph` if you need reproducibility for demos.

!!! warning
    Very large `number_walks` values can inflate runtime; prefer early stop criteria.
