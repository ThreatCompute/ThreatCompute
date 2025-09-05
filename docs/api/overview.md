# API Overview

High-level modules:
- `ThreatModeling.threat_model_creator.build_threat_model` – orchestrates full threat modeling pipeline.
- `ThreatModeling.tm_graph.tmr_to_graph` – converts threat model result dict into a NetworkX DiGraph.
- `AttackGraphGeneration.attackgraph` – builds and explores attack graphs.
- `TTCComputation.system_ttc` / `kube_ttc` – TTC aggregation and per-component estimators.

Offline mode surfaces through environment variable `TC_OFFLINE` and short-circuits LLM calls.

## Module Map

| Area | File | Purpose |
|------|------|---------|
| Threat modeling orchestration | `ThreatModeling/threat_model_creator.py` | Stateful pipeline graph |
| Technique analysis | `ThreatModeling/technique_analysis.py` | Technique generation / summarization |
| Asset categorization | `ThreatModeling/asset_categorizer.py` | Deterministic or LLM-based grouping |
| System model | `ThreatModeling/system_model.py` | Graph wrapper helpers & drawing |
| Attack graph | `AttackGraphGeneration/attackgraph.py` | Stochastic walks & statistics |
| TTC core | `TTCComputation/kube_ttc.py` | Per-node TTC math |
| TTC aggregation | `TTCComputation/system_ttc.py` | Hierarchical TTC propagation |

## Extension Points

- Replace LLM provider: adjust `get_deepinfra_model()` implementation.
- Add tactic filtering: post-process `tactics` dict before technique expansion.
- Extend TTC weighting: subclass `KUBE_TTC` with alternative formulas.

