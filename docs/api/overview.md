# API Overview

High-level modules:
- `ThreatModeling.threat_model_creator.build_threat_model` – orchestrates full threat modeling pipeline.
- `ThreatModeling.tm_graph.tmr_to_graph` – converts threat model result dict into a NetworkX DiGraph.
- `AttackGraphGeneration.attackgraph` – builds and explores attack graphs.
- `TTCComputation.system_ttc` / `kube_ttc` – TTC aggregation and per-component estimators.

Offline mode surfaces through environment variable `TC_OFFLINE` and short-circuits LLM calls.
