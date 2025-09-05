# Threat Modeling Pipeline

The pipeline loads a system model graph (GML), analyzes assets, categorizes containers, derives tactics, and generates techniques.

```python
from ThreatModeling.threat_model_creator import build_threat_model
result = build_threat_model("data/system_model_MYAPP_trivy.gml", application="MYAPP", write_results=False)
print(result.keys())  # dict: assets, tactics, techniques
```

## Output Structure (Simplified)
```json
{
  "assets": {"Container": {"categories": {"CatA": {"instances": [...]}}}},
  "tactics": {"Container": [{"tactic": "Initial Access", "description": "..."}]},
  "techniques": {"Container": {"CatA": {"Execution": [{"technique": "ExploitX", "target": "cluster"}]}}}
}
```

## Offline vs Online

| Mode | Trigger | Techniques | Summaries |
|------|---------|-----------|-----------|
| Online | Default (no `TC_OFFLINE`) | LLM generated | Natural language |
| Offline | `TC_OFFLINE=1` | Deterministic synthetic | Structured placeholders |

Set `TC_OFFLINE=1` in CI for reproducibility.

## Building Graph for Visualization

```python
from ThreatModeling import tm_graph
G = tm_graph.tmr_to_graph(result)
tm_graph.attack_paths(G)
```

