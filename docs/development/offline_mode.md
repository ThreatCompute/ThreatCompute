# Offline Mode

ThreatCompute supports a deterministic offline mode to enable reproducible CI and local testing without external LLM calls.

Enable it by setting:
```bash
export TC_OFFLINE=1
```

### Behavior Changes
| Component | Online | Offline |
|-----------|--------|---------|
| Technique generation | LLM-derived | Fixed synthetic techniques |
| Vulnerability & misconfiguration summarizers | Natural language synthesis | Structured counts with placeholders |
| Asset categorization | Semantic grouping via model | Deterministic grouping heuristic |
| Threat model creator tactics | Prompt + parsing | Single canned tactic |

### Use Cases
- CI pipelines
- Air‑gapped environments
- Regression testing
