<div align="center">

# ThreatCompute

Automated Threat Modeling & Attack Graph Generation for Kubernetes using LLM-assisted analysis and quantitative risk metrics.

[![CI](https://github.com/ThreatCompute/ThreatCompute/actions/workflows/ci.yaml/badge.svg)](https://github.com/ThreatCompute/ThreatCompute/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/ThreatCompute/ThreatCompute/branch/main/graph/badge.svg)](https://codecov.io/gh/ThreatCompute/ThreatCompute)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://threatcompute.github.io/ThreatCompute/)
[![Release](https://img.shields.io/github/v/release/ThreatCompute/ThreatCompute?display_name=tag&sort=semver)](https://github.com/ThreatCompute/ThreatCompute/releases/latest)

</div>

## 1. Overview
ThreatCompute automates core phases of security analysis for cloud‑native (Kubernetes) systems:

1. System Model Ingestion (graph of runtime & platform entities)
2. LLM-assisted Threat Modeling (tactics & techniques contextualized to the environment)
3. Time‑to‑Compromise (TTC) estimation from vulnerabilities & misconfigurations
4. Attack Graph Generation & Risk Exploration

It blends deterministic graph analytics with controlled LLM prompts (or a fully offline deterministic mode) to produce reproducible, explainable security artifacts.

## 2. Key Features
- MITRE ATT&CK & Kubernetes threat matrix alignment
- Offline deterministic mode (`TC_OFFLINE=1`) for CI / reproducibility (no LLM calls)
- Structured technique & tactic derivation pipeline
- Pluggable TTC computation for path scoring
- Attack path enumeration & exportable graphs (GML / PDF)

## 3. Repository Structure

```
ThreatModeling/         LLM-assisted (or offline) tactic & technique synthesis
TTCComputation/         Time-to-compromise calculations (vulns + misconfigurations)
AttackGraphGeneration/  Probabilistic attack path exploration & graph utilities
tests/                  Offline deterministic test suite
paper/                  Academic paper assets and figures
```

## 4. Installation

Clone and install dependencies (Python 3.11+ recommended; CI uses 3.13):

```bash
git clone https://github.com/ThreatCompute/ThreatCompute.git
cd ThreatCompute/ThreatCompute
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If you plan to run with a live LLM backend (DeepInfra), set:

```bash
export DEEPINFRA_API_TOKEN=your_token_here
```

## 5. Offline Deterministic Mode
To run without *any* LLM calls (ideal for CI, tests, restricted environments):

```bash
export TC_OFFLINE=1
pytest -q
```

In this mode, modules return synthetic yet structurally faithful outputs so pipelines remain testable.

## 6. Running Tests & Coverage

```bash
pytest --cov=ThreatModeling --cov=AttackGraphGeneration --cov=TTCComputation --cov-report=term-missing
```

The CI workflow (`.github/workflows/ci.yaml`) automatically:
1. Forces offline mode (`TC_OFFLINE=1`)
2. Runs the full suite
3. Uploads coverage to Codecov

## 7. Generating a Threat Model (Example)

```python
from ThreatModeling.threat_model_creator import build_threat_model

result = build_threat_model("data/system_model_MYAPP_trivy.gml", application="MYAPP", write_results=True)
print(result.keys())  # assets, tactics, techniques
```

To create a threat modeling graph file:

```python
from ThreatModeling import tm_graph
G = tm_graph.tmr_to_graph(result)
```

## 8. Attack Graph Generation (Conceptual)
1. Produce techniques & assets via `threat_model_creator`.
2. Compute TTC with `TTCComputation` module.
3. Feed into `AttackGraphGeneration.attackgraph` to explore weighted paths.

## 9. Extensibility
- Swap model provider in `ThreatModeling/model.py`.
- Add new TTC heuristics in `TTCComputation/system_ttc.py`.
- Extend graph analytics for prioritization.

## 10. Development
Recommended pre-commit style / linting (example):

```bash
pip install black ruff
black ThreatModeling AttackGraphGeneration TTCComputation
ruff check .
```

## 11. CI & Coverage Badges
Badges at the top reflect the status of the `main` branch. Coverage comes from deterministic offline execution.

## 12. Contributing
1. Fork & branch from `main`.
2. Enable offline mode for quick iteration.
3. Add tests for new logic (prefer deterministic paths).
4. Open a PR; ensure CI passes.

## 13. Roadmap (Selected)
- Additional risk scoring models (beyond TTC)
- Multi-cloud asset ontology support
- Visualization enhancements (attack path overlays)

## 14. Citation
If you use ThreatCompute in academic work, cite the accompanying paper in `paper/`.

## 15. License
See `LICENSE` and `COPYRIGHT` for maintainer and licensing details.

---
Feedback & issues welcome via GitHub Issues.
