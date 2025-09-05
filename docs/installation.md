# Installation

```bash
git clone https://github.com/ThreatCompute/ThreatCompute.git
cd ThreatCompute/ThreatCompute
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Optional: LLM Provider Configuration
Export your API token (DeepInfra example):
```bash
export DEEPINFRA_API_TOKEN=your_token
```

## Verify
```bash
pytest -q
```
