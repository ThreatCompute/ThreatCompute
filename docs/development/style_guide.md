---
title: Code Style & Conventions
description: Project coding standards, linting and testing expectations.
tags:
  - contributing
  - style
---

# Code Style & Conventions

## Python

- Target Python 3.11+ (CI tests 3.10–3.13).
- Prefer explicit imports over wildcard.
- Guard optional heavy imports / external calls behind environment checks (`TC_OFFLINE`).

## Linting

Suggested tools:

```bash
pip install ruff black
ruff check .
black .
```

## Testing

- Add offline deterministic tests for new logic paths.
- Ensure coverage does not regress (threshold currently 60%).
- Prefer small synthetic graphs / fixtures.

## Docstrings

- Use concise imperative style.
- Public functions: single-line summary + important parameter notes.

## Commit Messages

Use Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, etc.) with `-s` sign-off.
