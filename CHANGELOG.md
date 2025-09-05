# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog (https://keepachangelog.com/en/1.0.0/) and this project adheres (from v0.1.0 onward) to Semantic Versioning (https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-09-05
### Added
- Initial public baseline with automated threat modeling, attack graph generation, and TTC computation pipeline.
- Offline deterministic mode (`TC_OFFLINE`) enabling testable runs without external LLM calls.
- Comprehensive pytest suite with coverage gating and multi-version CI matrix.
- MkDocs documentation site (Material theme) with usage guides, advanced attack graph and TTC details, style guide, and contributing guidelines.
- CODEOWNERS file establishing maintainer review flow.

### Changed
- Refactored threat model creation and technique analysis for lazy model loading & offline safety.
- Improved attack graph generation (progress callbacks, early stop, defensive guards).
- Simplified hierarchical TTC propagation logic.
- Enhanced README with badges (CI, Docs) and offline mode explanation.
- Updated LICENSE with multi-maintainer attribution and added COPYRIGHT file.

### Fixed
- CI ModuleNotFoundError resolved by exporting PYTHONPATH.
- mkdocs.yml markdown_extensions configuration indentation issues causing build failures.
- Attack path edge key mismatch (pluralization of 'techniques').

### Security
- Deterministic offline mode mitigates accidental external API/model calls during tests.

### Tooling / CI
- Split documentation deployment into dedicated `docs.yaml` GitHub Pages workflow.

[0.1.0]: https://github.com/ThreatCompute/ThreatCompute/releases/tag/v0.1.0
