# Attack Graph Generation

Attack graphs combine the synthesized threat model with TTC metrics to explore feasible attack paths.

Typical steps:
1. Build threat model (assets + tactics + techniques)
2. Compute TTC values for nodes
3. Feed into attack graph walker to enumerate or sample paths

Key module: `AttackGraphGeneration/attackgraph.py`.
