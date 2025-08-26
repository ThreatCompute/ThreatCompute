# Attack Graph Generation

Attack graphs are generated using the previously generated threat model and computed time-to-compromise values.

In simplified form, the generation process works as follows:

1. Starts at an Initial Access technique (entry point).
2. Uses random weighted sampling (TTC-based) to simulate attack paths.
3. Greedily walks through the threat model, selecting the next steps based on lower TTC.
4. Terminates upon reaching an Impact technique, exceeding step limits, or no further steps.
5. Successful paths are aggregated into the attack graph.

