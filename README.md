# ThreatCompute
ThreatCompute: Leveraging LLMs for Automated Threat Modeling of Cloud-Native Applications

## Overview
The increasing complexity of cloud-native applications has necessitated advanced methodologies for threat modeling and security analysis.
This paper presents ThreatCompute, a novel framework that combines Large Language Models (LLMs) with attack graphs to automate the generation of threat hypotheses and the quantification of risk in Kubernetes environments.
While traditional approaches to attack graph generation require significant manual effort from security experts, ThreatCompute leverages LLMs to extract security insights from system information - reducing reliance on manual intervention while maintaining high accuracy and generating context-specific, system-aware threat insights.
The framework utilizes the MITRE ATT&CK Matrix and the Microsoft Threat Matrix for Kubernetes as structured domains of possible attack techniques.
Based on LLM-generated threat hypotheses and a quantitative risk metric, ThreatCompute constructs detailed attack graphs that illustrate potential attack paths and assess their associated risks. This enables both qualitative and quantitative evaluations of application security across varying levels of granularity.

Through real-world examples of Kubernetes applications, we demonstrate the effectiveness of our approach in identifying and quantifying security risks.

## Repository Structure

The repository is organized into three main components, reflecting the stages of the ThreatCompute framework:

- **ThreatModeling/**  
  Generates the threat model using LLMs based on the provided system model.

- **TTCComputation/**  
  Computes time-to-compromise (TTC) values for Kubernetes components using vulnerability and misconfiguration information.

- **AttackGraphGeneration/**  
  Generates attack graphs by combining the LLM-generated threat model with the computed TTC values.
