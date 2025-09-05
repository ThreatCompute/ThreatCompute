import os
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_core.exceptions import OutputParserException
from langchain_community.llms import Ollama
from .matrices import K8S_MATRIX
from .model import get_deepinfra_model

# Lazy-load the LLM so importing this module (e.g. for verify_techniques tests)
# does not immediately require external API credentials or network access.
_MODEL = None


def get_model_cached():
    global _MODEL
    if _MODEL is None and os.getenv("TC_OFFLINE") != "1":
        _MODEL = get_deepinfra_model()
    return _MODEL

format_instructions = 'The list of techniques should be formatted as a JSON array. Add three backticks before and after the JSON and enclose property names with double quotes. Format: ```json[{"technique": "Technique Name from Microsoft Threat Matrix", "description": "Description of the technique tailored to this asset.", "target": "Target Asset from the given list", "requirement": "required attack tactic"}, {"technique": "Another Technique", "description": "Another description for the technique.", "target": "Another Target Asset", "requirement": "required attack tactic"}]```'

general_techniques_prompt = PromptTemplate(
    template=(
        "You are a security expert creating a Kubernetes threat model based on the Microsoft Threat Matrix for Kubernetes. "
        "Your focus is on `{asset}` instances within the cluster, described as follows: `{asset_description}`. "
        "The system scan results for vulnerabilities and misconfigurations are summarized below:\n"
        "- Vulnerabilities found: `{asset_vulnerabilities}`\n"
        "- Misconfigurations identified: `{asset_misconfigurations}`\n\n"
        "Identify techniques that could be used to achieve the tactic '{tactic}' on the '{asset}'. For each technique, provide:\n"
        "- The technique name (from the Microsoft Threat Matrix for Kubernetes)\n"
        "- A brief description of how the technique can be executed on the {asset}\n"
        "- The target asset, which can be either the {asset} itself ('self') or another asset from the list below\n"
        "- The prerequisite tactic that must have been executed in previous attack steps "
        "(options: 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Impact')\n\n"
        "Reference Lists:\n"
        "- Techniques related to the tactic '{tactic}': {techniques_list}\n"
        "- Target assets in the environment: {assets_list}\n\n"
        "{format_instructions}\n"
        "Provide the response as a JSON array:\n"
    ),
    input_variables=[
        "asset",
        "asset_description",
        "system_scan_vulnerabilities",
        "system_scan_misconfigurations",
        "tactic",
        "techniques_list",
        "assets_list",
    ],
    partial_variables={"format_instructions": format_instructions},
)


techniques_prompt_no_vul_no_misconf = PromptTemplate(
    template=(
        "You are a security expert developing a Kubernetes threat model based on the Microsoft Threat Matrix for Kubernetes. "
        "Focus on `{asset}` instances in the cluster, described as: `{asset_description}`. "
        "The system scan revealed no vulnerabilities or misconfigurations. \n\n"
        "Identify techniques that could be used to achieve the tactic '{tactic}' on the '{asset}'. For each technique, provide:\n"
        "- The technique name (from the Microsoft Threat Matrix for Kubernetes)\n"
        "- A brief explanation of how the technique can be executed on the '{asset}'\n"
        "- The target asset, which can be 'self' (indicating the current {asset}) or another asset from the list below\n"
        "- The prerequisite tactic that must have been executed prior (options: 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Impact')\n\n"
        "Reference Lists:\n"
        "- Techniques for the tactic '{tactic}': {techniques_list}\n"
        "- Target assets: {assets_list}\n\n"
        "{format_instructions}\n"
        "Provide the response as a JSON array:\n"
    ),
    input_variables=[
        "asset",
        "asset_description",
        "tactic",
        "techniques_list",
        "assets_list",
    ],
    partial_variables={"format_instructions": format_instructions},
)

container_techniques_prompt = PromptTemplate(
    template=(
        "You are a security expert developing a Kubernetes threat model based on the Microsoft Threat Matrix for Kubernetes. "
        "Focus on containers categorized as `{asset}`, described as: `{asset_description}`. "
        "The system was scanned for vulnerabilities and misconfigurations: \n"
        "- Vulnerabilities: `{asset_vulnerabilities}` \n"
        "- Misconfigurations: `{asset_misconfigurations}` \n\n"
        "Your task is to identify techniques attackers could use to achieve the tactic '{tactic}' on the '{asset}'. For each technique, include:\n"
        "- The technique name (from the Microsoft Threat Matrix for Kubernetes)\n"
        "- A brief description of how the technique can be executed on the container '{asset}'\n"
        "- The target asset, which should be either 'self' (indicating the current container) or another asset from the list provided below\n"
        "- The prerequisite tactic that must have been executed previously (options: 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Impact')\n\n"
        "Reference Lists:\n"
        "- Techniques for the tactic '{tactic}': {techniques_list}\n"
        "- Target assets: {assets_list}\n\n"
        "{format_instructions}\n"
        "Provide the response as a JSON array:\n"
    ),
    input_variables=[
        "asset",
        "asset_description",
        "asset_vulnerabilities",
        "asset_misconfigurations",
        "tactic",
        "techniques_list",
        "assets_list",
    ],
    partial_variables={"format_instructions": format_instructions},
)

format_instructions_initial_access = 'The list of techniques should be formatted as a JSON array. Add three backticks before and after the JSON and enclose property names with double quotes. Format: ```json[{"technique": "Technique Name from Microsoft Threat Matrix", "description": "Description of the technique tailored to this asset."}, {"technique": "Another Technique", "description": "Another description for the technique."}]```'

initial_access_technique_prompt = PromptTemplate(
    template=(
        "You are a security expert developing a Kubernetes threat model based on the Microsoft Threat Matrix for Kubernetes. "
        "Focus on containers categorized as `{asset}`, described as: `{asset_description}`. "
        "The system was scanned for vulnerabilities and misconfigurations: \n"
        "- Vulnerabilities: `{asset_vulnerabilities}` \n"
        "- Misconfigurations: `{asset_misconfigurations}` \n\n"
        "Your task is to identify techniques attackers could use to gain Initial Access to a '{asset}' in the cluster. For each technique, include:\n"
        "- The technique name (from the Microsoft Threat Matrix for Kubernetes)\n"
        "- A brief description of how the technique can be executed on the container '{asset}'\n"
        "Reference List of techniques for '{tactic}': {techniques_list}\n"
        "{format_instructions}\n"
        "Provide the response as a JSON array:\n"
    ),
    input_variables=[
        "asset",
        "asset_description",
        "asset_vulnerabilities",
        "asset_misconfigurations",
        "tactic",
        "techniques_list",
        "assets_list",
    ],
    partial_variables={"format_instructions": format_instructions_initial_access},
)


def verify_techniques(result, technique_list, asset_list, tactic):
    """
    Check if the technique name, target asset and prerequisite tactic are correct
    """
    asset_list = [asset.lower() for asset in asset_list] + ["self"]
    technique_list = [technique.lower() for technique in technique_list]
    verified_result = []
    for technique in result:
        technique_correct = True
        asset_correct = True
        prerquisite_tactic_correct = True
        if technique["technique"].lower() not in technique_list:
            technique_correct = False
        if technique["target"].lower() not in asset_list:
            asset_correct = False
        if (
            technique["requirement"] not in K8S_MATRIX
            and technique["requirement"] != None
        ):
            prerquisite_tactic_correct = False
        if technique_correct and asset_correct and prerquisite_tactic_correct:
            verified_result.append(technique)
            continue
        else:
            if not technique_correct and not asset_correct:
                print(
                    "Technique and asset not in list:",
                    technique["technique"],
                    technique["target"],
                )
            elif not asset_correct:
                print("Asset not in list:", technique["target"])
            elif not technique_correct:
                print("Technique not in list:", technique["technique"])
            elif not prerquisite_tactic_correct:
                print("Prerequisite tactic not in list:", technique["requirement"])
    return verified_result


def techniques_for_asset(
    asset,
    asset_description,
    system_description,
    asset_vulnerabilities,
    asset_misconfigurations,
    tactic,
    assets_list,
    is_container=False,
):
    """
    Create a list of techniques for a given asset and tactic
    """

    if tactic in K8S_MATRIX:
        techniques_list = K8S_MATRIX[tactic]
    else:
        techniques_list = []

    def technique_invocation():
        # Offline deterministic path for tests (skips LLM + parsing chains)
        if os.getenv("TC_OFFLINE") == "1":
            base_tech = techniques_list[0] if techniques_list else "Exposed sensitive interfaces"
            if tactic == "Initial Access":
                return [
                    {
                        "technique": base_tech,
                        "description": "offline initial access",
                        "target": "self",
                        "requirement": None,
                    }
                ]
            if (
                asset_vulnerabilities == "No vulnerabilities found."
                and asset_misconfigurations == "No misconfigurations found."
            ):
                return [
                    {
                        "technique": base_tech,
                        "description": "offline no vul misconf",
                        "target": assets_list[0] if assets_list else "self",
                        "requirement": "Initial Access",
                    }
                ]
            # General or container path
            extra = techniques_list[1] if len(techniques_list) > 1 else base_tech
            return [
                {
                    "technique": base_tech,
                    "description": "offline general technique",
                    "target": "self",
                    "requirement": "Initial Access",
                },
                {
                    "technique": extra,
                    "description": "offline extra technique",
                    "target": assets_list[0] if assets_list else "self",
                    "requirement": "Execution",
                },
            ]
        if tactic == "Initial Access":
            try:
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (initial_access_technique_prompt | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "asset_vulnerabilities": asset_vulnerabilities,
                        "asset_misconfigurations": asset_misconfigurations,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            except OutputParserException:
                print("JSON Parsing Error occured")
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (initial_access_technique_prompt | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "asset_vulnerabilities": asset_vulnerabilities,
                        "asset_misconfigurations": asset_misconfigurations,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            for technique in result:
                technique["requirement"] = None
                technique["target"] = "self"
            return result
        if (
            asset_vulnerabilities == "No vulnerabilities found."
            and asset_misconfigurations == "No misconfigurations found."
        ):
            try:
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (techniques_prompt_no_vul_no_misconf | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "system_summary": system_description,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            except OutputParserException:
                print("JSON Parsing Error occured")
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (techniques_prompt_no_vul_no_misconf | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "system_summary": system_description,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            return result
        else:
            if is_container:
                prompt = container_techniques_prompt
            else:
                prompt = general_techniques_prompt
            try:
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (prompt | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "system_summary": system_description,
                        "asset_vulnerabilities": asset_vulnerabilities,
                        "asset_misconfigurations": asset_misconfigurations,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            except OutputParserException:
                print("JSON Parsing Error occured")
                model_obj = get_model_cached()
                if model_obj is None:
                    return []
                result = (prompt | model_obj | JsonOutputParser()).invoke(
                    {
                        "asset": asset,
                        "asset_description": asset_description,
                        "system_summary": system_description,
                        "asset_vulnerabilities": asset_vulnerabilities,
                        "asset_misconfigurations": asset_misconfigurations,
                        "tactic": tactic,
                        "techniques_list": techniques_list,
                        "assets_list": assets_list,
                    }
                )
            return result

    result = technique_invocation()
    verified_result = verify_techniques(result, techniques_list, assets_list, tactic)
    if not verified_result:
        print("No verified techniques found")
        result = technique_invocation()
        verified_result = verify_techniques(
            result, techniques_list, assets_list, tactic
        )
    if not verified_result:
        return []

    return verified_result


def vulnerabilties_summarizer(instance_ids, system_model):
    """
    Summarize list of vulnerabilities for a list of given asset instances
    inspired by Map reduce approach: https://python.langchain.com/v0.2/docs/tutorials/summarization/

    First a summary of all the vulnerabilties of one package is created. After that the summaries are combined to a final summary.
    -> Map and reduce where mapping is done via the package name.
    """
    if os.getenv("TC_OFFLINE") == "1":  # deterministic offline summary
        vulns = system_model.get_vulnerabilities_by_instance_ids(instance_ids)
        if not vulns:
            return "No vulnerabilities found."
        return {
            "total_vulnerabilities": len(vulns),
            "vulnerability_types": ["RCE"],
            # Offline synthetic CVE entries may just be strings
            "affected_packages": list({(v.get("resource") if isinstance(v, dict) else str(v)) for v in vulns}),
            "overall_impact": "offline summary",
        }

    vulnerabilities = system_model.get_vulnerabilities_by_instance_ids(instance_ids)
    if not vulnerabilities:
        print("No vulnerabilities found")
        return "No vulnerabilities found."
    grouped_vulnerabilities = {}
    for vulnerability in vulnerabilities:
        package = vulnerability["resource"]
        if package not in grouped_vulnerabilities:
            grouped_vulnerabilities[package] = []
        grouped_vulnerabilities[package].append(vulnerability["title"])

    for package in grouped_vulnerabilities:
        vul_string = "\n".join(grouped_vulnerabilities[package])
        if len(vul_string) > 500:
            summarized_vulnerabilities = []
            for vulnerability in grouped_vulnerabilities[package]:
                summarized_vulnerabilities.append(vulnerability)
            vul_string = "\n".join(summarized_vulnerabilities)
    print("Number of vulnerability groups:", len(grouped_vulnerabilities))
    print("Groups:", list(grouped_vulnerabilities.keys()))

    summarize_package_prompt = PromptTemplate(
        template=(
            "You are a security expert threat modeling a Kubernetes Application. \n"
            "The application uses the package {package}, which has the following vulnerabilities. \n"
            "Vulnerabilities: \n {vulnerabilities} \n \n"
            "Summarize the vulnerabilities of the package in at most 5 sentences and describe the impact on the security of the application."
            "Summary: "
        ),
        input_variables=["package", "vulnerabilities"],
    )

    model_obj = get_model_cached()
    if model_obj is None:
        return []
    summarize_package_chain = summarize_package_prompt | model_obj
    package_summaries = []
    for package, vulnerabilities in grouped_vulnerabilities.items():
        summary = summarize_package_chain.invoke(
            {"package": package, "vulnerabilities": vulnerabilities}
        )
        package_summaries.append(summary)

    summarizer_prompt = PromptTemplate(
        template=(
            "You are a security expert performing threat modeling for a Kubernetes application. "
            "You have summarized the vulnerabilities of the packages as follows:\n\n"
            "{summaries}\n\n"
            "Your task is to condense these summaries into a brief and structured final summary. "
            "The output must be formatted as a JSON object for automatic security analysis. "
            "The JSON object should include the following fields:\n\n"
            "1. **total_vulnerabilities**: The total number of vulnerabilities.\n"
            "2. **vulnerability_types**: A list of distinct types of vulnerabilities (e.g., 'DoS', 'RCE').\n"
            "3. **affected_packages**: A list of affected packages.\n"
            "4. **overall_impact**: A brief description of the overall risk posed by these vulnerabilities.\n"
            "Keep the summary concise and high-level, suitable for quick review and further automation."
        ),
        input_variables=["summaries"],
    )

    model_obj = get_model_cached()
    if model_obj is None:
        return {}
    summarizer_chain = summarizer_prompt | model_obj | JsonOutputParser()
    result = summarizer_chain.invoke({"summaries": package_summaries})
    return result


def misconfigurations_summarizer(instance_ids, instance_names, system_model):
    """
    Summarize list of misconfigurations for a given asset instance
    """
    if os.getenv("TC_OFFLINE") == "1":
        mis = system_model.get_misconfigurations_by_instance_ids(instance_ids)
        if not mis:
            return "No misconfigurations found."
        return f"{len(mis)} misconfigurations offline summary"
    misconfigurations = system_model.get_misconfigurations_by_instance_ids(instance_ids)
    if not misconfigurations:
        return "No misconfigurations found."
    print("Number of misconfigurations:", len(misconfigurations))
    misconfigurations_summary_prompt = PromptTemplate(
        template=(
            "You are a security expert threat modeling a Kubernetes Application. \n"
            "Summarize the misconfigurations of the asset instances {asset_instance}."
            "Misconfigurations: \n {misconfigurations}"
            "The summary should describe different types of misconfigurations and their impact on the security of the application."
            "Summary: "
        ),
        input_variables=["asset_instance", "misconfigurations"],
    )

    model_obj = get_model_cached()
    if model_obj is None:
        return "No misconfigurations found."
    misconfigurations_summary_chain = misconfigurations_summary_prompt | model_obj
    misconfigurations_summary = misconfigurations_summary_chain.invoke(
        {"asset_instance": instance_names, "misconfigurations": misconfigurations}
    )
    return misconfigurations_summary
