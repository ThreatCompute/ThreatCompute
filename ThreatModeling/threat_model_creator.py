from typing import Annotated
from langchain_core.runnables import RunnableConfig
from typing_extensions import TypedDict
from langchain_community.llms import DeepInfra
from langgraph.graph import StateGraph
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_core.exceptions import OutputParserException
from langsmith import traceable
import networkx as nx
import json, yaml
import time
from technique_analysis import (
    vulnerabilties_summarizer,
    misconfigurations_summarizer,
    techniques_for_asset,
)
from asset_categorizer import asset_categorizer
from system_model import SystemModel, analyze_asset_instances, summarize_asset_analyses
from model import get_deepinfra_model
from matrices import K8S_MATRIX
import dotenv

dotenv.load_dotenv()

model = get_deepinfra_model()

# Define the assets that can be used in the system model and the order in which they are analyzed
assets = ["RootShell", "Shell", "Container", "Pod", "namespace", "cluster"]


def add_technique(original_techniques, new):
    """
    function to add a new technique to the techniques dictionary of the langraph state
    """
    if isinstance(new, dict):
        for key, value in new.items():
            if key in original_techniques:
                original_techniques[key] = original_techniques[key] | value
                return original_techniques
    updated_assets = original_techniques | new
    return updated_assets


def add_asset(original_assets, new):
    """
    adds a new asset or tactic to the original dictionary by merging the dictionaries of the langraph state
    """
    updated_assets = original_assets | new
    return updated_assets


class State(TypedDict):
    input: str
    assets: Annotated[dict, add_asset]
    tactics: Annotated[dict, add_asset]
    techniques: Annotated[dict, add_technique]
    system_model: SystemModel
    system_description: str
    asset_vulnerabilities: str
    asset_misconfigurations: str
    current_asset: int
    current_tactic: int


graph = StateGraph(State)


def load_system_model(state: State) -> dict:
    """
    Load system model from file and initialize the state
    """
    system_model = SystemModel(system_model_file=state["input"])
    assets_map = {}
    assets = set(
        [attributes["type"] for node, attributes in system_model.nodes(data=True)]
    )
    # state assets are initiliazed with assets from system model
    for asset in assets:
        assets_map[asset] = {
            "instances": [
                (
                    {"id": node, "name": attributes["name"]}
                    if "name" in attributes
                    else {"id": node, "name": attributes["namespace"]}
                )
                for node, attributes in system_model.nodes(data=True)
                if (attributes["type"] == asset)
            ]
        }
    initial_state = {
        "assets": assets_map,
        "system_model": system_model,
        "current_asset": 0,
        "current_tactic": 0,
        "system_description": "The system is a kubernetes application deploying a webpage.",
    }
    print(initial_state)
    return initial_state


@traceable
def system_analysis(state: State) -> dict:
    """
    Analyse each asset in the system in a hierarchical manner
    Include lower level analysis results in higher level analysis results
    Extend System Model with analysis results
    """
    system_model = state["system_model"]
    assets_map = state["assets"]
    predeccessor_asset = None
    for asset_type in assets:
        if asset_type not in assets_map:
            continue
        print(f"Summarizing the analyses of the asset {asset_type}")
        analyses = analyze_asset_instances(system_model, asset_type, predeccessor_asset)
        nx.set_node_attributes(system_model, analyses)
        if asset_type == "cluster":
            assets_map[asset_type]["description"] = analyses[0]["analysis"]
        else:
            # save instance analyses in the asset map
            for instance in assets_map[asset_type]["instances"]:
                instance_analysis = analyses[instance["id"]]
                instance["description"] = instance_analysis["analysis"]
            summary = summarize_asset_analyses(asset_type, analyses)
            assets_map[asset_type]["description"] = summary
        predeccessor_asset = asset_type
    return {"system_model": system_model, "assets": assets_map}


@traceable
def categorizer(state) -> dict:
    """
    Categorize containers in different categories and assign instances to these categories
    """
    asset = "Container"
    print("Categorizer for", state["current_asset"], asset)

    subgraph = state["system_model"].get_asset_subgraph(
        asset, unwanted_attributes=["CVEs"]
    )

    ## get container descriptions which were generated in the system analysis
    node_summaries = [
        {"node": attributes["name"], "description": attributes["analysis"]}
        for node, attributes in subgraph.nodes(data=True)
    ]

    ## Use container descriptions to categorize containers
    pruned_result = asset_categorizer(asset, subgraph, node_summaries)

    result_dict = {
        "description": state["assets"][asset]["description"],
        "categories": pruned_result,
    }

    return {"assets": {asset: result_dict}}


@traceable
def tactics_creation(state: State) -> dict:
    """
    Generate attack tactics for each asset in the system
    """
    if state["current_asset"] == len(state["assets"].keys()):
        # reset on first transition from categorizer
        state["current_asset"] = 0
    assets = list(state["assets"].keys())
    asset = assets[state["current_asset"]]
    tactics = list(
        K8S_MATRIX.keys()
    )  # list of tactics from the Threat Matrix for Kubernetes

    print("##### Tactics for", state["current_asset"], asset)
    prompt = PromptTemplate(
        template=(
            "You are a security expert threat modeling a Kubernetes Application. \n"
            "The goal is to make the application more secure by identifying possible threats. \n"
            "Analyse the security, possible misuse or exploitation of the asset {asset}. "
            "List tactics from the MITRE ATT&CK Matrix that can be performed on {asset} instances. Provide a short description, how this tactic can be performed. \n"
            "List of tactics: {tactics}. \n"
            "{asset} description: \n {asset_description}."
            "{format_instructions}"
            "Output only the JSON array. \n"
        ),
        input_variables=["asset", "asset_description"],
        partial_variables={
            "format_instructions": 'The list of tactics should be formatted as a JSON array. Add three backticks before and after the JSON and enclose property names with double quotes. Format: ```[{"tactic": "tactic_name", "description": "brief description of how this tactic could be exploited for the asset"}, {"tactic": "tactic_name", "description": "another brief description of how this tactic could be exploited for the asset"} // add as many items as needed for each tactic]```'
        },
    )
    try:
        result = (prompt | model | JsonOutputParser()).invoke(
            {
                "asset": asset,
                "asset_description": state["assets"][asset]["description"],
                "tactics": tactics,
            }
        )
    except OutputParserException:
        print("JSON Parsing Error occured")
        # In case of a JSON Parsing Error the answer should be regenerated (usually the output is parsable the second time)
        result = (prompt | model | JsonOutputParser()).invoke(
            {
                "asset": asset,
                "asset_description": state["assets"][asset]["description"],
                "tactics": tactics,
            }
        )

    if not result:
        # The JSONOutputParser sometimes returns None and does not raise an exception
        return {"tactics": {asset: {}}, "current_asset": state["current_asset"] + 1}

    result = list(
        filter(None, result)
    )  # filters out empty dictionaries in the list of tactics
    print(result)
    return {"tactics": {asset: result}, "current_asset": state["current_asset"] + 1}


def techniques_relationer(state) -> dict:
    """
    Generate attack techniques for each asset in the system
        1. Summarize vulnerabilities and misconfigurations for each asset
        2. Generate attack techniques for each asset based on the vulnerabilities and misconfigurations
    """
    techniques_result = {}
    asset_list = list(state["assets"].keys()) + list(
        state["assets"]["Container"]["categories"].keys()
    )
    for asset in state["assets"]:
        asset_description = state["assets"][asset]["description"]
        techniques_result[asset] = {}
        if asset == "Container":
            for subasset in state["assets"]["Container"]["categories"]:
                subasset_instance_names = [
                    instance["name"]
                    for instance in state["assets"]["Container"]["categories"][
                        subasset
                    ]["instances"]
                ]
                subasset_instance_ids = [
                    instance["id"]
                    for instance in state["assets"]["Container"]["categories"][
                        subasset
                    ]["instances"]
                ]
                print("#### Summarizing subasset", subasset, subasset_instance_names)
                vulnerabilities = vulnerabilties_summarizer(
                    subasset_instance_ids, state["system_model"]
                )
                misconfigurations = misconfigurations_summarizer(
                    subasset_instance_ids,
                    subasset_instance_names,
                    state["system_model"],
                )
                techniques_result[asset][subasset] = {}
                print("####### Techniques for", asset, subasset)
                # iterate over tactics for each asset -> ask for possible techniques for each tactic
                for tactic in state["tactics"][asset]:
                    asset_techniques = techniques_for_asset(
                        subasset,
                        asset_description,
                        state["system_description"],
                        vulnerabilities,
                        misconfigurations,
                        tactic["tactic"],
                        asset_list,
                        is_container=True,
                    )
                    print(asset_techniques)
                    techniques_result[asset][subasset][
                        tactic["tactic"]
                    ] = asset_techniques
        else:
            instance_ids = [
                instance["id"] for instance in state["assets"][asset]["instances"]
            ]
            instance_names = [
                instance["name"] for instance in state["assets"][asset]["instances"]
            ]
            print("#### Summarizing asset", asset, instance_ids)
            vulnerabilities = vulnerabilties_summarizer(
                instance_ids, state["system_model"]
            )
            misconfigurations = misconfigurations_summarizer(
                instance_ids, instance_names, state["system_model"]
            )
            print("####### Techniques for", asset)
            # iterate over tactics for each asset -> ask for possible techniques for each tactic
            for tactic in state["tactics"][asset]:
                asset_techniques = techniques_for_asset(
                    asset,
                    asset_description,
                    state["system_description"],
                    vulnerabilities,
                    misconfigurations,
                    tactic["tactic"],
                    asset_list,
                )
                print(asset_techniques)
                techniques_result[asset][tactic["tactic"]] = asset_techniques

    return {"techniques": techniques_result}


def should_continue_relating_tactics(state: State):
    if state["current_asset"] == len(state["assets"].keys()):
        return "Techniques_Creation"
    return "Tactics_Creation"


graph.add_node("System_Model_Loader", load_system_model)
graph.add_node("System_Analysis", system_analysis)
graph.add_node("Asset_Categorizer", categorizer)
graph.add_node("Tactics_Creation", tactics_creation)
graph.add_node("Techniques_Creation", techniques_relationer)
graph.set_entry_point("System_Model_Loader")
graph.add_edge("System_Model_Loader", "System_Analysis")
graph.add_edge("System_Analysis", "Asset_Categorizer")
graph.add_edge("Asset_Categorizer", "Tactics_Creation")
graph.set_finish_point("Techniques_Creation")
graph.add_conditional_edges("Tactics_Creation", should_continue_relating_tactics)
compiled = graph.compile()

application = "APPLICATION NAME"

step1 = compiled.invoke(
    {"input": f"data/system_model_{application}_trivy.gml"},
    config=RunnableConfig(recursion_limit=60),
)
timestr = time.strftime("%Y%m%d-%H%M%S")

with open("threatmodeling/parameters.yaml", "r") as f:
    parameters = yaml.safe_load(f)
with open(
    f"data/results/{application}/{parameters['deepinfra']['model_name']}_results_{timestr}.json",
    "w+",
) as f:
    json.dump(
        {
            "assets": step1["assets"],
            "tactics": step1["tactics"],
            "techniques": step1["techniques"],
        },
        f,
        indent=2,
    )
print("############# Tactics #############")
print(json.dumps(step1["tactics"], indent=2))
print("############# Assets #############")
print(json.dumps(step1["assets"], indent=2))
