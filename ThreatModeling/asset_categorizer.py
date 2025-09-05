from langchain_core.output_parsers import JsonOutputParser, PydanticOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_core.exceptions import OutputParserException
from langchain_community.llms import Ollama
import networkx as nx
import difflib
import yaml
from pydantic import BaseModel, Field
from typing import List, Dict
import os
from .model import get_deepinfra_model

model = None
if os.getenv("TC_OFFLINE") != "1":
    try:
        model = get_deepinfra_model()
    except Exception:
        model = None


class Category(BaseModel):
    description: str = Field(description="Brief description of the asset category")
    instances: List[str]


class Categories(BaseModel):
    categories: Dict[str, Category]


# Set up a parser + inject instructions into the prompt template.
parser = JsonOutputParser(pydantic_object=Categories)

categorizer_prompt = PromptTemplate(
    template=(
        "You are a security expert threat modeling a Kubernetes Application. \n"
        "You already identified the general asset: {asset}. \n"
        "Here are all the instances of this asset: {system_model}"
        "Categorize the instances of {asset} and assign each instance to exactly one category. Example categories can be 'Application Container', 'Networking', 'Storage Container' or 'Health Probe'.\n"
        "Provide a map of these categories to the instances names in the following JSON format. Include a short description of each subcategory. \n {format_instructions}"
    ),
    input_variables=["system_model", "asset"],
    partial_variables={
        "format_instructions": 'Add three backticks before and after the JSON and don\'t add additional text before the JSON. Enclose property names in double quotes. Format: ```{"categories": {"category_name": {"description": \'description of the category\', "instances": [\'instance name as string\', \'instance name 2\']}}}``` \n'
    },
)

categorizer_chain = None
if model is not None:
    try:
        categorizer_chain = categorizer_prompt | model | parser
    except Exception:
        categorizer_chain = None


def instance_describer(system_graph):
    """
    Takes a set of container as input and generates a description for each container
    """
    node_summaries = []
    for node, attributes in system_graph.nodes(data=True):
        if os.getenv("TC_OFFLINE") == "1":
            description = f"offline desc for {attributes.get('name','inst')}"
        else:
            description = model.invoke(
                f"You are a security expert threat modeling a Kubernetes Application. You are provided with the attributes of a Container. Container attributes: {attributes} \n Analyze the container and its SBOM. Provide a 3 sentence description of the container and what is might be responsible for. \n Container description:"
            ) if model is not None else "offline desc"
        node_summaries.append({"node": attributes.get("name"), "description": description})
    return node_summaries


def asset_categorizer(asset, system_graph, node_summaries):
    """
    Takes a set of asset descriptions and categorizes them into different categories
    """
    ## Use container descriptions to categorize containers
    if os.getenv("TC_OFFLINE") == "1":
        # Deterministic simple grouping by first letter
        cats = {}
        for summary in node_summaries:
            name = summary["node"]
            if not name:
                continue
            key = name[0].upper()
            cats.setdefault(key, {"description": f"offline cat {key}", "instances": []})
            cats[key]["instances"].append(name)
        result = {"categories": {k: {"description": v["description"], "instances": v["instances"]} for k, v in cats.items()}}
    else:
        try:
            if categorizer_chain is None:
                return {}
            result = categorizer_chain.invoke(
                {"asset": asset, "system_model": node_summaries}
            )
        except OutputParserException:
            if categorizer_chain is None:
                return {}
            result = categorizer_chain.invoke(
                {"asset": asset, "system_model": node_summaries}
            )

    ## Discarding empty categories and wrong instances
    relevant_instances_names = [
        attributes["name"] if "name" in attributes else attributes["namespace"]
        for node, attributes in system_graph.nodes(data=True)
    ]
    relevant_instances_data = [
        {"id": node, "analysis": attributes["analysis"]}
        for node, attributes in system_graph.nodes(data=True)
    ]
    pruned_result = {}
    if not result:
        return {}
    result = result["categories"]
    for category in result:
        print("category", category)
        if not all(
            e in relevant_instances_names for e in result[category]["instances"]
        ):
            # sometimes the instance names are not completly correct -> match to closest match
            for instance in [
                e
                for e in result[category]["instances"]
                if e not in relevant_instances_names
            ]:
                close_matches = difflib.get_close_matches(
                    instance, relevant_instances_names, cutoff=0.8
                )
                print("Wrong instance name ", instance, close_matches)
                result[category]["instances"].remove(instance)
                if close_matches:
                    result[category]["instances"].append(close_matches[0])
        if result[category]["instances"]:
            instances = [
                {
                    "id": relevant_instances_data[
                        relevant_instances_names.index(instance)
                    ]["id"],
                    "name": instance,
                    "description": relevant_instances_data[
                        relevant_instances_names.index(instance)
                    ]["analysis"],
                }
                for instance in result[category]["instances"]
            ]
            pruned_result[category] = {
                "description": result[category],
                "instances": instances,
            }
        else:
            print("Pruned")
    diff = list(
        set(relevant_instances_names)
        - set(
            [
                instance["name"]
                for pruned_category in pruned_result
                for instance in pruned_result[pruned_category]["instances"]
            ]
        )
    )
    if diff:
        diffed_instances = [
            {
                "id": relevant_instances_data[relevant_instances_names.index(instance)][
                    "id"
                ],
                "name": instance,
                "description": relevant_instances_data[
                    relevant_instances_names.index(instance)
                ]["analysis"],
            }
            for instance in diff
        ]
        print("not categorized elements", diff)
        pruned_result["General Containers"] = {
            "description": "General Containers that were not assigned to a specific category.",
            "instances": diffed_instances,
        }
    return pruned_result


def categorizer(state) -> dict:
    """
    Categorize containers in different categories and assign instances to these categories
    """
    asset = "Container"
    print("Categorizer for", state["current_asset"], asset)
    relevant_nodes = [
        node
        for node, attributes in state["system_model"].nodes(data=True)
        if attributes["type"] == asset
    ]

    subgraph = state["system_model"].subgraph(relevant_nodes).copy()
    for node in subgraph.nodes():
        # remove CVEs from nodes because they are not relevant for categorization
        if "CVEs" in subgraph.nodes[node]:
            del subgraph.nodes[node]["CVEs"]
        # remove CHECKS from nodes because they are not relevant for categorization
        if "CHECKS" in subgraph.nodes[node]:
            del subgraph.nodes[node]["CHECKS"]

    ## First create a description of each node based on the attributes
    print("### Container Descriptions")
    node_summaries = instance_describer(subgraph)

    ## Use container descriptions to categorize containers
    pruned_result = asset_categorizer(asset, subgraph, node_summaries)
    return {"assets": {asset: pruned_result}}
