import networkx as nx
import matplotlib.pyplot as plt
from langchain_core.prompts import PromptTemplate
from .model import get_deepinfra_model
import numpy as np


class SystemModel(nx.DiGraph):
    """
    SystemModel class to interact with the system model
    """

    def __init__(self, system_model_file=None) -> None:
        # Initialize the base class (nx.Graph)
        super().__init__()
        self.system_model_file = system_model_file
        # Read the graph from the file
        if system_model_file:
            gml_graph = nx.read_gml(
                system_model_file, destringizer=nx.readwrite.gml.literal_destringizer
            )
            # Update self to contain the nodes and edges from the read graph
            self.add_nodes_from(gml_graph.nodes(data=True))
            self.add_edges_from(gml_graph.edges(data=True))

    def get_vulnerabilities_by_instances(self, asset_name, instance_names) -> list:
        """
        Get vulnerabilities for a list of instances of a given asset
        """
        instances = [
            attributes
            for node, attributes in self.nodes(data=True)
            if (attributes.get("name") in instance_names)
            and (attributes["type"] == asset_name)
        ]
        vulnerabilities = []
        for instance in instances:
            if "CVEs" in instance:
                vulnerabilities = vulnerabilities + instance["CVEs"]
        return vulnerabilities

    def get_vulnerabilities_by_instance_ids(self, instance_ids) -> list:
        """
        Get vulnerabilities for a list of instance ids
        """
        vulnerabilities = []
        for instance_id in instance_ids:
            if "CVEs" in self.nodes[instance_id]:
                vulnerabilities = vulnerabilities + self.nodes[instance_id]["CVEs"]
        return vulnerabilities

    def get_misconfigurations_by_instances(self, instance_names) -> list:
        """
        Get misconfigurations for a list of instances
        """
        instances = [
            attributes
            for node, attributes in self.nodes(data=True)
            if attributes.get("name") in instance_names
        ]
        misconfigurations = []
        for instance in instances:
            if "CHECKS" in instance:
                misconfigurations = misconfigurations + instance["CHECKS"]
        return misconfigurations

    def get_misconfigurations_by_instance_ids(self, instance_ids) -> list:
        """
        Get misconfigurations for a list of instance ids
        """
        misconfigurations = []
        for instance_id in instance_ids:
            if "CHECKS" in self.nodes[instance_id]:
                misconfigurations = (
                    misconfigurations + self.nodes[instance_id]["CHECKS"]
                )
        return misconfigurations

    def get_asset_subgraph(
        self, asset: str, unwanted_attributes=None, wanted_attributes=None
    ) -> nx.Graph:
        """
        Get a subgraph containing only the nodes of a given asset type

        Args:
            asset (str): The asset type to get the subgraph for
            unwanted_attributes (list): List of attributes to remove from the nodes
            wanted_attributes (list): List of attributes to keep in the nodes

        Returns:
            nx.Graph: The subgraph containing only the nodes of the given asset type
        """
        relevant_nodes = [
            node
            for node, attributes in self.nodes(data=True)
            if attributes["type"] == asset
        ]
        subgraph = self.subgraph(relevant_nodes).copy()
        if unwanted_attributes:
            for node in subgraph.nodes():
                for attribute in unwanted_attributes:
                    subgraph.nodes[node].pop(attribute, None)

        return subgraph

    def get_instance_id(self, asset_name, instance_name):
        """
        Get the node id of an instance
        """
        instance_id = [
            node
            for node, attributes in self.nodes(data=True)
            if (attributes.get("name") == instance_name)
            and (attributes["type"] == asset_name)
        ]
        return instance_id[0] if instance_id else None

    def get_instance_name(self, instance_id):
        """
        Get the name of an instance
        """
        if self.nodes[instance_id].get("type") in ["cluster", "namespace"]:
            return self.nodes[instance_id].get("namespace")
        return self.nodes[instance_id].get("name")

    def draw_system_model(self):
        """
        Draw the system model graph
        """

        def x_scaling(x):
            x_position = x[0]
            y_position = x[1]
            return np.array([x_position * 10, y_position])

        # Define a color map for types
        asset_to_color = {
            "Container": "cyan",
            "namespace": "skyblue",
            "cluster": "yellowgreen",
            "RootShell": "violet",
            "Shell": "tomato",
            "Pod": "bisque",
        }

        # Assign a hierarchy level to each type
        type_to_level = {
            "cluster": 0,  # Top layer
            "namespace": 1,
            "Pod": 2,
            "Container": 3,
            "RootShell": 4,
            "Shell": 5,  # Bottom layer
        }

        types = nx.get_node_attributes(self, "type")
        node_colors = [asset_to_color[types[node]] for node in self.nodes()]

        # Define labels for nodes
        labels = {
            node: attributes.get("name", attributes.get("namespace", ""))
            for node, attributes in self.nodes(data=True)
        }

        # Define the order of categories for the multipartite layout
        subsets = {
            "cluster": [node for node in self.nodes() if types[node] == "cluster"],
            "namespace": [node for node in self.nodes() if types[node] == "namespace"],
            "Pod": [node for node in self.nodes() if types[node] == "Pod"],
            "Container": [node for node in self.nodes() if types[node] == "Container"],
            "RootShell": [node for node in self.nodes() if types[node] == "RootShell"],
            "Shell": [node for node in self.nodes() if types[node] == "Shell"],
        }
        pos = nx.multipartite_layout(
            self, subset_key=subsets, align="horizontal", scale=1
        )
        pos = {p: x_scaling(pos[p]) for p in pos}
        if pos[subsets["cluster"][0]][1] < pos[subsets["namespace"][0]][1]:
            # Swap the positions of the cluster and namespace nodes
            cluster_y = pos[subsets["cluster"][0]][1]
            namespace_y = pos[subsets["namespace"][0]][1]
            for node in subsets["cluster"]:
                pos[node] = (pos[node][0], namespace_y)
            for node in subsets["namespace"]:
                pos[node] = (pos[node][0], cluster_y)

        if pos[subsets["Container"][0]][1] < pos[subsets["RootShell"][0]][1]:
            # Swap the positions of the Container and Rootshell nodes
            container_y = pos[subsets["Container"][0]][1]
            rootshell_y = pos[subsets["RootShell"][0]][1]
            for node in subsets["Container"]:
                pos[node] = (pos[node][0], rootshell_y)
            for node in subsets["RootShell"]:
                pos[node] = (pos[node][0], container_y)

        if pos[subsets["Pod"][0]][1] < pos[subsets["Container"][0]][1]:
            # Swap the positions of the Pod and Container nodes
            pod_y = pos[subsets["Pod"][0]][1]
            container_y = pos[subsets["Container"][0]][1]
            for node in subsets["Pod"]:
                pos[node] = (pos[node][0], container_y)
            for node in subsets["Container"]:
                pos[node] = (pos[node][0], pod_y)

        if pos[subsets["Shell"][0]][1] > pos[subsets["Container"][0]][1]:
            diff_container_rootshell = (
                pos[subsets["Container"][0]][1] - pos[subsets["RootShell"][0]][1]
            )
            new_y = pos[subsets["RootShell"][0]][1] - diff_container_rootshell
            for node in subsets["Shell"]:
                pos[node] = (pos[node][0], new_y)

        plt.figure(figsize=(30, 20))
        nx.draw(self, pos=pos, node_color=node_colors, node_size=700, with_labels=False)

        # Rotate the node labels
        for label in labels:
            x, y = pos[label]
            plt.text(
                (x - 0.25), y, labels[label], fontsize=16, va="bottom", rotation=45
            )

        # Create legend
        handles = [
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor=color,
                markersize=30,
                label=type_name,
            )
            for type_name, color in asset_to_color.items()
        ]
        plt.legend(
            handles=handles, title="Node Types", title_fontsize="28", fontsize="24"
        )
        plt.savefig(f"{self.system_model_file}.pdf")


def analyze_asset_instances(
    system_model: SystemModel, asset_type, successor_asset_type=None
):
    """
    Analyze asset instances in the system model and add summary to the asset instance
    """
    model = get_deepinfra_model()
    relevant_nodes = [
        (node, attributes)
        for node, attributes in system_model.nodes(data=True)
        if attributes["type"] == asset_type
    ]
    analysis_results = {}
    for node_id, node_attributes in relevant_nodes:
        try:
            successors = list(system_model.successors(node_id))
        except nx.NetworkXError:
            successors = []

        attributes = node_attributes.copy()

        # Get the 'analysis' attribute for each node in node_ids
        analysis_attributes = nx.get_node_attributes(system_model, "analysis")
        analyses = [
            analysis_attributes[node_id]
            for node_id in successors
            if node_id in analysis_attributes
        ]

        attributes.pop("CVEs", None)
        attributes.pop("CHECKS", None)
        # Analyse the asset instance and include the analysis of the successors in the summary
        if analyses:
            if asset_type == "Container":
                prompt = f"You are a security expert threat modeling a Kubernetes Application. You are provided with the attributes of a Kubernetes {asset_type}. {asset_type} attributes: {attributes} \n The {asset_type} contains instances {successor_asset_type} which were analyzed as follows: {analyses} \n. Analyze the {asset_type} and its SBOM.  Describe the {asset_type} and its possible use in 3 sentences. Only output this description.\n {asset_type} description:"
            else:
                prompt = f"You are a security expert threat modeling a Kubernetes Application. You are provided with the attributes of a {asset_type}. {asset_type} attributes: {attributes} \n The {asset_type} contains instances {successor_asset_type} which were analyzed as follows: {analyses} \n. Describe the {asset_type} and its possible use in 3 sentences. Only output this description. \n {asset_type} description:"
        else:
            prompt = f"You are a security expert threat modeling a Kubernetes Application. You are provided with the attributes of a {asset_type}. {asset_type} attributes: {attributes} \n  Describe the {asset_type} and its possible use in one sentence. Only output this description. \n {asset_type} description: \n"

        instance_analysis = model.invoke(prompt)
        print(instance_analysis)
        analysis_results[node_id] = {"analysis": instance_analysis}

    return analysis_results


def summarize_asset_analyses(asset, analyses):
    """
    Summarize the analyses of an asset
    """
    model = get_deepinfra_model()
    prompt = PromptTemplate(
        template=(
            "You are a security expert performing threat modeling for a Kubernetes application. "
            "Based on the provided analyses of the {asset}s, summarize the overall security risks and characteristics of the Kubernetes application in five sentences. "
            "Focus on key themes such as the use of privileged containers, access to the Kubernetes API, vulnerable configurations, and the intended purpose of these {asset}s (e.g., testing, administration, or production). "
            "Avoid listing details about individual containers and instead identify overarching patterns and their implications for the cluster's security posture."
            "Analyses: {analyses}. \nConcise summary of {asset}s in the cluster: \n"
        ),
        input_variables=["asset", "analyses"],
    )
    summary = (prompt | model).invoke({"asset": asset, "analyses": analyses})
    return summary
