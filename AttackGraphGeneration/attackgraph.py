import networkx as nx
import random
import matplotlib.pyplot as plt
import sys
import os
import json
import numpy as np

# Add the parent directory to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from ThreatModeling.system_model import SystemModel
from TTCComputation.system_ttc import calc_system_ttcs


class AttackGraph(nx.DiGraph):
    def __init__(
        self,
        threat_model: nx.DiGraph = None,
        system_model=None,
        attacker_level="novice",
        max_repititions=2,
    ):
        super(AttackGraph, self).__init__()
        self.threat_model = threat_model
        self.system_model: SystemModel = system_model
        self.attacker_level = attacker_level
        self.max_repititions = max_repititions
        if system_model is not None:
            self.ttc_dict = calc_system_ttcs(system_model, self.attacker_level)
        self.graph_statistics = {}
        self.graph_statistics["parameters"] = {}
        self.graph_statistics["parameters"][
            "attacker_skill_level"
        ] = self.attacker_level
        self.graph_statistics["walks"] = []
        self.walk_tactics = []

    def load_from_graph_statistics(self, graph_statistics):
        """ "
        Load attack graph from graph statistics
        """
        self.graph_statistics = graph_statistics
        for walk in graph_statistics["walks"]:
            if walk["successfull"]:
                self.add_walk_to_attack_graph(walk["attack_steps"])

    def generate_attack_graph(self, number_walks=60):
        """
        Generate attack graph by walking through the threat model multiple times

        Arguments:
        number_walks: number of walks through the graph to create the attack graph
        """
        for i in range(number_walks):
            print("########################################################")
            print("Walk: ", i)
            self.graph_statistics["walks"].append({})
            self.graph_statistics["walks"][i]["unique_step_counts"] = {}
            walk = self.generate_walk(walk_counter=i)
            if self.is_successfull_walk(walk):
                print("Successfull Walk")
                self.add_walk_to_attack_graph(walk)
                walk_ttc = self.get_path_ttc_sum(walk)
                self.graph_statistics["walks"][i]["attack_steps"] = walk
                self.graph_statistics["walks"][i]["successfull"] = True
                self.graph_statistics["walks"][i]["TTC"] = walk_ttc
            else:
                print("Unsuccessfull Walk :(")
                self.graph_statistics["walks"][i]["successfull"] = False

    def is_successfull_walk(self, walk):
        """
        Check if the walk was successfull i.e., the tactic 'Impact' was reached
        """
        if walk[-1]["technique"]["tactic"] == "Impact":
            return True
        return False

    def generate_walk(self, walk_counter, max_steps=15):
        """
        Generate a single walk throught the threat model but do not add the instances to the attack graph

        Arguments:
        starting_node: node i.e., asset to start the graph walk (entrance point for attack)
        starting_instance: specific instance of the starting node to begin the attack
        """
        self.walk_tactics = ["Initial Access"]
        walk = []
        # first step: sample from edges of tactic 'Initial Access'
        target_node, target_instance, technique = (
            self.sample_tactic_specific_next_attack_step("Initial Access")
        )
        technique["walk"] = walk_counter
        technique["step_counter"] = 0
        # add edge to attack graph
        walk.append(
            {
                "source_node": target_node,
                "source_instance": target_instance,
                "target_instance": target_instance,
                "target_node": target_node,
                "technique": technique,
            }
        )
        starting_instance = target_instance
        starting_node = target_node
        previous_technique = technique
        step_counter = 1
        while step_counter < max_steps:
            # following steps: sample from all outgoing edges
            target_node, target_instance, technique = self.sample_next_attack_step(
                starting_node, starting_instance, previous_technique
            )
            if target_node is None:
                print("No possible next step")
                break
            # add edge to attack graph
            technique["walk"] = walk_counter
            technique["step_counter"] = step_counter
            walk.append(
                {
                    "source_node": starting_node,
                    "source_instance": starting_instance,
                    "target_instance": target_instance,
                    "target_node": target_node,
                    "technique": technique,
                }
            )

            # stop: when tactic 'Impact' is reached
            if technique["tactic"] == "Impact":
                break
            else:
                # update starting node and instance
                starting_node = target_node
                starting_instance = target_instance
                previous_technique = technique
                step_counter += 1
                self.walk_tactics.append(technique["tactic"])
        self.graph_statistics["walks"][walk_counter]["step_counter"] = step_counter
        return walk

    def add_walk_to_attack_graph(self, walk):
        """
        Add the instances of the walk to the attack graph
        """
        for i, step in enumerate(walk):
            source_instance = step["source_instance"]
            source_node = step["source_node"]
            target_instance = step["target_instance"]
            target_node = step["target_node"]
            technique = step["technique"]
            if i == 0:
                self.add_attack_step(
                    source_instance,
                    source_node,
                    target_instance,
                    target_node,
                    technique,
                    start=True,
                )
            else:
                self.add_attack_step(
                    source_instance,
                    source_node,
                    target_instance,
                    target_node,
                    technique,
                )

    def add_attack_step(
        self,
        source_instance,
        source_node,
        target_instance,
        target_node,
        technique,
        start=False,
    ):
        # check if edge already exists -> extend techniques list and increase weight
        if self.has_edge(source_instance["id"], target_instance["id"]):
            self.edges[source_instance["id"], target_instance["id"]][
                "techniques"
            ].append(technique.copy())
            self.edges[source_instance["id"], target_instance["id"]]["weight"] += 1
            self.nodes[target_instance["id"]]["traversal"] += 1
        else:
            if not self.has_node(source_instance["id"]):
                asset_type = self.system_model.nodes[source_instance["id"]]["type"]
                self.add_node(
                    source_instance["id"],
                    instance_name=[source_instance["name"]],
                    asset=source_node,
                    asset_type=asset_type,
                    start=0,
                    ttc=self.ttc_dict[source_instance["id"]],
                    traversal=1,
                )
            if not self.has_node(target_instance["id"]):
                asset_type = self.system_model.nodes[target_instance["id"]]["type"]
                self.add_node(
                    target_instance["id"],
                    instance_name=[target_instance["name"]],
                    asset=target_node,
                    asset_type=asset_type,
                    start=0,
                    ttc=self.ttc_dict[target_instance["id"]],
                    traversal=1,
                )
            self.add_edge(source_instance["id"], target_instance["id"])
            self.edges[source_instance["id"], target_instance["id"]]["techniques"] = [
                technique.copy()
            ]
            self.edges[source_instance["id"], target_instance["id"]]["weight"] = 1
            self.edges[source_instance["id"], target_instance["id"]]["TTC"] = (
                self.ttc_dict[target_instance["id"]]["TTC"]
            )
        if start:
            self.nodes[source_instance["id"]]["start"] += 1
        # update unique step counts
        key = (
            f"{source_instance['id']}:{target_instance['id']}:{technique['technique']}"
        )
        if key in self.graph_statistics["walks"][-1]["unique_step_counts"]:
            self.graph_statistics["walks"][-1]["unique_step_counts"][key] += 1
        else:
            self.graph_statistics["walks"][-1]["unique_step_counts"][key] = 1

    def instance_restriction(self, current_instance):
        """
        Check if the instance is allowed to be used in the current attack step
        """

        def check_instance(next_instance):
            next_instance = next_instance[1]
            if nx.has_path(
                self.system_model, current_instance["id"], next_instance["id"]
            ) or nx.has_path(
                self.system_model, next_instance["id"], current_instance["id"]
            ):
                return True
            return False

        return check_instance

    def technique_restriction(self, technique):
        """
        Check if the technique is allowed to be used in the current attack step
        """
        if technique["tactic"] == "Initial Access":
            return False
        if technique["requirement"] not in self.walk_tactics:
            return False
        return True

    def combined_step_restriction(
        self, current_node, current_instance, previous_technique
    ):
        """
        Check if the combination of node, instance and technique is allowed to be used in the current attack step
        """

        def check_step(next_step):
            next_node = next_step[0]
            next_instance = next_step[1]
            technique = next_step[2]
            if technique["selfLoop"] and current_instance["id"] != next_instance["id"]:
                # target is the same instance as the source instance
                return False
            if (
                current_node == next_node
                and current_instance == next_instance
                and previous_technique == technique
            ):
                # exact same step should not be repeated directly after each other
                return False
            elif (
                self.graph_statistics["walks"][-1]["unique_step_counts"].get(
                    f"{current_instance['id']}:{next_instance['id']}:{technique['technique']}",
                    0,
                )
                > self.max_repititions
            ):
                # exact same step should not be repeated more than max_repititions times
                return False
            return True

        return check_step

    def sample_next_attack_step(
        self, current_node, current_instance, previous_technique
    ):
        """
        Randomly choose one of the outgoing edges from the current node

        Arguments:
        current_node: current node of the attack
        current instance: current instance of the attack

        Return: return the technique and target node and instance of the sampled attack step
        """

        # find all neighbors of the current node
        neighbors = self.threat_model.neighbors(current_node)

        # create a list of possible next instances and techniques to sample the next step from
        possible_next_steps = []
        for neighbor in neighbors:
            current_neighbor_instances = list(
                filter(
                    self.instance_restriction(current_node, current_instance),
                    [
                        (neighbor, instance)
                        for instance in self.threat_model.nodes[neighbor]["instances"]
                    ],
                )
            )
            techniques = filter(
                self.technique_restriction,
                self.threat_model.get_edge_data(current_node, neighbor)["techniques"],
            )
            possible_next_steps.extend(
                [
                    (node, instance, technique)
                    for node, instance in current_neighbor_instances
                    for technique in techniques
                ]
            )

        # remove the combination of current node, instance and previous technique from the possible next steps to avoid loops
        possible_next_steps = list(
            filter(
                self.combined_step_restriction(
                    current_node, current_instance, previous_technique
                ),
                possible_next_steps,
            )
        )
        # randomly pick one of the instances as the next attack step
        instance_weights = [
            1 / self.ttc_dict[instance[1]["id"]]["TTC"]
            for instance in possible_next_steps
        ]
        if len(set(instance_weights)) == 1:
            print("All TTCs are the same")
        # randomly choose the next attack step with the inverse time to compromise as weights
        if sum(instance_weights) > 0:
            target_node, target_instance, technique = random.choices(
                possible_next_steps, weights=instance_weights
            )[0]
        elif len(possible_next_steps) > 0:
            target_node, target_instance, technique = random.choice(possible_next_steps)
        else:
            print("No possible next step")
            return (None, None, None)

        return (target_node, target_instance, technique)

    def sample_tactic_specific_next_attack_step(self, tactic):
        """
        Randomly choose one of the outgoing edges from the current node that belongs to the tactic

        Arguments:
        current_node: current node of the attack
        current instance: current instance of the attack
        tactic: tactic of the
        """

        # get outgoing edges with the technique of the tactic
        possible_next_steps = []
        for source_node in self.threat_model.nodes:
            possible_techniques = self.threat_model.edges[source_node, source_node][
                "techniques"
            ]
            for instance in self.threat_model.nodes[source_node]["instances"]:
                possible_next_steps.extend(
                    [
                        (source_node, instance, technique)
                        for technique in possible_techniques
                        if technique["tactic"] == tactic
                    ]
                )

        instance_weights = [
            1 / self.ttc_dict[instance[1]["id"]]["TTC"]
            for instance in possible_next_steps
        ]
        if len(set(instance_weights)) == 1:
            print("All TTCs are the same")
        # randomly choose the next attack step with the inverse time to compromise as weights
        if sum(instance_weights) > 0:
            target_node, target_instance, technique = random.choices(
                possible_next_steps, weights=instance_weights
            )[0]
        elif len(possible_next_steps) > 0:
            target_node, target_instance, technique = random.choice(possible_next_steps)
        else:
            print("No possible next step")
            return (None, None, None)
        # randomly pick one of the instances as the next attack step
        return (target_node, target_instance, technique)

    def get_path_ttc_sum(self, path):
        """ "
        Return: Sum of TTC of unique instances in the attack path
        """
        unique_instances = [step["target_instance"]["id"] for step in path]
        return sum([self.ttc_dict[instance]["TTC"] for instance in unique_instances])

    def get_shortest_path(self, impact_technique=None):
        """
        Return: Shortest path to the impact technique
        """
        if not impact_technique:
            walk_idx, ttc = min(
                enumerate(
                    [
                        self.get_path_ttc_sum(walk["attack_steps"])
                        for walk in self.graph_statistics["walks"]
                        if walk["successfull"]
                    ]
                ),
                key=lambda x: x[1],
            )
            print(f"Total Shortest Path TTC: {ttc}")
            return self.graph_statistics["walks"][walk_idx]["attack_steps"]
        else:
            impact_technique_walks = []
            for idx, walk in enumerate(self.graph_statistics["walks"]):
                if (
                    walk["successfull"]
                    and walk["attack_steps"][-1]["technique"]["technique"].lower()
                    == impact_technique.lower()
                ):
                    impact_technique_walks.append(
                        (idx, self.get_path_ttc_sum(walk["attack_steps"]))
                    )
            print(
                f"Number of successfull walks with impact technique {impact_technique}: {len(impact_technique_walks)}"
            )
            if len(impact_technique_walks) == 0:
                return None
            walk_idx, ttc = min(impact_technique_walks, key=lambda x: x[1])
            print(
                f"Shortest Path TTC for {impact_technique}: {ttc}, walk_idx: {walk_idx}"
            )
            return self.graph_statistics["walks"][walk_idx]["attack_steps"]

    def get_graph_analysis(self):
        """
        Return: Percentage of impact techniques among successfull walks
        """
        impact_techniques = [
            "Data destruction",
            "Denial of service",
            "Resource hijacking",
        ]
        impact_technique_statistics = {}
        for impact_technique in impact_techniques:
            successfull_walks = len(
                [walk for walk in self.graph_statistics["walks"] if walk["successfull"]]
            )
            impact_technique_walks = len(
                [
                    walk
                    for walk in self.graph_statistics["walks"]
                    if walk["successfull"]
                    and walk["attack_steps"][-1]["technique"]["technique"].lower()
                    == impact_technique.lower()
                ]
            )
            impact_technique_statistics[impact_technique] = (
                impact_technique_walks / successfull_walks
            ) * 100

        # some more statistics
        average_steps = np.mean(
            [
                walk["step_counter"]
                for walk in self.graph_statistics["walks"]
                if walk["successfull"]
            ]
        )
        average_ttc_unique_instance = np.mean(
            [
                walk["TTC"]
                for walk in self.graph_statistics["walks"]
                if walk["successfull"]
            ]
        )
        average_ttc = np.mean(
            [
                self.get_path_ttc_sum(walk["attack_steps"])
                for walk in self.graph_statistics["walks"]
                if walk["successfull"]
            ]
        )
        # average number of unique instances in the attack graph
        average_number_unique_instances = np.mean(
            [
                len(
                    set(
                        [step["target_instance"]["id"] for step in walk["attack_steps"]]
                    )
                )
                for walk in self.graph_statistics["walks"]
                if walk["successfull"]
            ]
        )
        # number of successfull walks with only one unique instance
        number_unique_instance_one = len(
            [
                walk
                for walk in self.graph_statistics["walks"]
                if walk["successfull"]
                and len(
                    set(
                        [step["target_instance"]["id"] for step in walk["attack_steps"]]
                    )
                )
                == 1
            ]
        )
        most_traversed_instance = self.nodes[
            max(self.nodes, key=lambda x: self.nodes[x]["traversal"])
        ]
        most_traversed_instance_name = most_traversed_instance["instance_name"]
        impact_technique_statistics["average_steps"] = average_steps
        impact_technique_statistics["average_ttc"] = average_ttc
        impact_technique_statistics["average_ttc_unique_instance"] = (
            average_ttc_unique_instance
        )
        impact_technique_statistics["average_number_unique_instances"] = (
            average_number_unique_instances
        )
        impact_technique_statistics["number_unique_instance_one"] = (
            number_unique_instance_one
        )
        impact_technique_statistics["most_traversed_instance"] = {
            "name": most_traversed_instance_name,
            "traversal": most_traversed_instance["traversal"],
        }
        return impact_technique_statistics

    def draw_multipartite_layout(self, filepath):
        """
        Draw the system model graph with adjusted spacing to prevent node overlap
        """

        def scale_positions(positions, scale_factor=2.0):
            """
            Scale the positions to increase spacing between nodes.
            """
            return {node: (x * scale_factor, y) for node, (x, y) in positions.items()}

        # Define a color map for types
        asset_to_color = {
            "Container": "cyan",
            "namespace": "skyblue",
            "cluster": "yellowgreen",
            "RootShell": "violet",
            "Shell": "tomato",
            "Pod": "bisque",
        }

        types = nx.get_node_attributes(self, "asset_type")
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
        pos = nx.multipartite_layout(self, subset_key=subsets, align="horizontal")

        # Scale positions to increase spacing
        pos = scale_positions(pos, scale_factor=0.5)

        plt.figure(
            figsize=(22, 12),
            tight_layout={"pad": 0, "h_pad": 0, "w_pad": 0.2, "rect": [0, 0, 1, 1]},
        )
        node_sizes = [
            self.nodes[node].get("traversal", 1) * 27 + 1500 for node in self.nodes()
        ]
        nx.draw_networkx_nodes(
            self, pos, node_size=node_sizes, node_color=node_colors, margins=(0, 0.1)
        )
        node_labels = {
            node: str(node).replace(" ", "\n") for node in self.nodes()
        }  # Adding line breaks (adjust if needed)
        nx.draw_networkx_labels(
            self, pos, labels=node_labels, font_color="black", font_size=26
        )
        # Draw the edges
        for u, v in self.edges():
            if u == v:
                # Handle self-loop explicitly
                nx.draw_networkx_edges(
                    self, pos, edgelist=[(u, v)], node_size=130, edge_color="gray"
                )
            else:
                nx.draw_networkx_edges(
                    self,
                    pos,
                    edgelist=[(u, v)],
                    node_size=node_sizes,
                    edge_color="gray",
                )

        # Rotate the node labels
        for label in labels:
            x, y = pos[label]
            plt.text(
                (x - 0.25), y, labels[label], fontsize=26, va="bottom", rotation=45
            )

        # Create legend
        handles = [
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor=color,
                markersize=20,
                label=type_name,
            )
            for type_name, color in asset_to_color.items()
        ]
        plt.legend(
            handles=handles, title="Node Types", title_fontsize="30", fontsize="26"
        )
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(filepath)


def paths_for_impact_techniques(attack_graph):
    """
    Find shortest paths for different impact techniques
    """
    impact_techniques = ["Data destruction", "Denial of service", "Resource hijacking"]

    for impact_technique in impact_techniques:
        shortest_path = attack_graph.get_shortest_path(
            impact_technique=impact_technique
        )
        if shortest_path:
            print(
                f"Shortest Path {impact_technique}: ",
                [
                    (step["target_instance"], step["technique"]["technique"])
                    for step in shortest_path
                ],
            )
        else:
            print(f"No successfull walk with impact technique {impact_technique}")


if __name__ == "__main__":
    # load threat model from
    tm_file = "ThreatModelFileLocation"
    sm_file = "SystemModelFileLocation"
    threat_model = nx.read_gml(tm_file)
    system_model = SystemModel(sm_file)
    attack_graph = AttackGraph(threat_model=threat_model, system_model=system_model)
    attack_graph.generate_attack_graph(number_walks=100)
    # print percentage of successfull walks
    successfull_walks = len(
        [walk for walk in attack_graph.graph_statistics["walks"] if walk["successfull"]]
    )
    print(
        f"Successfull Walks: {successfull_walks}/{len(attack_graph.graph_statistics['walks'])}"
    )
    # Find shortest paths for different impact techniques
    paths_for_impact_techniques(attack_graph)
    attack_graph.graph_statistics["graph_analysis"] = attack_graph.get_graph_analysis()
    print(attack_graph.graph_statistics["graph_analysis"])
    figure_filepath = "path/to/store/graph"
    attack_graph.draw_multipartite_layout(figure_filepath)
    statistics_filepath = "path/to/store/graphstatistics"
    graph_statistics = attack_graph.graph_statistics
    json.dump(graph_statistics, open(graph_statistics, "w"), indent=4)
