import networkx as nx
from cvss import CVSS3, CVSS2
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from TTCComputation.kube_ttc import KUBE_TTC


def load_graph(file_path):
    return nx.read_gml(file_path)


def calculate_node_ttc(
    node,
    child_vulnerabilities=[],
    child_misconfigurations=[],
    attacker_skill_level="novice",
):
    vulnerabilities = (
        node[1].get("CVEs", []) + child_vulnerabilities
    )  # add vulnerabilities of children
    cvss_scores = []
    for vul in vulnerabilities:
        cvss = vul.get("cvss", [])
        if cvss == "None" or not cvss:
            # Assume worst case scenario if no CVSS score is available
            cvss_score = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        else:
            if isinstance(cvss, list):
                cvss = cvss[0]
            cvss_vector = cvss.get("vector")
            if cvss.get("version") == 2:
                cvss_score = CVSS2(cvss_vector)
            else:
                cvss_score = CVSS3(cvss_vector)
        cvss_scores.append(cvss_score)
    misconfigurations = (
        node[1].get("CHECKS", []) + child_misconfigurations
    )  # add misconfigurations of children

    TTC = KUBE_TTC(cvss_scores, misconfigurations)
    ttc = TTC.calc_TTC_components(attacker_skill_level)
    return ttc


def asset_level(node):
    if node[1]["type"] == "RootShell" or node[1]["type"] == "Shell":
        return 0
    elif node[1]["type"] == "Container":
        return 1
    elif node[1]["type"] == "Pod":
        return 2
    elif node[1]["type"] == "namespace":
        return 3
    elif node[1]["type"] == "cluster":
        return 4
    return -1


def encapsulated_ttc(graph, node, child_type, ttc_dict, attacker_skill_level="novice"):
    """
    Calculate the TTC of a node considering the vulnerabilities of its children (e.g., containers in a pod)
    """
    # Collect children of the requested type
    child_instances = [
        child for child in graph.successors(node[0]) if graph.nodes[child]["type"] == child_type
    ]
    if not child_instances:
        # No children of that type: fallback to own vulnerabilities only
        return calculate_node_ttc(node, attacker_skill_level=attacker_skill_level)

    # Select child with minimal TTC (already computed and stored in ttc_dict)
    min_child = min(child_instances, key=lambda c: ttc_dict[c]["TTC"]) if child_instances else None
    if min_child is None:
        return calculate_node_ttc(node, attacker_skill_level=attacker_skill_level)

    # Propagate the child's TTC dictionary upward directly (no recomputation) to
    # satisfy the design expectation that higher-level asset TTC reflects its
    # most vulnerable descendant of the specified child type.
    return ttc_dict[min_child]


def calc_system_ttcs(graph, attacker_skill_level="novice"):
    """
    Calculate the TTC of all assets in the system model
    """
    ttc_dict = {}
    # sort node by increasing asset level (rootshell/Shell -> container -> pod -> namespace -> cluster)
    shells = []
    containers = []
    pods = []
    namespaces = []
    clusters = []
    for node in graph.nodes(data=True):
        if node[1]["type"] == "RootShell" or node[1]["type"] == "Shell":
            shells.append(node)
        elif node[1]["type"] == "Container":
            containers.append(node)
        elif node[1]["type"] == "Pod":
            pods.append(node)
        elif node[1]["type"] == "namespace":
            namespaces.append(node)
        elif node[1]["type"] == "cluster":
            clusters.append(node)
    for node in shells:
        asset = node[0]
        ttc_dict[asset] = calculate_node_ttc(
            node, attacker_skill_level=attacker_skill_level
        )
    for node in containers:
        asset = node[0]
        ttc_dict[asset] = calculate_node_ttc(
            node, attacker_skill_level=attacker_skill_level
        )
    for node in pods:
        asset = node[0]
        ttc_dict[asset] = encapsulated_ttc(
            graph,
            node,
            "Container",
            ttc_dict,
            attacker_skill_level=attacker_skill_level,
        )
    for node in namespaces:
        asset = node[0]
        ttc_dict[asset] = encapsulated_ttc(
            graph, node, "Pod", ttc_dict, attacker_skill_level=attacker_skill_level
        )
    for node in clusters:
        asset = node[0]
        ttc_dict[asset] = encapsulated_ttc(
            graph,
            node,
            "namespace",
            ttc_dict,
            attacker_skill_level=attacker_skill_level,
        )
    return ttc_dict


def main():
    file_path = "path/to/systemmodel"
    graph = load_graph(file_path)
    ttc_dict = calc_system_ttcs(graph)


if __name__ == "__main__":
    main()
