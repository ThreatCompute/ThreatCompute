import networkx as nx
from TTCComputation.system_ttc import encapsulated_ttc, calculate_node_ttc


def build_graph(parent_type, child_type, child_ttcs):
    g = nx.DiGraph()
    g.add_node("parent", type=parent_type)
    for idx, ttc in enumerate(child_ttcs):
        cid = f"c{idx}"
        g.add_node(cid, type=child_type, CVEs=[], CHECKS=[])  # minimal fields
        g.add_edge("parent", cid)
    return g


def test_encapsulated_ttc_no_children():
    g = nx.DiGraph()
    g.add_node("p", type="Pod", CVEs=[], CHECKS=[])
    fake_ttc_dict = {}
    node = ("p", g.nodes["p"])
    result = encapsulated_ttc(g, node, "Container", fake_ttc_dict, attacker_skill_level="novice")
    # Falls back to calculate_node_ttc -> dict with TTC
    assert "TTC" in result


def test_encapsulated_ttc_single_child_passthrough():
    g = build_graph("Pod", "Container", [5.0])
    # pre-populate child TTC
    fake_ttc_dict = {"c0": {"TTC": 5.0}}
    node = ("parent", g.nodes["parent"])
    result = encapsulated_ttc(g, node, "Container", fake_ttc_dict, attacker_skill_level="novice")
    assert result["TTC"] == 5.0


def test_encapsulated_ttc_multiple_children_min():
    g = build_graph("Pod", "Container", [7.0, 3.0, 10.0])
    fake_ttc_dict = {"c0": {"TTC": 7.0}, "c1": {"TTC": 3.0}, "c2": {"TTC": 10.0}}
    node = ("parent", g.nodes["parent"])
    result = encapsulated_ttc(g, node, "Container", fake_ttc_dict, attacker_skill_level="novice")
    assert result["TTC"] == 3.0
