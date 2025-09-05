import networkx as nx
from TTCComputation.system_ttc import calc_system_ttcs


def build_hierarchy_graph():
    g = nx.DiGraph()
    # cluster -> namespace -> pods -> containers
    g.add_node(30, type="cluster", name="cluster")
    g.add_node(20, type="namespace", name="ns")
    g.add_edge(30, 20)
    # Pod A (10) with high severity container 1
    g.add_node(10, type="Pod", name="pod-a")
    g.add_edge(20, 10)
    g.add_node(
        1,
        type="Container",
        name="c-high",
        CVEs=[{"cvss": {"version": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
        CHECKS=[],
    )
    g.add_edge(10, 1)
    # Pod B (11) with lower severity container 2
    g.add_node(11, type="Pod", name="pod-b")
    g.add_edge(20, 11)
    g.add_node(
        2,
        type="Container",
        name="c-low",
        CVEs=[{"cvss": {"version": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}}],
        CHECKS=[],
    )
    g.add_edge(11, 2)
    return g


def test_ttc_aggregation_pod_and_namespace():
    g = build_hierarchy_graph()
    ttcs = calc_system_ttcs(g, attacker_skill_level="intermediate")
    # Pod TTC should equal TTC of its lowest-TTC container
    assert abs(ttcs[10]["TTC"] - ttcs[1]["TTC"]) < 1e-6
    assert abs(ttcs[11]["TTC"] - ttcs[2]["TTC"]) < 1e-6
    # Namespace TTC should pick min (pod-a vs pod-b) => pod-a
    assert abs(ttcs[20]["TTC"] - min(ttcs[10]["TTC"], ttcs[11]["TTC"])) < 1e-6
    # Cluster inherits min of namespaces (only one here)
    assert abs(ttcs[30]["TTC"] - ttcs[20]["TTC"]) < 1e-6
