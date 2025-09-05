import networkx as nx
from TTCComputation.system_ttc import calc_system_ttcs


def build_minimal_graph():
    g = nx.DiGraph()
    # cluster -> namespace -> pod -> container
    g.add_node(0, type='cluster', name='cluster')
    g.add_node(1, type='namespace', name='ns')
    g.add_node(2, type='Pod', name='pod')
    g.add_node(3, type='Container', name='app', CVEs=[], CHECKS=[])
    g.add_edge(0,1)
    g.add_edge(1,2)
    g.add_edge(2,3)
    return g


def test_calc_system_ttcs_minimal_graph():
    g = build_minimal_graph()
    ttcs = calc_system_ttcs(g, attacker_skill_level='novice')
    # All nodes should have TTC computed
    assert set(ttcs.keys()) == {0,1,2,3}
    for v in ttcs.values():
        assert 'TTC' in v
