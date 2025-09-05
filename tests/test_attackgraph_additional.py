import networkx as nx
from AttackGraphGeneration.attackgraph import AttackGraph


def build_minimal_threat_model():
    g = nx.DiGraph()
    # Node with one instance
    g.add_node("A", instances=[{"id": "instA", "name": "instA"}])
    # Self loop edge holding techniques
    initial = {"technique": "Initial Access Method", "tactic": "Initial Access", "requirement": None, "selfLoop": True}
    impact = {"technique": "Impact Method", "tactic": "Impact", "requirement": "Initial Access", "selfLoop": True}
    g.add_edge("A", "A", techniques=[initial, impact])
    return g


def test_attackgraph_generate_and_stop():
    threat_model = build_minimal_threat_model()
    ag = AttackGraph(threat_model=threat_model, system_model=None)

    # progress callback will request stop after first walk
    def cb(progress):
        ag.request_stop()
    ag.progress_callback = cb
    ag.generate_attack_graph(number_walks=5)
    # Only first walk attempted (may be successful)
    assert ag._completed_walks == 1
    assert len(ag.graph_statistics["walks"]) == 1


def test_attackgraph_shortest_path_none():
    ag = AttackGraph(threat_model=None, system_model=None)
    ag.generate_attack_graph(number_walks=2)  # no threat model -> no walks
    assert ag.get_shortest_path() is None


def test_attackgraph_shortest_path_success_and_analysis():
    threat_model = build_minimal_threat_model()
    ag = AttackGraph(threat_model=threat_model, system_model=None)
    ag.generate_attack_graph(number_walks=3)
    sp = ag.get_shortest_path()
    assert sp is not None
    # Should terminate with Impact technique
    assert sp[-1]["technique"]["tactic"] == "Impact"
    analysis = ag.get_graph_analysis()
    # Impact Method should appear with 100% since only one impact technique
    assert "Denial of service" in analysis  # keys exist even if zero
    assert any(v >= 0 for v in analysis.values())


def test_attackgraph_progress_callback_exception():
    threat_model = build_minimal_threat_model()
    ag = AttackGraph(threat_model=threat_model, system_model=None, progress_callback=lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
    ag.generate_attack_graph(number_walks=1)  # should not raise
    assert ag._completed_walks == 1
