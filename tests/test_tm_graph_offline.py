import os
import networkx as nx
from ThreatModeling import tm_graph

def build_tmr_fixture():
    # Minimal threat model structure consistent with tm_graph expectations
    tmr = {
        "assets": {
            "Container": {
                "categories": {
                    "CatA": {
                        "description": "Category A containers",
                        "instances": [{"name": "cont1", "id": 1}],
                    }
                }
            },
            "Pod": {"description": "Pod desc", "instances": [{"name": "pod1", "id": 2}]},
            "cluster": {"description": "Cluster desc", "instances": [{"name": "cl", "id": 3}]},
        },
        "techniques": {
            "Container": {
                "CatA": {
                    # One tactic with multiple technique target forms
                    "Execution": [
                        {  # list target branch
                            "technique": "Exploit1",
                            "description": "Desc1",
                            "tactic": "Execution",
                            "target": ["Pod", "cluster"],
                            "requirement": "req1",
                        },
                        {  # self target branch
                            "technique": "Exploit2",
                            "description": "Desc2",
                            "tactic": "Execution",
                            "target": "self",
                            "requirement": "req2",
                        },
                        {  # single target branch
                            "technique": "Exploit3",
                            "description": "Desc3",
                            "tactic": "Execution",
                            "target": "cluster",
                            "requirement": "req3",
                        },
                    ]
                }
            },
            "Pod": {
                "Execution": [
                    {
                        "technique": "PodExploit",
                        "description": "PodDesc",
                        "tactic": "Execution",
                        "target": "cluster",
                        "requirement": "req4",
                    }
                ]
            },
            "cluster": {"Execution": []},
        },
    }
    return tmr


def test_tmr_to_graph_and_edges():
    tmr = build_tmr_fixture()
    G = tm_graph.tmr_to_graph(tmr)
    # Nodes present
    assert set(G.nodes()) == {"CatA", "Pod", "cluster"}
    # Edge weights aggregated
    assert G.has_edge("CatA", "Pod")
    assert G.has_edge("CatA", "cluster")
    assert G.has_edge("CatA", "CatA")  # self-loop
    # Techniques recorded
    data = G.get_edge_data("CatA", "cluster")
    assert data["weight"] == 2  # one from list target (cluster) + single target
    # Ensure self-loop technique flagged
    loop_data = G.get_edge_data("CatA", "CatA")
    assert loop_data["techniques"][0]["selfLoop"] is True


def test_attack_paths_runs(monkeypatch):
    tmr = build_tmr_fixture()
    G = tm_graph.tmr_to_graph(tmr)
    # Replace print to collect outputs (avoid noisy test log)
    printed = []
    import builtins
    monkeypatch.setattr(builtins, "print", lambda *a, **k: printed.append(a))
    tm_graph.attack_paths(G)  # Should not raise
    assert isinstance(printed, list)
