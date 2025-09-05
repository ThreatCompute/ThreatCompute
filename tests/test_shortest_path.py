from AttackGraphGeneration.attackgraph import AttackGraph
from ThreatModeling.system_model import SystemModel


def test_shortest_path_selection():
    # Build system model with two containers c1 (more vulnerable) and c2 (less vulnerable)
    sm = SystemModel()
    sm.add_node(0, type="Container", name="c1", CVEs=[{"cvss": {"version": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}], CHECKS=[])
    sm.add_node(1, type="Container", name="c2", CVEs=[{"cvss": {"version": 3.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}}], CHECKS=[])
    # Threat model with container node self-loop for Initial Access and Impact
    import networkx as nx
    tm = nx.DiGraph()
    tm.add_node("Container", instances=[{"id":0,"name":"c1"},{"id":1,"name":"c2"}])
    tm.add_edge(
        "Container",
        "Container",
        techniques=[
            {"technique":"Using cloud credentials","tactic":"Initial Access","requirement":None,"selfLoop":True},
            {"technique":"Data destruction","tactic":"Impact","requirement":"Initial Access","selfLoop":True},
        ],
    )
    ag = AttackGraph(threat_model=tm, system_model=sm, attacker_level="novice")
    # Manually craft two walks instead of relying on randomness
    low_walk = [
        {"source_node":"Container","source_instance":{"id":0,"name":"c1"},"target_instance":{"id":0,"name":"c1"},"target_node":"Container","technique":{"technique":"Using cloud credentials","tactic":"Initial Access"}},
        {"source_node":"Container","source_instance":{"id":0,"name":"c1"},"target_instance":{"id":0,"name":"c1"},"target_node":"Container","technique":{"technique":"Data destruction","tactic":"Impact"}},
    ]
    high_walk = [
        {"source_node":"Container","source_instance":{"id":1,"name":"c2"},"target_instance":{"id":1,"name":"c2"},"target_node":"Container","technique":{"technique":"Using cloud credentials","tactic":"Initial Access"}},
        {"source_node":"Container","source_instance":{"id":1,"name":"c2"},"target_instance":{"id":1,"name":"c2"},"target_node":"Container","technique":{"technique":"Data destruction","tactic":"Impact"}},
    ]
    ag.graph_statistics["walks"] = [
        {"attack_steps": low_walk, "successfull": True},
        {"attack_steps": high_walk, "successfull": True},
    ]
    # Ensure TTC computed
    assert ag.ttc_dict[0]["TTC"] <= ag.ttc_dict[1]["TTC"]
    sp = ag.get_shortest_path()
    assert sp[-1]["target_instance"]["id"] == 0
