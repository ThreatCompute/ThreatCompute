import networkx as nx
from AttackGraphGeneration.attackgraph import AttackGraph
from ThreatModeling.system_model import SystemModel


def build_system_and_threat_models():
    # System model with two containers and a pod
    sm = SystemModel()
    sm.add_node(0, type='Container', name='c1', CVEs=[], CHECKS=[])
    sm.add_node(1, type='Container', name='c2', CVEs=[], CHECKS=[])
    sm.add_edge(0,1)

    # Threat model with an Initial Access self-loop and an Execution edge
    tm = nx.DiGraph()
    tm.add_node('Container', instances=[{'id':0,'name':'c1'},{'id':1,'name':'c2'}])
    # self loop techniques for initial access
    tm.add_edge('Container','Container', techniques=[
        {'technique':'Using cloud credentials','tactic':'Initial Access','requirement':None,'selfLoop':True},
        {'technique':'Application exploit (RCE)','tactic':'Execution','requirement':'Initial Access','selfLoop':True}
    ])
    return sm, tm


def test_attackgraph_generation():
    sm, tm = build_system_and_threat_models()
    ag = AttackGraph(threat_model=tm, system_model=sm, attacker_level='novice')
    ag.generate_attack_graph(number_walks=3)
    # At least one successful walk should exist (Impact not modeled, so success depends on code path)
    # Here walks will not be successful because no Impact tactic; ensure no crash and walks recorded
    assert len(ag.graph_statistics['walks']) == 3
