import os
import networkx as nx
from ThreatModeling.threat_model_creator import build_threat_model
from ThreatModeling.system_model import SystemModel


def build_simple_system(tmp_path):
    G = nx.DiGraph()
    # Minimal chain RootShell -> Container -> Pod -> namespace -> cluster
    G.add_node(1, type="RootShell", name="rootA")
    G.add_node(2, type="Shell", name="shA")
    G.add_node(3, type="Container", name="contA", CVEs=["CVE-1"], CHECKS=["CHK-1"])  # add vuln/misconf to exercise summarizers
    G.add_node(4, type="Pod", name="podA")
    G.add_node(5, type="namespace", namespace="nsA")
    G.add_node(6, type="cluster", namespace="clusterA")
    G.add_edges_from([(1,3),(3,4),(4,5),(5,6)])
    path = tmp_path/"model.gml"
    nx.write_gml(G, path)
    return str(path)


def test_build_threat_model_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("TC_OFFLINE", "1")
    system_model_path = build_simple_system(tmp_path)
    result = build_threat_model(system_model_path, application="TEST", write_results=False)
    # Basic shape assertions
    assert "assets" in result and result["assets"]
    assert "tactics" in result and result["tactics"]
    assert "techniques" in result
    # Offline deterministic tactic present
    some_asset = next(iter(result["tactics"]))
    assert result["tactics"][some_asset][0]["tactic"] == "Initial Access"
    # Techniques structure (may be empty offline if dependencies missing but key should exist)
    assert isinstance(result["techniques"], dict)
