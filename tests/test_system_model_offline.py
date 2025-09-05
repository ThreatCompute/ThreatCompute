import os
import networkx as nx
from ThreatModeling.system_model import SystemModel, analyze_asset_instances, summarize_asset_analyses


def build_system_model(tmp_path):
    G = nx.DiGraph()
    G.add_node(1, type="Container", name="c1", CVEs=["CVE-1"], CHECKS=["CHK-1"])
    G.add_node(2, type="Pod", name="p1")
    G.add_node(3, type="cluster", namespace="clusterA")
    G.add_edge(1,2)
    G.add_edge(2,3)
    path = tmp_path/"sys.gml"
    nx.write_gml(G, path)
    return SystemModel(system_model_file=str(path))


def test_getters_and_subgraph(tmp_path):
    sm = build_system_model(tmp_path)
    assert sm.get_instance_id("Container", "c1") == 1
    assert sm.get_instance_name(3) == "clusterA"
    sub = sm.get_asset_subgraph("Container", unwanted_attributes=["CVEs"])  # remove CVEs
    assert list(sub.nodes()) == [1]
    assert "CVEs" not in sub.nodes[1]
    vulns = sm.get_vulnerabilities_by_instance_ids([1])
    assert vulns == ["CVE-1"]
    mis = sm.get_misconfigurations_by_instance_ids([1])
    assert mis == ["CHK-1"]


def test_offline_analysis_and_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("TC_OFFLINE", "1")
    sm = build_system_model(tmp_path)
    analyses = analyze_asset_instances(sm, "Container")
    assert 1 in analyses and "analysis" in analyses[1]
    summary = summarize_asset_analyses("Container", analyses)
    assert "Offline summary" in summary
