import os
import networkx as nx
import pytest
from ThreatModeling.technique_analysis import techniques_for_asset, vulnerabilties_summarizer, misconfigurations_summarizer

class DummySystemModel:
    def __init__(self):
        self._vulns = [
            {"resource": "pkgA", "title": "RCE issue", "cvss": {"version": 3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            {"resource": "pkgB", "title": "Another vuln", "cvss": {"version": 3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}},
        ]
        self._mis = [
            {"check": "privileged", "severity": "HIGH"},
            {"check": "runAsRoot", "severity": "MED"},
        ]
    def get_vulnerabilities_by_instance_ids(self, ids):
        return self._vulns if ids else []
    def get_misconfigurations_by_instance_ids(self, ids):
        return self._mis if ids else []


def setup_module(module):
    os.environ["TC_OFFLINE"] = "1"

def teardown_module(module):
    os.environ.pop("TC_OFFLINE", None)


def test_offline_techniques_initial_access():
    res = techniques_for_asset(
        asset="Container",
        asset_description="test container",
        system_description="system",
        asset_vulnerabilities="Some vulns",
        asset_misconfigurations="Some mis",
        tactic="Initial Access",
        assets_list=["Container"],
        is_container=True,
    )
    assert res and res[0]["technique"]
    assert res[0]["requirement"] is None


def test_offline_techniques_no_vul_no_mis():
    res = techniques_for_asset(
        asset="Container",
        asset_description="test container",
        system_description="system",
        asset_vulnerabilities="No vulnerabilities found.",
        asset_misconfigurations="No misconfigurations found.",
        tactic="Execution",
        assets_list=["Container"],
        is_container=True,
    )
    assert res and res[0]["target"].lower() in ["container", "self"]


def test_offline_techniques_general():
    res = techniques_for_asset(
        asset="Pod",
        asset_description="test pod",
        system_description="system",
        asset_vulnerabilities="Some vulns",
        asset_misconfigurations="Some mis",
        tactic="Execution",
        assets_list=["Container", "Pod"],
        is_container=False,
    )
    assert len(res) >= 1


def test_offline_vulnerability_summary():
    sys_model = DummySystemModel()
    summary = vulnerabilties_summarizer(["a", "b"], sys_model)
    assert isinstance(summary, dict)
    assert summary["total_vulnerabilities"] == 2


def test_offline_misconfiguration_summary():
    sys_model = DummySystemModel()
    summary = misconfigurations_summarizer(["a"], ["inst"], sys_model)
    assert "misconfigurations offline" in summary
