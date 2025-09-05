import pytest
from ThreatModeling.technique_analysis import verify_techniques
from ThreatModeling.matrices import K8S_MATRIX


def test_verify_techniques_filters_invalid():
    techniques_list = K8S_MATRIX["Execution"]
    assets_list = ["Pod", "Container"]
    # mix of valid / invalid entries
    sample = [
        {"technique": techniques_list[0], "target": "Pod", "requirement": "Initial Access"},  # valid
        {"technique": "NotAReal", "target": "Pod", "requirement": "Initial Access"},      # invalid technique
        {"technique": techniques_list[1], "target": "AlienAsset", "requirement": "Initial Access"},  # invalid asset
        {"technique": techniques_list[2], "target": "self", "requirement": "BadTactic"},    # invalid prerequisite tactic
    ]
    verified = verify_techniques(sample, techniques_list, assets_list, "Execution")
    assert len(verified) == 1
    assert verified[0]["technique"] == techniques_list[0]


def test_verify_techniques_case_insensitive():
    techniques_list = K8S_MATRIX["Impact"]
    assets_list = ["Node"]
    sample = [
        {"technique": techniques_list[0].upper(), "target": "SELF", "requirement": "Initial Access"},
    ]
    # requirement tactic allowed as long as present or None
    verified = verify_techniques(sample, techniques_list, assets_list, "Impact")
    assert verified and verified[0]["technique"].lower() == techniques_list[0].lower()


def test_verify_techniques_empty_result():
    techniques_list = []
    assets_list = ["Container"]
    sample = [
        {"technique": "Something", "target": "Container", "requirement": None}
    ]
    verified = verify_techniques(sample, techniques_list, assets_list, "Execution")
    assert verified == []
