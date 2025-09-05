from ThreatModeling.technique_analysis import verify_techniques


def test_verify_techniques_filters_invalid_entries():
    technique_list = ["Exec into container", "Application exploit (RCE)"]
    asset_list = ["Container", "Pod"]
    tactic = "Execution"
    candidate = [
        {  # valid
            "technique": "Exec into container",
            "description": "valid",
            "target": "self",
            "requirement": "Initial Access",
        },
        {  # wrong technique
            "technique": "Nonexistent Technique",
            "description": "invalid technique",
            "target": "self",
            "requirement": "Initial Access",
        },
        {  # wrong target
            "technique": "Exec into container",
            "description": "invalid target",
            "target": "UnknownAsset",
            "requirement": "Initial Access",
        },
        {  # wrong prerequisite tactic
            "technique": "Application exploit (RCE)",
            "description": "invalid prereq",
            "target": "self",
            "requirement": "MadeUpTactic",
        },
    ]
    verified = verify_techniques(candidate, technique_list, asset_list, tactic)
    assert len(verified) == 1
    assert verified[0]["technique"] == "Exec into container"


def test_verify_techniques_accepts_none_requirement():
    # For Initial Access techniques requirement can be None
    technique_list = ["Using cloud credentials"]
    asset_list = ["Container"]
    tactic = "Initial Access"
    candidate = [
        {
            "technique": "Using cloud credentials",
            "description": "ok",
            "target": "self",
            "requirement": None,
        }
    ]
    verified = verify_techniques(candidate, technique_list, asset_list, tactic)
    assert len(verified) == 1
    assert verified[0]["requirement"] is None
