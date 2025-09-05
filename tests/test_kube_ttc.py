import math
from TTCComputation.kube_ttc import KUBE_TTC


def test_kube_ttc_no_scores():
    ttc = KUBE_TTC([], [])
    # With no scores, v == 0 so calc_u should return 1 and TTC components use defaults
    # Ensure calling the methods does not raise and returns numeric values
    result = ttc.calc_TTC_components('novice')
    assert 'TTC' in result and isinstance(result['TTC'], float)


def test_kube_ttc_with_dummy_scores():
    # Create two synthetic CVSS3 vectors (High / Medium) using cvss lib requires real objects
    import cvss
    high = cvss.CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')
    medium = cvss.CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N')
    ttc = KUBE_TTC([high, medium], misconfigurations=[{"scoreFactor": 5}])
    res_beginner = ttc.calc_TTC('beginner')
    res_expert = ttc.calc_TTC('expert')
    assert res_expert <= res_beginner  # expert should have lower/equal TTC
