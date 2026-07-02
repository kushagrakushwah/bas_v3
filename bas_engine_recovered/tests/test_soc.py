import pytest
from bas_engine.detection.soc_scoring import SOCScoringEngine

def test_soc_scoring_no_modules():
    engine = SOCScoringEngine()
    result = engine.calculate_score(findings=[], executed_modules=[])
    assert result["soc_score"] == 0
    assert result["rating"] == "Not Tested"

def test_soc_scoring_perfect_defense():
    engine = SOCScoringEngine()
    result = engine.calculate_score(findings=[], executed_modules=["nmap_scan", "owasp_web"])
    # Should get base score of 100 since no critical findings
    assert result["soc_score"] == 100
    assert result["rating"] == "Excellent"

def test_soc_scoring_with_critical():
    engine = SOCScoringEngine()
    findings = [{"severity": "critical"}, {"severity": "high"}]
    result = engine.calculate_score(findings=findings, executed_modules=["nmap_scan"])
    # 100 - (1 * 15) - (1 * 8) - 10 (coverage penalty for < 4 tactics) + 2 (coverage reward for 1 tactic) = 69
    assert result["soc_score"] == 69
