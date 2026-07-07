from bas_engine.detection.coverage_engine import (
    CoverageEngine
)

from bas_engine.detection.soc_scoring import (
    SOCScoringEngine
)

from bas_engine.detection.blindspot_analyzer import (
    BlindSpotAnalyzer
)

from bas_engine.detection.sigma_generator import (
    SigmaGenerator
)


class DetectionValidationEngine:

    def __init__(self):

        self.coverage_engine = (
            CoverageEngine()
        )

        self.soc_engine = (
            SOCScoringEngine()
        )

        self.blindspot_engine = (
            BlindSpotAnalyzer()
        )

        self.sigma_engine = (
            SigmaGenerator()
        )

    # ------------------------------------------------
    # FULL VALIDATION
    # ------------------------------------------------

    def validate(
        self,
        findings: list,
        executed_modules: list = None
    ):

        coverage = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        soc_score = (
            self.soc_engine
            .calculate_score(findings, executed_modules)
        )

        blindspots = (
            self.blindspot_engine
            .analyze(findings)
        )

        sigma_rules = (
            self.sigma_engine
            .generate_rules(findings)
        )

        return {
            "methodology": {
                "disclaimer": "This validation is simulated. No SIEM integration detected.",
                "exposure_score": "Severity-weighted logarithmic score of attacker success (0-100).",
                "detection_score": "Simulated SOC detection capability based on technique-to-Sigma-rule mappings (0-100)."
            },

            "attack_surface": {
                "exposure_score": soc_score.get("exposure_score", 0),
                "critical_findings": soc_score.get("critical_findings", 0),
                "high_findings": soc_score.get("high_findings", 0),
                "medium_findings": soc_score.get("medium_findings", 0),
                "low_findings": soc_score.get("low_findings", 0),
                "techniques_tested": coverage.get("techniques_tested", 0),
            },
            
            "detection_simulation": {
                "detection_score": soc_score.get("detection_score", 0),
                "nist_maturity_tier": soc_score.get("nist_maturity_tier", "Tier 1: Minimal"),
                "tactics_detected": coverage.get("tactics_detected", 0),
                "sigma_rules_matched": coverage.get("sigma_rules_matched", 0),
                "blind_spots_tactics": blindspots.get("blind_spots", []),
                "untested_subtechniques": blindspots.get("untested_subtechniques", []),
                "coverage_metrics": coverage.get("coverage", {}),
                "sigma_rules": sigma_rules
            },
            
            "blindspots": blindspots
        }