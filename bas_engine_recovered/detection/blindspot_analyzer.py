from bas_engine.detection.coverage_engine import (
    CoverageEngine
)
from bas_engine.detection.constants import MITRE_ATTACK_TACTICS, MITRE_SUBTECHNIQUES

class BlindSpotAnalyzer:

    def __init__(self):

        self.coverage_engine = (
            CoverageEngine()
        )

    # ------------------------------------------------
    # ANALYZE BLIND SPOTS
    # ------------------------------------------------

    def analyze(
        self,
        findings: list
    ):

        coverage_data = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        detected_tactics = set(
            coverage_data[
                "coverage"
            ].keys()
        )

        blind_spots = []

        for tactic in MITRE_ATTACK_TACTICS:
            if tactic not in detected_tactics:
                blind_spots.append(tactic)
                
        # --------------------------------------------
        # SUB-TECHNIQUE ANALYSIS
        # --------------------------------------------
        detected_techniques = set()
        for finding in findings:
            mid = finding.get("mitre_id")
            if mid:
                detected_techniques.add(mid)
                
        untested_subtechniques = []
        for tech, subtechs in MITRE_SUBTECHNIQUES.items():
            if tech in detected_techniques or any(t.startswith(tech + ".") for t in detected_techniques):
                for subtech in subtechs:
                    if subtech not in detected_techniques:
                        untested_subtechniques.append(subtech)

        # --------------------------------------------
        # RISK LEVEL
        # --------------------------------------------

        count = len(blind_spots)

        if count >= 7:

            risk = "High"

        elif count >= 4:

            risk = "Moderate"

        else:

            risk = "Low"

        # --------------------------------------------
        # COVERAGE %
        # --------------------------------------------

        coverage_percent = round(

            (
                len(detected_tactics)
                / len(MITRE_ATTACK_TACTICS)
            ) * 100,

            2
        )

        return {

            "coverage_percent":
                coverage_percent,

            "detected_tactics":
                list(detected_tactics),

            "blind_spots":
                blind_spots,

            "blind_spot_count":
                count,
                
            "untested_subtechniques": untested_subtechniques,
            
            "untested_subtechniques_count": len(untested_subtechniques),

            "risk_level":
                risk
        }