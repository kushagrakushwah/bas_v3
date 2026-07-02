from collections import defaultdict

from bas_engine.detection.mitre_mapper import (
    get_tactic
)
from bas_engine.detection.constants import TACTIC_TECHNIQUE_COUNTS


class CoverageEngine:

    # ------------------------------------------------
    # CALCULATE COVERAGE
    # ------------------------------------------------

    def calculate_coverage(
        self,
        findings: list
    ):

        tactic_counts = defaultdict(set)
        detected_techniques = set()

        for finding in findings:

            mitre_id = finding.get(
                "mitre_id"
            )
            if not mitre_id:
                continue

            # normalize ID (remove subtechnique part for tactic mapping if needed, or keep as is)
            base_id = mitre_id.split('.')[0]
            
            tactic = get_tactic(
                base_id
            )

            tactic_counts[tactic].add(mitre_id)
            detected_techniques.add(mitre_id)

        # --------------------------------------------
        # BUILD COVERAGE %
        # --------------------------------------------

        coverage = {}

        for tactic, techniques in tactic_counts.items():
            total_known = TACTIC_TECHNIQUE_COUNTS.get(tactic, 10) # default fallback
            coverage[tactic] = round(
                (len(techniques) / total_known) * 100,
                2
            )
            
        # --------------------------------------------
        # SIMULATED DETECTION RATE
        # --------------------------------------------
        
        from bas_engine.detection.sigma_generator import SigmaGenerator
        supported_tactics = SigmaGenerator().supported_tactics
        
        rules_matched = 0
        for tech in detected_techniques:
            if tech in supported_tactics or tech.split('.')[0] in supported_tactics:
                rules_matched += 1
                
        simulated_detection_rate = 0.0
        if detected_techniques:
            simulated_detection_rate = round(
                (rules_matched / len(detected_techniques)) * 100,
                2
            )

        return {

            "total_findings":
                len(findings),
                
            "techniques_tested":
                len(detected_techniques),

            "tactics_detected":
                len(tactic_counts),

            "coverage":
                coverage,
                
            "simulated_detection_rate": simulated_detection_rate,
            "sigma_rules_matched": rules_matched
        }