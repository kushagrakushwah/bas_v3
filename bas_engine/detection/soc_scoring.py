from bas_engine.detection.coverage_engine import (
    CoverageEngine
)
from bas_engine.detection.constants import MITRE_ATTACK_TACTICS
import math

class SOCScoringEngine:

    def __init__(self):

        self.coverage_engine = CoverageEngine()

    # ------------------------------------------------
    # CALCULATE SOC SCORE
    # ------------------------------------------------

    def calculate_score(
        self,
        findings: list,
        executed_modules: list = None
    ):
        if executed_modules is None:
            executed_modules = []

        coverage_data = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        coverage = coverage_data[
            "coverage"
        ]

        total_findings = coverage_data[
            "total_findings"
        ]

        tactics_detected = coverage_data[
            "tactics_detected"
        ]
        
        simulated_detection_rate = coverage_data.get("simulated_detection_rate", 0.0)

        if len(executed_modules) == 0:
            return {
                "exposure_score": 0,
                "detection_score": 0,
                "nist_maturity_tier": "Tier 1: Minimal",
                "coverage_strength": f"{tactics_detected} tactics",
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0,
                "blind_spots": len(MITRE_ATTACK_TACTICS),
                "coverage": coverage,
                "simulated_detection_rate": 0.0
            }

        # --------------------------------------------
        # SEVERITY ANALYSIS
        # --------------------------------------------

        critical = 0
        high = 0
        medium = 0
        low = 0

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    ""
                )
            ).lower()

            if severity == "critical":
                critical += 1

            elif severity == "high":
                high += 1

            elif severity == "medium":
                medium += 1

            elif severity == "low":
                low += 1

        # --------------------------------------------
        # EXPOSURE SCORE
        # --------------------------------------------
        
        exposure_raw = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
        # log-normalize the exposure score to 0-100
        if exposure_raw > 0:
            exposure_score = min(round((math.log10(exposure_raw) / 2) * 100, 2), 100)
        else:
            exposure_score = 0.0
            
        # --------------------------------------------
        # ENTERPRISE SOC DETECTION CAPABILITY (SIMULATED)
        # --------------------------------------------
        
        # In a real enterprise, detection relies on Logging Gaps. We simulate this by checking
        # if the tactics detected fall into typically high-visibility logs (e.g. process_creation)
        # vs low-visibility logs (e.g. network scanning).
        
        high_visibility_tactics = {"TA0002", "TA0003", "TA0004", "TA0005"}
        
        # Calculate D3FEND mappings based on simulated detection
        d3fend_mappings = []
        logging_gaps = []
        
        for tactic in coverage.keys():
            if tactic in high_visibility_tactics:
                d3fend_mappings.append(f"D3-PRA (Process Analysis) for {tactic}")
            else:
                logging_gaps.append(f"Missing deep visibility for {tactic} (e.g. Zeek/Sysmon)")

        # Refined detection score based on the Sigma rule match rate and severity weighting
        detection_score = round(simulated_detection_rate * (1.0 if critical > 0 else 0.8), 2)
        
        if detection_score < 20:
            nist_tier = "Tier 1: Partial / Minimal Logging"
        elif detection_score < 50:
            nist_tier = "Tier 2: Risk Informed / Basic SIEM"
        elif detection_score < 75:
            nist_tier = "Tier 3: Repeatable / Active SOC"
        elif detection_score < 90:
            nist_tier = "Tier 4: Adaptive / Advanced Hunt"
        else:
            nist_tier = "Tier 5: Automated / Proactive"

        # --------------------------------------------
        # BLIND SPOTS
        # --------------------------------------------

        blind_spots = max(
            len(MITRE_ATTACK_TACTICS) - tactics_detected,
            0
        )

        return {

            "exposure_score":
                exposure_score,

            "detection_score":
                detection_score,

            "nist_maturity_tier":
                nist_tier,

            "coverage_strength":
                f"{tactics_detected} tactics",
                
            "d3fend_mappings": d3fend_mappings,
            "logging_gaps": logging_gaps,

            "critical_findings":
                critical,

            "high_findings":
                high,

            "medium_findings":
                medium,

            "low_findings":
                low,

            "blind_spots":
                blind_spots,

            "coverage":
                coverage,
                
            "simulated_detection_rate": simulated_detection_rate
        }