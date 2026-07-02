"""
Attack Recommendation Engine

Maps:
- ports
- services
- banners

to:
- BAS attack modules
- recon actions
- validation workflows
"""

from typing import Dict, List


PORT_ATTACK_MAP = {
    22: ["ssh_bruteforce", "privilege_escalation"],
    80: ["waf_evasion", "owasp_web", "apt_killchain", "vuln_scanner"],
    443: ["waf_evasion", "owasp_web", "apt_killchain", "vuln_scanner"],
    8080: ["waf_evasion", "owasp_web", "vuln_scanner"],
}


class AttackRecommender:

    def recommend_by_port(
        self,
        port: int,
    ) -> List[str]:
        from bas_engine.attack_modules.registry import MODULE_REGISTRY
        attacks = PORT_ATTACK_MAP.get(port, [])
        return [attack for attack in attacks if attack in MODULE_REGISTRY]

    def recommend_for_host(

        self,
        open_ports: List[int],
    ) -> Dict[int, List[str]]:

        recommendations = {}

        for port in open_ports:

            recommendations[port] = (
                self.recommend_by_port(port)
            )

        return recommendations