"""
Impact Simulation – SAFE (discovery only)
MITRE ATT&CK: T1083, T1071

Read‑only discovery of accessible storage paths and C2 beacon patterns.
No encryption, no DDoS, no system changes.
"""

import asyncio
import aiohttp
import logging
from typing import List

from bas_engine.attack_modules.utils.endpoint_validator import is_real_endpoint
from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.impact.safe")


class ImpactSimModule(BaseAttackModule):
    MODULE_NAME  = "impact_sim"
    DESCRIPTION  = "Impact simulation (safe, discovery only)"
    MITRE_TACTIC = "Impact"
    MITRE_IDS    = ["T1083", "T1071"]

    FILE_DISCOVERY_PATHS = [
        "/uploads", "/files", "/documents", "/backup", "/data",
        "/export", "/images", "/assets", "/media", "/storage"
    ]
    C2_PATHS = ["/c2/beacon", "/update/check", "/api/register", "/ping"]

    async def execute(self) -> List[Finding]:
        findings = []
        resolved = await self.resolve_target()
        target = self.build_target_url(resolved, default_scheme="https")

        findings.extend(await self._stage_discovery(target))
        return findings

    async def _stage_discovery(self, target: str) -> List[Finding]:
        findings = []
        discovered = []

        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for Impact Sim (Safe)")
        connector = aiohttp.TCPConnector(ssl=ssl_verify)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "SecureForge-BAS/1.0"}
        ) as session:
            for path in self.FILE_DISCOVERY_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 403):
                            real = await is_real_endpoint(session, target, path)
                            if real:
                                discovered.append(path)
                                await self.emit_event("INFO", f"[DISCOVERED] Storage path reachable: {path}")
                except Exception:
                    pass
                await asyncio.sleep(0.2)

            if discovered:
                findings.append(self.finding(
                    title="Accessible Storage Paths Found",
                    description=f"Discovered {len(discovered)} accessible paths: {', '.join(discovered)}",
                    severity=Severity.HIGH,
                    mitre_id="T1083",
                    evidence=str(discovered),
                    remediation="Restrict web access to storage directories.",
                    mode="safe",
                    evidence_type="discovery"
                ))

            # C2 beacon check (read‑only)
            for path in self.C2_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        real = await is_real_endpoint(session, target, path)
                        if real:
                            await self.emit_event("INFO", f"[DISCOVERED] Potential C2 beacon endpoint: {path}")
                            findings.append(self.finding(
                                title=f"Potential C2 Endpoint Reachable: {path}",
                                description=f"Path '{path}' returned HTTP {resp.status}.",
                                severity=Severity.CRITICAL,
                                mitre_id="T1071",
                                evidence=f"GET {url} → {resp.status}",
                                remediation="Block outbound to unknown endpoints.",
                                mode="safe",
                                evidence_type="discovery"
                            ))
                except Exception:
                    pass
                await asyncio.sleep(0.2)

        return findings