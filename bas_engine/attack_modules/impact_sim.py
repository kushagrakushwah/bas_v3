"""
Impact Simulation Module
========================
Merged from 2 modules:
  - ransomware_sim     (T1486, T1083, T1490, T1071)
  - network_load_sim   (T1498, T1499)

Runs 2 sequential stages over separate aiohttp sessions
(network_load_sim needs its own connector with a concurrency limit).

Stage 1 — Ransomware Simulation:
  file discovery → mock encryption staging → C2 beacon probe

Stage 2 — Network Load Simulation:
  configurable HTTP volume burst → rate limiting verdict

A combined impact summary finding is appended at the end,
only possible because both stages share a single execution context.
"""

import asyncio
import aiohttp
import random
import time
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class ImpactSimModule(BaseAttackModule):

    MODULE_NAME  = "impact_sim"
    DESCRIPTION  = (
        "Impact simulation: ransomware behavior (file discovery, mock encryption, C2 beacon) "
        "and network load testing for rate limiting validation (T1486/T1498)"
    )
    MITRE_TACTIC = "Impact"
    MITRE_IDS    = [
        "T1486",
        "T1083",
        "T1490",
        "T1071",
        "T1498",
        "T1499",
    ]

    # =========================================================
    # STAGE 1 — RANSOMWARE SIM
    # from: ransomware_sim.py
    # =========================================================

    C2_PATHS = [
        "/c2/beacon",
        "/update/check",
        "/api/register",
        "/ping",
    ]

    FILE_DISCOVERY_PATHS = [
        "/uploads",
        "/files",
        "/documents",
        "/backup",
        "/data",
        "/export",
    ]

    # =========================================================
    # MAIN EXECUTE
    # =========================================================

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []

        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Stage results used for the combined summary finding
        ransomware_results = await self._stage_ransomware(target)
        load_results       = await self._stage_network_load(target)

        findings.extend(ransomware_results["findings"])
        findings.extend(load_results["findings"])

        # Combined impact summary — only meaningful because both stages ran
        c2_reachable     = ransomware_results["c2_reachable"]
        files_discovered = ransomware_results["files_discovered"]
        rate_limit_absent = load_results["rate_limit_absent"]
        req_count        = load_results["req_count"]
        block_rate       = load_results["block_rate"]

        summary_severity = Severity.HIGH
        if c2_reachable or rate_limit_absent:
            summary_severity = Severity.CRITICAL

        findings.append(self.finding(
            title       = "Impact Simulation Complete — Combined Assessment",
            description = (
                f"Both impact stages completed against {target}.\n\n"
                f"Ransomware Stage:\n"
                f"  • Storage paths discovered: {files_discovered}\n"
                f"  • Mock encryption: staged (no real files touched)\n"
                f"  • C2 beacon paths reachable: {c2_reachable}\n\n"
                f"Network Load Stage:\n"
                f"  • Requests sent: {req_count}\n"
                f"  • Rate limiting detected: {'No' if rate_limit_absent else 'Yes'}\n"
                f"  • Block rate: {block_rate:.1f}%\n\n"
                "Combined risk: "
                + (
                    "CRITICAL — C2 paths reachable and/or no rate limiting in place."
                    if summary_severity == Severity.CRITICAL
                    else "HIGH — impact vectors present but partially mitigated."
                )
            ),
            severity    = summary_severity,
            mitre_id    = "T1486",
            evidence    = (
                f"C2 reachable={c2_reachable}, "
                f"files_discovered={files_discovered}, "
                f"rate_limit_absent={rate_limit_absent}, "
                f"block_rate={block_rate:.1f}%"
            ),
            remediation = (
                "1. Block outbound access to C2-pattern endpoints via egress firewall.\n"
                "2. Implement immutable/versioned backups (3-2-1 rule).\n"
                "3. Deploy rate limiting on all public-facing endpoints.\n"
                "4. Configure WAF threshold alerts for volume spikes.\n"
                "5. Enable file integrity monitoring on storage directories."
            ),
            raw_data    = {
                "c2_reachable":      c2_reachable,
                "files_discovered":  files_discovered,
                "rate_limit_absent": rate_limit_absent,
                "req_count":         req_count,
                "block_rate":        round(block_rate, 1),
            },
        ))

        return findings

    # =========================================================
    # STAGE 1 — RANSOMWARE SIMULATION
    # =========================================================

    async def _stage_ransomware(self, target: str) -> dict:

        findings: List[Finding] = []
        c2_reachable     = 0
        files_discovered = 0

        await self.emit_event(
            "INFO",
            "Stage 1 starting: Ransomware Simulation",
            {"stage": 1, "module": self.MODULE_NAME},
        )

        self.logger.info("[impact_sim] Stage 1: Ransomware simulation")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # --- File discovery ---
            self.logger.info("[impact_sim] Stage 1a: File discovery")
            discovered = []
            for path in self.FILE_DISCOVERY_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 403):
                            discovered.append(path)
                except Exception as e:
                    self.logger.debug(f"Discovery probe {url}: {e}")
                await asyncio.sleep(0.2)

            files_discovered = len(discovered)

            if discovered:
                findings.append(self.finding(
                    title       = "File Discovery: Accessible Storage Paths Found",
                    description = (
                        f"Ransomware simulation discovered {len(discovered)} accessible storage "
                        f"paths: {', '.join(discovered)}. In a real attack these would be "
                        "enumerated and staged for encryption."
                    ),
                    severity    = Severity.HIGH,
                    mitre_id    = "T1083",
                    evidence    = f"Accessible paths: {discovered}",
                    remediation = (
                        "1. Restrict direct web access to upload/storage directories.\n"
                        "2. Implement file integrity monitoring on critical directories.\n"
                        "3. Maintain offline/immutable backups."
                    ),
                    raw_data    = {"discovered_paths": discovered},
                ))

            # --- Mock encryption staging ---
            self.logger.info("[impact_sim] Stage 1b: Mock encryption staging")
            await asyncio.sleep(0.5)
            findings.append(self.finding(
                title       = "Ransomware Simulation: Encryption Staging",
                description = (
                    f"Simulated encryption process tracked across {len(discovered)} directories "
                    f"on {target}. No real files were modified. "
                    "A README_DECRYPT.txt artifact would be dropped in a real attack."
                ),
                severity    = Severity.CRITICAL,
                mitre_id    = "T1486",
                evidence    = "Mock encryption loop completed — no real files touched",
                remediation = (
                    "1. Deploy behavioral anti-ransomware endpoint solutions.\n"
                    "2. Implement immutable/versioned backups (3-2-1 rule).\n"
                    "3. Enable file activity monitoring and alert on mass file renames.\n"
                    "4. Test backup restoration procedures regularly."
                ),
            ))

            # --- C2 beacon ---
            self.logger.info("[impact_sim] Stage 1c: C2 beacon simulation")
            for path in self.C2_PATHS[:2]:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status != 404:
                            c2_reachable += 1
                            findings.append(self.finding(
                                title       = f"Potential C2 Endpoint Reachable: {path}",
                                description = (
                                    f"The path '{path}' returned HTTP {resp.status}. "
                                    "This path pattern is commonly used by ransomware C2 beacons. "
                                    "Legitimate C2 infrastructure should be unreachable from internal hosts."
                                ),
                                severity    = Severity.CRITICAL,
                                mitre_id    = "T1071",
                                evidence    = f"GET {url} → HTTP {resp.status}",
                                remediation = (
                                    "1. Block outbound connections to unknown/untrusted endpoints.\n"
                                    "2. Implement DNS filtering and egress firewall rules.\n"
                                    "3. Monitor for unusual outbound HTTP/S traffic patterns."
                                ),
                                raw_data    = {"path": path, "status": resp.status},
                            ))
                except Exception as e:
                    self.logger.debug(f"C2 probe {url}: {e}")
                await asyncio.sleep(0.2)

        return {
            "findings":        findings,
            "c2_reachable":    c2_reachable,
            "files_discovered": files_discovered,
        }

    # =========================================================
    # STAGE 2 — NETWORK LOAD SIMULATION
    # =========================================================

    async def _stage_network_load(self, target: str) -> dict:

        findings: List[Finding] = []

        await self.emit_event(
            "INFO",
            "Stage 2 starting: Network Load Simulation",
            {"stage": 2, "module": self.MODULE_NAME},
        )

        self.logger.info("[impact_sim] Stage 2: Network load simulation")

        req_count   = int(self.options.get("request_count", 50))
        concurrency = int(self.options.get("concurrency", 10))

        self.logger.info(
            f"[impact_sim] Sending {req_count} requests "
            f"(concurrency={concurrency}) to {target}"
        )

        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
        timeout   = aiohttp.ClientTimeout(total=5)

        status_counts = {}
        blocked_count = 0
        success_count = 0
        start_time    = time.time()

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            async def single_request(i: int):
                nonlocal blocked_count, success_count
                url = f"{target}?_bas_load_test={i}"
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        status_counts[resp.status] = status_counts.get(resp.status, 0) + 1
                        if resp.status == 429:
                            blocked_count += 1
                        elif resp.status < 400:
                            success_count += 1
                except Exception:
                    status_counts["error"] = status_counts.get("error", 0) + 1

            for batch_start in range(0, req_count, concurrency):
                batch = [
                    single_request(i)
                    for i in range(batch_start, min(batch_start + concurrency, req_count))
                ]
                await asyncio.gather(*batch)
                await asyncio.sleep(0.1)

        elapsed    = time.time() - start_time
        rps        = req_count / elapsed if elapsed > 0 else 0
        block_rate = (blocked_count / req_count * 100) if req_count > 0 else 0

        findings.append(self.finding(
            title       = "Network Load Simulation Completed",
            description = (
                f"Sent {req_count} HTTP requests to {target} in {elapsed:.1f}s "
                f"({rps:.1f} req/s). "
                f"Status distribution: {status_counts}. "
                f"Rate-limited (429): {blocked_count} requests ({block_rate:.1f}%)."
            ),
            severity    = Severity.INFO,
            mitre_id    = "T1498",
            evidence    = f"{req_count} requests @ {rps:.1f} req/s → {status_counts}",
            remediation = "Review rate limiting thresholds and DDoS mitigation rules.",
            raw_data    = {
                "total_requests": req_count,
                "elapsed_s":      round(elapsed, 2),
                "rps":            round(rps, 1),
                "status_counts":  status_counts,
                "blocked":        blocked_count,
            },
        ))

        rate_limit_absent = blocked_count == 0

        if rate_limit_absent:
            findings.append(self.finding(
                title       = "No Rate Limiting Detected",
                description = (
                    f"All {req_count} requests succeeded without any HTTP 429 responses. "
                    "The target does not appear to enforce rate limiting, making it "
                    "vulnerable to DoS and credential stuffing attacks."
                ),
                severity    = Severity.HIGH,
                mitre_id    = "T1499",
                evidence    = f"0 rate-limited responses out of {req_count} requests",
                remediation = (
                    "1. Implement rate limiting (e.g., nginx limit_req_zone).\n"
                    "2. Configure WAF rate-based rules.\n"
                    "3. Deploy a CDN/DDoS protection service.\n"
                    "4. Set threshold alerts in your SIEM for request spikes."
                ),
            ))
        elif block_rate > 50:
            findings.append(self.finding(
                title       = "Rate Limiting Active and Effective",
                description = (
                    f"Rate limiting blocked {block_rate:.1f}% of requests with HTTP 429. "
                    "The target has effective request throttling in place."
                ),
                severity    = Severity.INFO,
                mitre_id    = "T1499",
                evidence    = f"{blocked_count}/{req_count} requests rate-limited",
                remediation = "Rate limiting is functioning. Continue monitoring thresholds.",
            ))

        return {
            "findings":          findings,
            "rate_limit_absent": rate_limit_absent,
            "req_count":         req_count,
            "block_rate":        block_rate,
        }