"""
Privilege Escalation – SAFE enumeration only
MITRE ATT&CK: T1068, T1548, T1574

This module performs read‑only checks on Linux and Windows.
No files are modified, no exploits are executed.
"""

import asyncio
import os
import stat
import logging
import platform
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.privesc.safe")


class PrivEscModule(BaseAttackModule):
    MODULE_NAME  = "privilege_escalation"
    DESCRIPTION  = "Privilege escalation enumeration (safe, read‑only)"
    MITRE_TACTIC = "Privilege Escalation"
    MITRE_IDS    = ["T1068", "T1548", "T1548.001", "T1574.009"]

    async def execute(self) -> List[Finding]:
        findings = []
        
        if not self.options.get("ssh_user"):
            findings.append(self.finding(
                title="Target Execution Blocked",
                description="Target execution requires 'ssh_user' and password/key in options.",
                severity=Severity.INFO,
                mitre_id="N/A",
                evidence="No SSH credentials provided.",
                remediation="Configure the module with ssh_user and ssh_pass/ssh_key.",
                mode="safe",
                evidence_type="enumeration"
            ))
            return findings

        try:
            uname = await self._run_cmd("uname -a")
            system = "Linux" if "Linux" in uname else "Windows"
        except Exception as e:
            logger.error(f"Failed to connect to target: {e}")
            findings.append(self.finding(
                title="SSH Connection Failed",
                description=f"Could not connect to target: {str(e)}",
                severity=Severity.INFO,
                mitre_id="N/A",
                evidence=str(e),
                remediation="Verify target SSH port and credentials.",
                mode="safe",
                evidence_type="enumeration"
            ))
            return findings

        if system == "Linux":
            findings.extend(await self._linux_checks())
        elif system == "Windows":
            findings.extend(await self._windows_checks())
        return findings

    # ─── Linux Checks ─────────────────────────────────────────────

    async def _linux_checks(self) -> List[Finding]:
        findings = []
        await self.emit_event("INFO", "[ENUMERATION] Checking SUID binaries...")
        findings.extend(await self._check_suid_binaries())
        await self.emit_event("INFO", "[ENUMERATION] Checking sudo rules...")
        findings.extend(await self._check_sudo_rules())
        await self.emit_event("INFO", "[ENUMERATION] Checking writable paths...")
        findings.extend(await self._check_writable_paths())
        await self.emit_event("INFO", "[ENUMERATION] Checking cron jobs...")
        findings.extend(await self._check_cron_jobs())
        await self.emit_event("INFO", "[ENUMERATION] Checking Docker group...")
        findings.extend(await self._check_docker_group())
        await self.emit_event("INFO", "[ENUMERATION] Checking kernel version...")
        findings.extend(await self._check_kernel_version())
        return findings

    async def _check_suid_binaries(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "find / -perm -4000 -type f 2>/dev/null | head -50"
            )
            known_safe = {
                "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                "/bin/mount", "/bin/umount", "/usr/bin/newgrp",
                "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
            }
            unusual = [
                line.strip() for line in result.splitlines()
                if line.strip() and line.strip() not in known_safe
            ]
            if unusual:
                findings.append(self.finding(
                    title="Unusual SUID Binaries Present",
                    description=f"{len(unusual)} non‑standard SUID binaries found.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1548.001",
                    evidence=str(unusual[:10]),
                    remediation="Audit all SUID binaries and remove unnecessary bits.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"SUID check failed: {e}")
        return findings

    async def _check_sudo_rules(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("sudo -l -n 2>/dev/null || true")
            if "NOPASSWD" in result:
                findings.append(self.finding(
                    title="Passwordless sudo Rules Configured",
                    description="NOPASSWD entries found – privilege escalation risk.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1548.003",
                    evidence=result[:500],
                    remediation="Remove NOPASSWD from /etc/sudoers.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
            elif "ALL" in result and "(ALL)" in result:
                findings.append(self.finding(
                    title="Unrestricted sudo Access",
                    description="User has full sudo access (ALL).",
                    severity=Severity.HIGH,
                    mitre_id="T1548.003",
                    evidence=result[:500],
                    remediation="Restrict sudo rules to specific commands.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"sudo check failed: {e}")
        return findings

    async def _check_writable_paths(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null"
            )
            if result.strip():
                writable = [l.strip() for l in result.splitlines() if l.strip()]
                findings.append(self.finding(
                    title="Writable Directories in PATH",
                    description=f"{len(writable)} PATH directories are writable.",
                    severity=Severity.HIGH,
                    mitre_id="T1574.007",
                    evidence=str(writable),
                    remediation="Remove world‑writable directories from PATH.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"PATH writable check failed: {e}")
        return findings

    async def _check_cron_jobs(self) -> List[Finding]:
        findings = []
        try:
            # Find world-writable cron files remotely via SSH
            result = await self._run_cmd(
                "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly "
                "/var/spool/cron -maxdepth 1 -type f -perm -o+w 2>/dev/null"
            )
            world_writable = [l.strip() for l in result.splitlines() if l.strip()]
            if world_writable:
                findings.append(self.finding(
                    title="World‑Writable Cron Files",
                    description=f"{len(world_writable)} cron files are world‑writable on the target.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1053.003",
                    evidence=str(world_writable),
                    remediation="chmod 644 /etc/cron.d/* && chown root:root /etc/cron.d/*",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"Cron check failed: {e}")
        return findings

    async def _check_docker_group(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("id")
            if "docker" in result:
                findings.append(self.finding(
                    title="User in Docker Group",
                    description="Docker group membership allows root‑equivalent access.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1611",
                    evidence=result.strip(),
                    remediation="Remove non‑admin users from docker group.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"Docker group check failed: {e}")
        return findings

    async def _check_kernel_version(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("uname -r")
            kernel = result.strip()
            parts = kernel.split(".")
            if len(parts) >= 2:
                major, minor = int(parts[0]), int(parts[1].split("-")[0])
                if major < 5 or (major == 5 and minor < 15):
                    findings.append(self.finding(
                        title=f"Potentially Vulnerable Kernel: {kernel}",
                        description="Kernel predates 5.15 LTS – may have known CVEs.",
                        severity=Severity.HIGH,
                        mitre_id="T1068",
                        evidence=kernel,
                        remediation="Update to latest LTS kernel.",
                        mode="safe",
                        evidence_type="enumeration"
                    ))
        except Exception as e:
            logger.debug(f"Kernel version check failed: {e}")
        return findings

    # ─── Windows Checks ───────────────────────────────────────────

    async def _windows_checks(self) -> List[Finding]:
        findings = []
        findings.extend(await self._check_unquoted_service_paths())
        findings.extend(await self._check_always_install_elevated())
        findings.extend(await self._check_privileged_groups())
        return findings

    async def _check_unquoted_service_paths(self) -> List[Finding]:
        findings = []
        try:
            ps_script = """
            Get-WmiObject Win32_Service | Where-Object { $_.PathName -match '^[^"]* .*' -and $_.PathName -notmatch '^"' } |
            Select-Object Name, PathName
            """
            result = await self._run_powershell(ps_script)
            if result.strip():
                findings.append(self.finding(
                    title="Unquoted Service Paths Detected",
                    description="Services with unquoted paths containing spaces.",
                    severity=Severity.HIGH,
                    mitre_id="T1574.009",
                    evidence=result[:1000],
                    remediation="Enclose service paths in double quotes.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"Unquoted service path check failed: {e}")
        return findings

    async def _check_always_install_elevated(self) -> List[Finding]:
        findings = []
        try:
            ps_script = """
            Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue |
            Select-Object AlwaysInstallElevated
            """
            result = await self._run_powershell(ps_script)
            if "True" in result:
                findings.append(self.finding(
                    title="AlwaysInstallElevated Policy Enabled",
                    description="MSI packages can install with SYSTEM privileges.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1548.002",
                    evidence=result,
                    remediation="Disable AlwaysInstallElevated in Group Policy.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"AlwaysInstallElevated check failed: {e}")
        return findings

    async def _check_privileged_groups(self) -> List[Finding]:
        findings = []
        try:
            ps_script = """
            $groups = 'Administrators', 'Domain Admins', 'Enterprise Admins'
            foreach ($g in $groups) {
                $members = net localgroup $g 2>$null | Where-Object { $_ -match '^\\S' -and $_ -notmatch 'command|Alias' } | Select-Object -Skip 4
                if ($members) {
                    Write-Output "Group: $g`n$members`n"
                }
            }
            """
            result = await self._run_powershell(ps_script)
            if result.strip():
                findings.append(self.finding(
                    title="User in Privileged Group",
                    description=f"Current user is in a privileged group:\n{result}",
                    severity=Severity.MEDIUM,
                    mitre_id="T1078",
                    evidence=result[:1000],
                    remediation="Review privileged group membership.",
                    mode="safe",
                    evidence_type="enumeration"
                ))
        except Exception as e:
            logger.debug(f"Privileged groups check failed: {e}")
        return findings

    # ─── Helpers ──────────────────────────────────────────────────

    async def _run_cmd(self, cmd: str) -> str:
        ssh_user = self.options.get("ssh_user")
        ssh_pass = self.options.get("ssh_pass")
        ssh_key = self.options.get("ssh_key")
        ssh_port = int(self.options.get("ssh_port", 22))

        if not ssh_user:
            raise ValueError("Target execution requires 'ssh_user' in options.")

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

    async def _run_powershell(self, command: str) -> str:
        cmd = f"powershell -NoProfile -Command \"{command}\""
        return await self._run_cmd(cmd)