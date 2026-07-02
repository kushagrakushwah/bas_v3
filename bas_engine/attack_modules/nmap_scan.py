import asyncio
import ipaddress
import socket
import re
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class NmapScanModule(BaseAttackModule):
    MODULE_NAME  = "nmap_scan"
    DESCRIPTION  = "Full native Nmap scanner: subnet discovery, service fingerprinting, OS detection (T1046)"
    MITRE_TACTIC = "Discovery"
    MITRE_IDS    = ["T1046", "T1590", "T1595"]

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _parse_target(self, target: str) -> Tuple[str, bool]:
        """Return (host_or_cidr, is_cidr)."""
        t = target.strip()
        if t.startswith(("http://", "https://")):
            t = urlparse(t).hostname or t
        try:
            ipaddress.ip_network(t, strict=False)
            return t, "/" in t
        except ValueError:
            return t, False

    def _get_ports(self, profile: str, custom: Optional[str]) -> str:
        if custom:
            return custom
        
        profiles = {
            "quick": "21,22,23,80,443,445,3306,3389,5432,6379,8080,9200,27017",
            "standard": "top-ports 100", # Nmap syntax for top 100
            "full": "1-65535",
            "web": "80,443,8080,8443,8888,3000,4200,5000,8500,15672",
            "db": "1433,1521,3306,5432,6379,7474,9042,27017,5984,11211",
            "devops": "2375,2376,6443,10250,2379,9090,3100,8500,4646,9092,2181",
        }
        return profiles.get(profile, "top-ports 100")

    async def _run_nmap(self, target: str, ports: str, timing: str, subnet: bool) -> str:
        # Build arguments
        args = ["nmap", "-oX", "-"]
        
        if timing in ["T2", "T3", "T4", "T5"]:
            args.append(f"-{timing}")
        else:
            args.append("-T4")
            
        if subnet:
            args.extend(["-sn"]) # Ping scan only for subnet discovery
        else:
            args.extend(["-sV", "--version-intensity", "5"]) # Service fingerprinting
            if ports.startswith("top-ports"):
                parts = ports.split(" ")
                top_n = parts[1] if len(parts) > 1 and parts[1].isdigit() else "100"
                args.extend(["--top-ports", top_n])
            else:
                args.extend(["-p", ports])
                
        args.append(target)
        
        self.logger.info(f"[{self.MODULE_NAME}] Running: {' '.join(args)}")
        
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            self.logger.warning(f"Nmap returned non-zero exit code {proc.returncode}. Stderr: {stderr.decode()}")
            
        return stdout.decode(errors="replace")

    def _parse_nmap_xml(self, xml_data: str) -> List[Dict]:
        hosts = []
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall('host'):
                if host.find('status').get('state') != 'up':
                    continue
                    
                host_info = {
                    "ip": "",
                    "hostname": "",
                    "ports": []
                }
                
                # Get IP
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        host_info["ip"] = address.get('addr')
                        
                # Get Hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hname in hostnames.findall('hostname'):
                        host_info["hostname"] = hname.get('name')
                        break # Just take the first one
                        
                # Get Ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is None or state.get('state') != 'open':
                            continue
                            
                        port_id = int(port.get('portid'))
                        service = port.find('service')
                        
                        svc_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        svc_product = service.get('product', '') if service is not None else ''
                        svc_version = service.get('version', '') if service is not None else ''
                        
                        banner = f"{svc_product} {svc_version}".strip()
                        
                        severity = Severity.LOW
                        # Simple severity mapping based on port/service
                        critical_ports = {1433, 1521, 2375, 2379, 6379, 9200, 9300, 10250, 11211, 27017}
                        high_ports = {21, 23, 135, 139, 161, 389, 445, 3306, 3389, 5432, 5900}
                        
                        if port_id in critical_ports:
                            severity = Severity.CRITICAL
                        elif port_id in high_ports:
                            severity = Severity.HIGH
                        elif port_id > 1024:
                            severity = Severity.MEDIUM
                            
                        host_info["ports"].append({
                            "port": port_id,
                            "service": svc_name,
                            "banner": banner,
                            "severity": severity
                        })
                        
                hosts.append(host_info)
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            
        return hosts

    def _build_findings(self, target_display: str, host_data: dict, duration: float) -> List[Finding]:
        findings = []
        ip = host_data.get("ip", target_display)
        open_ports = host_data.get("ports", [])
        
        if not open_ports:
            findings.append(self.finding(
                title       = f"No Open Ports on {target_display}",
                description = f"TCP scan found no open ports on {target_display}.",
                severity    = Severity.INFO,
                mitre_id    = "T1046",
                evidence    = f"Nmap scan completed in <{duration:.1f}s",
                remediation = "Host is secure or firewalled.",
            ))
            return findings

        critical_ports, high_ports = [], []
        for p in open_ports:
            port = p["port"]
            service = p["service"]
            severity = p["severity"]
            banner = p["banner"]
            
            banner_note = f"\n\nBanner/Version: `{banner}`" if banner else ""
            if severity == Severity.CRITICAL:
                critical_ports.append(port)
            elif severity == Severity.HIGH:
                high_ports.append(port)

            findings.append(self.finding(
                title       = f"Open Port {port}/{service} on {target_display}",
                description = (
                    f"Port **{port}** ({service}) is open on {target_display}. "
                    f"{banner_note}"
                ),
                severity    = severity,
                mitre_id    = "T1046",
                evidence    = f"Nmap connected to {ip}:{port} and fingerprinted service.",
                remediation = (
                    f"1. Confirm {service} on port {port} is intentionally exposed.\n"
                    "2. Apply firewall rules — restrict to trusted source IPs only.\n"
                    "3. Enable authentication, encryption, and audit logging."
                ),
                raw_data    = {
                    "host": target_display,
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "banner": banner,
                },
            ))

        # Attack surface summary
        findings.append(self.finding(
            title       = f"Attack Surface Summary — {target_display}",
            description = (
                f"Scan completed in **{duration:.1f}s** | "
                f"Open ports: **{len(open_ports)}** | "
                f"Critical: **{len(critical_ports)}** | "
                f"High: **{len(high_ports)}**\n\n"
                f"Open: {[p['port'] for p in open_ports]}\n"
                + (f"\nCritical risk ports: {critical_ports}" if critical_ports else "")
            ),
            severity    = Severity.CRITICAL if critical_ports else (Severity.HIGH if high_ports else Severity.MEDIUM),
            mitre_id    = "T1590",
            evidence    = f"Nmap scan result for {target_display}",
            remediation = "Review exposed services and apply segmentation.",
            raw_data    = {
                "host": target_display,
                "ip": ip,
                "open_ports": [p['port'] for p in open_ports],
                "critical_ports": critical_ports,
                "scan_duration_sec": round(duration, 2),
            },
        ))

        return findings

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []

        resolved = await self.resolve_target()
        raw_target = resolved.original.strip()
        target, is_cidr = self._parse_target(raw_target)

        all_options = getattr(self, "options", {}) or {}
        options = all_options.get("nmap_scan", all_options)
        
        profile = options.get("profile", "standard").lower()
        custom_ports = options.get("ports", None)
        timing = options.get("timing", "T4")
        subnet_scan = options.get("subnet_scan", False)

        ports = self._get_ports(profile, custom_ports)
        
        self.logger.info(f"[{self.MODULE_NAME}] Target={target} | Ports={ports} | Timing={timing} | Subnet={is_cidr or subnet_scan}")
        await self.emit_event("INFO", f"[NMAP] Starting scan on {target}")

        t0 = time.monotonic()
        
        if is_cidr or subnet_scan:
            cidr = target if is_cidr else target + "/24"
            xml_data = await self._run_nmap(cidr, ports, timing, subnet=True)
            hosts = self._parse_nmap_xml(xml_data)
            
            live_hosts = [h["ip"] for h in hosts if h["ip"]]
            if not live_hosts:
                findings.append(self.finding(
                    title       = f"No Live Hosts Found in {cidr}",
                    description = f"Nmap ping scan found no responsive hosts in {cidr}.",
                    severity    = Severity.INFO,
                    mitre_id    = "T1046",
                    evidence    = f"Probed {cidr} with Nmap -sn",
                    remediation = "Subnet may be firewalled or offline.",
                ))
                return findings
                
            findings.append(self.finding(
                title       = f"Subnet Discovery: {len(live_hosts)} Live Hosts in {cidr}",
                description = (
                    f"Found **{len(live_hosts)}** live hosts in `{cidr}`:\n\n"
                    + "\n".join(f"- `{ip}`" for ip in sorted(live_hosts))
                ),
                severity    = Severity.MEDIUM,
                mitre_id    = "T1590",
                evidence    = f"Nmap ping sweep across {cidr}",
                remediation = "Review all discovered hosts.",
                raw_data    = {"cidr": cidr, "live_hosts": live_hosts},
            ))
            
            # Now scan the live hosts
            for ip in live_hosts:
                h_t0 = time.monotonic()
                h_xml = await self._run_nmap(ip, ports, timing, subnet=False)
                h_data = self._parse_nmap_xml(h_xml)
                if h_data:
                    findings.extend(self._build_findings(ip, h_data[0], time.monotonic() - h_t0))
                    
        else:
            xml_data = await self._run_nmap(target, ports, timing, subnet=False)
            hosts = self._parse_nmap_xml(xml_data)
            
            if not hosts:
                findings.append(self.finding(
                    title       = f"Host Down: {target}",
                    description = f"Nmap could not reach or find open ports on `{target}`.",
                    severity    = Severity.INFO,
                    mitre_id    = "T1046",
                    evidence    = "Nmap scan returned 0 hosts up.",
                    remediation = "Verify the hostname/IP is correct and reachable.",
                ))
                return findings
                
            findings.extend(self._build_findings(target, hosts[0], time.monotonic() - t0))

        return findings
