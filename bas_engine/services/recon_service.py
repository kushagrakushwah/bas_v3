"""
Recon Service

Handles:
- subnet discovery
- nmap orchestration
- host intelligence
"""

import asyncio
import re
import ipaddress
import nmap
import logging
import socket

from typing import Dict, List

from bas_engine.core.recon.service_classifier import (
    ServiceClassifier
)

classifier = ServiceClassifier()
logger = logging.getLogger("secureforge.recon")

# ---------------------------------------------------------------------------
# Input validation helpers — fix C2: command injection via nmap args
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

# SSRF denylist — RFC-1918, loopback, link-local
_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


async def _validate_target(target: str) -> str:
    """
    Validate the nmap target.  Raises ValueError on:
    - empty / whitespace
    - shell metacharacters
    - internal / loopback / cloud-metadata IP ranges
    Returns the cleaned target string.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    # Reject shell metacharacters — primary command injection guard
    forbidden = set(";|&`$(){}\\<>'\"\n\r\t")
    if any(c in forbidden for c in target):
        raise ValueError(f"Target contains forbidden characters: {target!r}")

    # Check if it looks like an IP / CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        for internal in _INTERNAL_NETS:
            if net.overlaps(internal):
                raise ValueError(
                    f"Target {target!r} resolves to a private/internal range "
                    "and is blocked for SSRF protection."
                )
        return target
    except ValueError as exc:
        # If it was the SSRF block, re-raise
        if "private" in str(exc) or "internal" in str(exc) or "blocked" in str(exc):
            raise
        pass  # Not an IP — fall through to hostname check

    # Validate as hostname
    # Strip leading scheme if present
    clean = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    if not _HOSTNAME_RE.match(clean):
        raise ValueError(f"Target {target!r} is not a valid hostname or IP address.")

    # Prevent SSRF via DNS resolution
    try:
        ip_str = await asyncio.to_thread(socket.gethostbyname, clean)
        ip_obj = ipaddress.ip_address(ip_str)
        for internal in _INTERNAL_NETS:
            if ip_obj in internal:
                raise ValueError(
                    f"Target {target!r} resolves to a private/internal range ({ip_str}) "
                    "and is blocked for SSRF protection."
                )
    except socket.gaierror:
        # If DNS resolution fails, we allow it (will fail at nmap execution)
        pass

    return target


def _validate_ports(ports: str) -> str:
    """Validate port specification to prevent command injection."""
    ports = ports.strip()
    if not _PORTS_RE.match(ports):
        raise ValueError(
            f"Port specification {ports!r} is invalid. "
            "Use formats like '80', '1-1000', or '22,80,443'."
        )
    # Enforce individual port values are in range
    for part in ports.split(","):
        bounds = part.split("-")
        for b in bounds:
            val = int(b)
            if not (1 <= val <= 65535):
                raise ValueError(f"Port {val} is out of range (1-65535).")
    return ports


class ReconService:

    async def discover_subnet(

        self,
        target: str,
        ports: str = "1-1000",

    ) -> List[Dict]:

        # Validate inputs before passing to nmap — fix C2
        try:
            target = await _validate_target(target)
            ports = _validate_ports(ports)
        except ValueError as e:
            logger.warning(f"ReconService rejected invalid input: {e}")
            return []

        scanner = nmap.PortScanner()

        loop = asyncio.get_running_loop()

        await loop.run_in_executor(

            None,

            lambda: scanner.scan(

                hosts=target,

                ports=ports,

                arguments="-sT -sV -Pn -T4"
            )
        )

        results = []

        for host in scanner.all_hosts():

            host_data = {

                "host": host,

                "hostname": (
                    scanner[host]
                    .hostname()
                ),

                "state": (
                    scanner[host]
                    .state()
                ),

                "os": "Unknown",

                "ports": []
            }

            if "tcp" in scanner[host]:

                for port in (

                    scanner[host]["tcp"]
                ):

                    service = (

                        scanner[host]["tcp"][port]
                    )

                    classified = (
                        classifier.classify(
                            port,
                            service.get(
                                "product",
                                ""
                            )
                        )
                    )

                    host_data["ports"].append(
                        classified
                    )

            results.append(host_data)

        return results