from dataclasses import dataclass
from urllib.parse import urlparse
import socket
import ipaddress


@dataclass
class ResolvedTarget:
    original: str
    hostname: str | None
    ip: str
    scheme: str | None
    port: int | None
    url: str | None


class DNSResolver:

    @staticmethod
    async def resolve(target: str):

        original = target

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        parsed = urlparse(target)

        hostname = parsed.hostname
        scheme = parsed.scheme
        port = parsed.port

        try:
            ipaddress.ip_address(hostname)

            ip = hostname

        except ValueError:

            ip = socket.gethostbyname(hostname)

        return ResolvedTarget(
            original=original,
            hostname=hostname,
            ip=ip,
            scheme=scheme,
            port=port,
            url=target
        )