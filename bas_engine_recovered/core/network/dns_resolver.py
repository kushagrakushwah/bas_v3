from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse
import asyncio
import socket
import ipaddress


@dataclass
class ResolvedTarget:
    original: str
    hostname: str | None
    ip: str | None
    scheme: str | None
    port: int | None
    url: str | None


class DNSResolver:

    @staticmethod
    async def _resolve_ip(hostname: str, port: int | None) -> str:

        def lookup() -> str:
            infos = socket.getaddrinfo(
                hostname,
                port or 0,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            for info in infos:
                sockaddr = info[4]
                if sockaddr and sockaddr[0]:
                    return sockaddr[0]
            raise socket.gaierror(f"No address found for {hostname}")

        return await asyncio.to_thread(lookup)

    @staticmethod
    async def resolve(target: str):

        original = target

        raw_target = target.strip()

        try:
            network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError:
            network = None

        if network is not None and ("/" in raw_target or raw_target == str(network)):
            return ResolvedTarget(
                original=original,
                hostname=None,
                ip=raw_target,
                scheme=None,
                port=None,
                url=raw_target,
            )

        parsed_input = raw_target if raw_target.startswith(("http://", "https://")) else f"http://{raw_target}"

        parsed = urlparse(parsed_input)

        hostname = parsed.hostname
        scheme = parsed.scheme
        port = parsed.port
        path = parsed.path or ""
        params = parsed.params or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        url = urlunparse((scheme, parsed.netloc, path, params, query, fragment)).rstrip("/")

        if hostname is None:
            return ResolvedTarget(
                original=original,
                hostname=None,
                ip=raw_target,
                scheme=scheme,
                port=port,
                url=url,
            )

        try:
            ipaddress.ip_address(hostname)

            ip = hostname

        except ValueError:

            try:
                ip = await DNSResolver._resolve_ip(hostname, port)
            except Exception:
                ip = hostname

        return ResolvedTarget(
            original=original,
            hostname=hostname,
            ip=ip,
            scheme=scheme,
            port=port,
            url=url,
        )