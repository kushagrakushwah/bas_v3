"""
Shared endpoint discovery helpers for web attack modules.

The helper collects candidate routes from the target root, follows same-domain
links and forms, and falls back to a small set of common routes when discovery
is sparse. It deliberately avoids treating identical fallback HTML as proof of
a real endpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup


DEFAULT_SEEDS: Sequence[str] = (
    "/login",
    "/signin",
    "/admin",
    "/dashboard",
    "/manage",
    "/account",
    "/api",
    "/graphql",
    "/rest",
    "/search",
    "/upload",
    "/uploads",
    "/files",
    "/download",
    "/downloads",
    "/reports",
    "/data",
)


@dataclass(frozen=True)
class DiscoveredEndpoint:
    url: str
    source: str
    status: int


class EndpointDiscoveryEngine:
    def __init__(
        self,
        session,
        target: str,
        *,
        seeds: Optional[Sequence[str]] = None,
        max_endpoints: int = 50,
        max_depth: int = 1,
        timeout: float = 6.0,
    ):
        self.session = session
        self.target = target.rstrip("/")
        self.seeds = list(seeds or DEFAULT_SEEDS)
        self.max_endpoints = max_endpoints
        self.max_depth = max_depth
        self.timeout = timeout
        self._baseline_signature: Optional[str] = None

    @property
    def base_url(self) -> str:
        parsed = urlparse(self.target)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        if "://" in self.target:
            return self.target.rstrip("/")
        return f"https://{self.target.lstrip('/')}".rstrip("/")

    async def discover(self) -> List[str]:
        endpoints: List[DiscoveredEndpoint] = []
        seen = set()

        baseline = await self._fetch(self.base_url)
        if baseline is not None:
            self._baseline_signature = self._signature(baseline[2])

        candidates = []
        if baseline is not None:
            candidates.extend(self._extract_candidates(self.base_url, baseline[2]))

        candidates.extend(urljoin(self.base_url + "/", seed.lstrip("/")) for seed in self.seeds)

        depth = 0
        while candidates and len(endpoints) < self.max_endpoints and depth <= self.max_depth:
            next_candidates = []
            for candidate in candidates:
                if len(endpoints) >= self.max_endpoints:
                    break

                normalized = self._normalize_url(candidate)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)

                response = await self._fetch(normalized)
                if response is None:
                    continue

                status, final_url, body = response
                final_url = self._normalize_url(final_url) or normalized

                if self._is_same_domain(final_url) and self._looks_like_endpoint(status, body):
                    if not self._is_baseline_fallback(body):
                        endpoints.append(
                            DiscoveredEndpoint(
                                url=final_url,
                                source="crawl" if depth else "seed",
                                status=status,
                            )
                        )
                        next_candidates.extend(self._extract_candidates(final_url, body))

            candidates = next_candidates
            depth += 1

        deduped: List[str] = []
        for endpoint in endpoints:
            if endpoint.url not in deduped:
                deduped.append(endpoint.url)
        return deduped

    async def _fetch(self, url: str):
        try:
            async with self.session.get(url, allow_redirects=True, ssl=False, timeout=self.timeout) as resp:
                body = await resp.text(errors="replace")
                return resp.status, str(resp.url), body
        except Exception:
            return None

    def _extract_candidates(self, base_url: str, body: str) -> List[str]:
        soup = BeautifulSoup(body or "", "html.parser")
        candidates = []

        for tag_name, attr_name in (("a", "href"), ("form", "action"), ("link", "href"), ("script", "src")):
            for tag in soup.find_all(tag_name):
                href = tag.get(attr_name)
                if not href:
                    continue
                if href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                full = urljoin(base_url, href)
                full, _ = urldefrag(full)
                if self._is_same_domain(full):
                    candidates.append(full)

        for match in re.findall(r"/(?:api|rest|graphql|admin|login|dashboard|upload|uploads|files|download|downloads|reports|data)[A-Za-z0-9_./?-]*", body or "", re.IGNORECASE):
            full = urljoin(base_url, match)
            full, _ = urldefrag(full)
            if self._is_same_domain(full):
                candidates.append(full)

        return candidates

    def _normalize_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        parsed = urlparse(url)
        if not parsed.scheme:
            return None
        normalized, _ = urldefrag(url)
        return normalized.rstrip("/") if normalized.endswith("/") else normalized

    def _is_same_domain(self, url: str) -> bool:
        parsed_target = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return parsed_url.netloc == parsed_target.netloc

    def _signature(self, body: str) -> str:
        normalized = re.sub(r"\s+", " ", body or "").strip().lower()
        normalized = re.sub(r"nonce=[\"'][^\"']+[\"']", "nonce=", normalized)
        return normalized

    def _is_baseline_fallback(self, body: str) -> bool:
        if self._baseline_signature is None:
            return False
        return self._signature(body) == self._baseline_signature or self._looks_like_spa_shell(body)

    def _looks_like_spa_shell(self, body: str) -> bool:
        text = (body or "").lower()
        markers = (
            "<app-root",
            "id=\"app\"",
            "id='app'",
            "data-reactroot",
            "__next_data__",
            "webpack",
        )
        return sum(marker in text for marker in markers) >= 2

    def _looks_like_endpoint(self, status: int, body: str) -> bool:
        if status in (200, 401, 403, 301, 302, 307, 308):
            return True
        text = (body or "").strip()
        return bool(text) and len(text) > 20