"""
Recon & Exposure Module — Deadly Edition
=========================================
Merged from 4 modules:
  - credential_dumping  (T1003, T1552, T1110.001)
  - data_exfiltration   (T1041, T1020, T1530)
  - lateral_movement    (T1021, T1021.001, T1021.002)
  - supply_chain        (T1195, T1195.002, T1059)

Runs 4 sequential stages over a single shared aiohttp session.
Each stage emits a WebSocket event on start and contributes
findings to a single returned list. Findings are based on
real exploitation techniques, not fabricated narratives.
"""

import asyncio
import aiohttp
import re
from typing import List
from urllib.parse import urlparse
from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.attack_modules.utils.endpoint_discovery import EndpointDiscoveryEngine
from bas_engine.models.simulation import Finding, Severity


class ReconExposureModule(BaseAttackModule):

    MODULE_NAME  = "recon_exposure"
    DESCRIPTION  = (
        "Recon & exposure scan: credential files, data exfiltration vectors, "
        "lateral movement paths, and supply chain risks (T1552/T1041/T1021/T1195)"
    )
    MITRE_TACTIC = "Reconnaissance & Exposure"
    MITRE_IDS    = [
        "T1552",
        "T1041",
        "T1020",
        "T1021",
        "T1195",
        "T1195.002",
        "T1059",
        "T1003",
        "T1530",
    ]

    # =========================================================
    # STAGE 1 — CREDENTIAL DUMPING
    # =========================================================

    CREDENTIAL_PATHS = [
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/config.yml",
        "/config.yaml",
        "/settings.py",
        "/application.properties",
        "/.git/config",
        "/database.yml",
        "/credentials.json",
        "/secrets.json",
        "/.aws/credentials",
        "/backup.sql",
        "/dump.sql",
    ]

    CREDENTIAL_PATTERNS = [
        (r"DB_PASSWORD\s*=\s*(\S+)",           1, "Database password"),
        (r"db_password\s*:\s*(\S+)",           1, "Database password"),
        (r"SECRET_KEY\s*=\s*(\S+)",            1, "Secret key"),
        (r"AWS_SECRET_ACCESS_KEY\s*=\s*(\S+)", 1, "AWS secret access key"),
        (r"password\s*=\s*['\"]([^'\"]+)['\"]",1, "Hardcoded password"),
        (r"mysql://(\S+):(\S+)@",              2, "MySQL connection string"),
        (r"postgresql://(\S+):(\S+)@",         2, "PostgreSQL connection string"),
    ]

    # Default credentials used in lateral movement (stage 3)
    DEFAULT_CREDENTIALS = [
        ("admin",  "admin"),
        ("admin",  "password"),
        ("admin",  "123456"),
        ("root",   "root"),
        ("root",   "password"),
        ("user",   "user"),
        ("test",   "test"),
    ]

    # =========================================================
    # STAGE 2 — DATA EXFILTRATION
    # =========================================================

    EXFIL_PATHS = [
        "/api/users",
        "/api/v1/users",
        "/api/students",
        "/rest/products",
        "/rest/user",
        "/users.csv",
        "/users.json",
        "/students.csv",
        "/backup.zip",
        "/database_backup.sql",
        "/exports",
        "/reports",
        "/downloads",
        "/data",
        "/logs",
        "/log",
        "/access.log",
        "/error.log",
    ]

    PII_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email addresses"),
        (r"\b\d{10,16}\b",                                          "Numeric IDs / card numbers"),
        (r"password['\"]?\s*[:=]\s*['\"]?\w+",                     "Password fields in API response"),
        (r"\"email\"\s*:",                                          "Email field in JSON response"),
        (r"\"ssn\"\s*:",                                            "SSN field in API response"),
        (r"Index of /",                                             "Directory listing exposed"),
    ]

    # =========================================================
    # STAGE 3 — LATERAL MOVEMENT
    # =========================================================

    LATERAL_PROBE_PATHS = [
        "/admin",
        "/manager",
        "/console",
        "/phpmyadmin",
        "/wp-admin",
        "/.env",
        "/config",
        "/backup",
    ]

    # Common parameter names vulnerable to SSRF
    SSRF_PARAMETERS = [
        "url", "uri", "path", "dest", "redirect", "redirect_uri",
        "forward", "target", "proxy", "fetch", "load", "image_url",
        "file", "document", "resource", "source",
    ]

    # =========================================================
    # STAGE 4 — SUPPLY CHAIN
    # =========================================================

    MANIFEST_PATHS = [
        "/package.json",
        "/package-lock.json",
        "/requirements.txt",
        "/Pipfile",
        "/Gemfile",
        "/composer.json",
        "/pom.xml",
        "/build.gradle",
        "/.npmrc",
        "/yarn.lock",
        "/Pipfile.lock",
    ]

    SCRIPT_PATHS = [
        "/",
        "/index.html",
        "/robots.txt",
    ]

    VULNERABLE_PATTERNS = [
        (r'"version"\s*:\s*"([^"]+)"',            "npm package version"),
        (r"(Django|Flask|Spring|Rails)==([^\n]+)", "Framework version"),
        (r"(log4j|log4j2)[^=]*==?([^\n\s]+)",     "Log4j version — check for CVE-2021-44228"),
    ]

    SUSPICIOUS_SCRIPT_PATTERNS = [
        r'<script[^>]+src=["\']https?://(?!cdnjs|unpkg|jsdelivr|ajax\.googleapis)([^"\']+)["\']',
    ]

    # =========================================================
    # Helpers
    # =========================================================

    def _dedupe_urls(self, urls):
        seen = set()
        deduped = []
        for item in urls:
            url = item[0] if isinstance(item, tuple) else item
            if url not in seen:
                seen.add(url)
                deduped.append(item)
        return deduped

    def _route_candidates(self, target, discovered_urls, fallback_paths, keywords,
                          minimum=3, fallback_limit=None, allow_fallback=True):
        selected = []
        target_base = target.rstrip("/")

        for url in discovered_urls:
            path = urlparse(url).path.lower()
            if any(keyword in path for keyword in keywords):
                selected.append((url, "discovery"))

        if allow_fallback and len(selected) < minimum:
            limit = fallback_limit or len(fallback_paths)
            for path in fallback_paths[:limit]:
                selected.append((target_base + path, "fallback"))

        return self._dedupe_urls(selected)

    async def _discover_routes(self, session, target):
        engine = EndpointDiscoveryEngine(
            session,
            target,
            max_endpoints=40,
            max_depth=1,
            timeout=6.0,
        )
        return await engine.discover()

    # =========================================================
    # MAIN EXECUTE
    # =========================================================

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []

        resolved = await self.resolve_target()
        target = self.build_target_url(resolved, default_scheme="https")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            discovered_routes = self._dedupe_urls(await self._discover_routes(session, target))
            discovery_sparse  = len(discovered_routes) < 5

            findings.extend(await self._stage_credential_dumping(session, target, discovered_routes, discovery_sparse))
            findings.extend(await self._stage_data_exfiltration(session, target, discovered_routes, discovery_sparse))
            findings.extend(await self._stage_lateral_movement(session, target, discovered_routes, discovery_sparse))
            findings.extend(await self._stage_supply_chain(session, target, discovered_routes, discovery_sparse))

        # Final summary finding
        findings.append(self.finding(
            title       = "Recon & Exposure Scan Complete",
            description = (
                f"Completed 4 exposure stages against {target}. "
                f"Route discovery yielded {len(discovered_routes)} candidate endpoint(s). "
                f"Total findings generated: {len(findings)}. "
                "Stages covered: Credential Exposure, Data Exfiltration, "
                "Lateral Movement Vectors, Supply Chain Risks."
            ),
            severity      = Severity.INFO,
            mitre_id      = "T1595",
            evidence      = f"4 stages executed against {target}; discovered_routes={len(discovered_routes)}",
            remediation   = "Review all findings above and prioritise CRITICAL and HIGH severity items.",
            raw_data      = {
                "discovered_routes": len(discovered_routes),
                "discovery_sparse": discovery_sparse,
                "provenance": "mixed",
            },
            mode          = "live",
            evidence_type = "target-derived",
        ))

        return findings

    # =========================================================
    # STAGE 1 — CREDENTIAL DUMPING
    # =========================================================

    async def _stage_credential_dumping(self, session, target, discovered_routes, discovery_sparse):
        findings = []

        await self.emit_event(
            "INFO", "Stage 1 starting: Credential Exposure",
            {"stage": 1, "module": self.MODULE_NAME},
        )

        credential_candidates = self._route_candidates(
            target, discovered_routes, self.CREDENTIAL_PATHS,
            ("env", "config", "git", "credential", "secret", "backup", "dump", "database"),
            minimum=5, allow_fallback=discovery_sparse,
        )

        for url, source in credential_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        extracted = []
                        for pattern, group_idx, desc in self.CREDENTIAL_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                if group_idx == 1:
                                    secret = matches[0] if isinstance(matches[0], str) else matches[0][0]
                                else:
                                    secret = f"{matches[0][0]}:****"
                                extracted.append((desc, secret, str(matches[:2])))

                        if extracted:
                            for desc, secret, raw in extracted:
                                findings.append(self.finding(
                                    title=f"Credentials Exposed: {path}",
                                    description=(
                                        f"The file '{path}' is publicly accessible and contains "
                                        f"credential data: {desc}. Example secret: {secret}. "
                                        "This gives an attacker direct access to backend systems."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1552",
                                    evidence=f"GET {url} → HTTP 200, extracted: {raw}",
                                    remediation=(
                                        f"1. Immediately remove {path} from web root.\n"
                                        "2. Rotate all exposed credentials.\n"
                                        "3. Add sensitive file patterns to .htaccess deny rules."
                                    ),
                                    raw_data={"path": path, "secret_type": desc, "source": source},
                                    mode="live",
                                    evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
                        else:
                            findings.append(self.finding(
                                title=f"Config File Accessible: {path}",
                                description=f"'{path}' is accessible but no immediate credentials were parsed. Still a risk.",
                                severity=Severity.MEDIUM,
                                mitre_id="T1552",
                                evidence=f"GET {url} → HTTP 200, size {len(body)}",
                                remediation=f"Restrict access to {path}.",
                                raw_data={"path": path, "source": source},
                                mode="live",
                                evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                            ))

                    elif resp.status == 403:
                        findings.append(self.finding(
                            title=f"Sensitive Path Exists But Blocked: {path}",
                            description=f"'{path}' returned HTTP 403. The file exists but is currently blocked.",
                            severity=Severity.MEDIUM,
                            mitre_id="T1552",
                            evidence=f"GET {url} → HTTP 403",
                            remediation=f"Move {path} outside web root entirely.",
                            raw_data={"path": path, "source": source},
                            mode="live",
                            evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                        ))
            except Exception as e:
                self.logger.debug(f"Credential probe {url}: {e}")
            await asyncio.sleep(0.2)

        # Discover login pages for use in Stage 3
        self._discovered_login_pages = self._route_candidates(
            target, discovered_routes,
            ["/login", "/admin/login", "/moodle/login/index.php", "/mail/"],
            ("login", "signin", "auth", "mail"),
            minimum=2, fallback_limit=2, allow_fallback=discovery_sparse,
        )

        return findings

    # =========================================================
    # STAGE 2 — DATA EXFILTRATION
    # =========================================================

    async def _stage_data_exfiltration(self, session, target, discovered_routes, discovery_sparse):
        findings = []

        await self.emit_event(
            "INFO", "Stage 2 starting: Data Exfiltration Vectors",
            {"stage": 2, "module": self.MODULE_NAME},
        )

        exfil_candidates = self._route_candidates(
            target, discovered_routes, self.EXFIL_PATHS,
            ("api", "rest", "data", "export", "download", "report", "user", "student",
             "log", "backup", "files", "csv", "json"),
            minimum=4, allow_fallback=discovery_sparse,
        )

        for url, source in exfil_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body      = await resp.text(errors="replace")
                        body_size = len(body)

                        if "Index of /" in body:
                            findings.append(self.finding(
                                title=f"Directory Listing Exposed: {path}",
                                description="Directory listing enabled; attackers can browse and download files.",
                                severity=Severity.HIGH,
                                mitre_id="T1041",
                                evidence=f"GET {url} → HTTP 200 with 'Index of /'",
                                remediation="Disable directory listing (Options -Indexes / autoindex off).",
                                raw_data={"path": path, "source": source},
                                mode="live",
                                evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                            ))

                        for pattern, desc in self.PII_PATTERNS:
                            matches = re.findall(pattern, body[:5000], re.IGNORECASE)
                            if matches:
                                findings.append(self.finding(
                                    title=f"Sensitive Data Exposed via {path}",
                                    description=(
                                        f"'{path}' returned {body_size} bytes with potential {desc}. "
                                        "Data could be exfiltrated."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1041",
                                    evidence=f"Pattern '{pattern}' matched in response from {url}",
                                    remediation="Restrict access, apply data masking, add authentication.",
                                    raw_data={"path": path, "pattern": pattern, "size": body_size, "source": source},
                                    mode="live",
                                    evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
                                break

                        if body_size > 50000 and not findings:
                            findings.append(self.finding(
                                title=f"Large Unauthenticated Response: {path}",
                                description=f"'{path}' returned {body_size:,} bytes without authentication. Exfiltration risk.",
                                severity=Severity.MEDIUM,
                                mitre_id="T1020",
                                evidence=f"GET {url} → HTTP 200, {body_size:,} bytes",
                                remediation="Add authentication and pagination.",
                                raw_data={"path": path, "size": body_size, "source": source},
                                mode="live",
                                evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                            ))

            except Exception as e:
                self.logger.debug(f"Exfil probe {url}: {e}")
            await asyncio.sleep(0.2)

        return findings

    # =========================================================
    # STAGE 3 — LATERAL MOVEMENT
    # =========================================================

    async def _stage_lateral_movement(self, session, target, discovered_routes, discovery_sparse):
        findings = []

        await self.emit_event(
            "INFO", "Stage 3 starting: Lateral Movement Vectors",
            {"stage": 3, "module": self.MODULE_NAME},
        )

        # 1. Try default credentials on discovered login pages
        for login_url, source in getattr(self, "_discovered_login_pages", []):
            try:
                async with session.get(login_url) as resp:
                    if resp.status == 200:
                        page = await resp.text()
                        if re.search(r'<input[^>]*type=["\']password["\']', page, re.IGNORECASE):
                            for user, pwd in self.DEFAULT_CREDENTIALS[:4]:
                                try:
                                    data = {"username": user, "password": pwd, "submit": "Login"}
                                    async with session.post(
                                        login_url, data=data, allow_redirects=False
                                    ) as post_resp:
                                        if post_resp.status in (302, 303) and \
                                                "session" in str(post_resp.cookies).lower():
                                            findings.append(self.finding(
                                                title=f"Default Credentials Successful on {login_url}",
                                                description=(
                                                    f"Login with {user}/{pwd} succeeded. "
                                                    "An attacker can now pivot laterally using this account."
                                                ),
                                                severity=Severity.CRITICAL,
                                                mitre_id="T1110.001",
                                                evidence=f"POST {login_url} returned {post_resp.status} with session cookie",
                                                remediation=(
                                                    "Immediately change default credentials "
                                                    "and enforce a strong password policy."
                                                ),
                                                raw_data={"login_url": login_url, "username": user, "source": source},
                                                mode="live",
                                                evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                                            ))
                                            break
                                except Exception:
                                    pass
            except Exception:
                pass

        # 2. Probe admin/management interfaces for SSRF vectors
        lateral_candidates = self._route_candidates(
            target, discovered_routes, self.LATERAL_PROBE_PATHS,
            ("admin", "manage", "dashboard", "console", "phpmyadmin", "wp-admin", "config", "backup"),
            minimum=3, allow_fallback=discovery_sparse,
        )

        for url, source in lateral_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body            = await resp.text(errors="replace")
                        ssrf_candidates = [
                            param for param in self.SSRF_PARAMETERS
                            if re.search(rf"[?&]{param}=", body, re.IGNORECASE)
                        ]
                        if ssrf_candidates:
                            findings.append(self.finding(
                                title=f"Potential SSRF Vector: {path}",
                                description=(
                                    f"The management interface '{path}' accepts parameters "
                                    f"{', '.join(ssrf_candidates)}. An attacker could abuse this "
                                    "to make requests to internal services, enabling lateral movement."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1021",
                                evidence=f"GET {url} → HTTP 200 with parameters {ssrf_candidates}",
                                remediation=(
                                    "Validate and restrict URL parameters; "
                                    "implement allowlists for external requests."
                                ),
                                raw_data={"path": path, "ssrf_params": ssrf_candidates, "source": source},
                                mode="live",
                                evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                            ))

                    elif resp.status == 403:
                        findings.append(self.finding(
                            title=f"Protected Admin Interface: {path}",
                            description=(
                                f"'{path}' returned HTTP 403. If credentials are obtained (e.g., via "
                                "password spraying), an attacker can use this interface to pivot internally."
                            ),
                            severity=Severity.MEDIUM,
                            mitre_id="T1021",
                            evidence=f"GET {url} → HTTP 403",
                            remediation=(
                                "Restrict access to management interfaces by IP allowlist; enable MFA."
                            ),
                            raw_data={"path": path, "source": source},
                            mode="live",
                            evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                        ))
            except Exception as e:
                self.logger.debug(f"Lateral probe {url}: {e}")
            await asyncio.sleep(0.3)

        # 3. Open redirect probe
        open_redirect_urls = [
            f"{target}/?redirect=http://evil.com",
            f"{target}/redirect?url=http://evil.com",
            f"{target}/login?next=http://evil.com",
        ]
        for test_url in open_redirect_urls:
            try:
                async with session.get(test_url, allow_redirects=False) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location", "")
                        if "evil.com" in loc:
                            findings.append(self.finding(
                                title="Open Redirect Detected",
                                description=(
                                    "Parameter injection leads to redirect to an external domain. "
                                    "An attacker can use this in phishing campaigns to steal credentials "
                                    "and move laterally."
                                ),
                                severity=Severity.MEDIUM,
                                mitre_id="T1021.001",
                                evidence=f"GET {test_url} → {resp.status} Location: {loc}",
                                remediation="Validate redirect URLs against a whitelist; use relative redirects.",
                                raw_data={"url": test_url, "redirect_to": loc},
                                mode="live",
                                evidence_type="target-derived",
                            ))
            except Exception:
                pass

        return findings

    # =========================================================
    # STAGE 4 — SUPPLY CHAIN
    # =========================================================

    async def _stage_supply_chain(self, session, target, discovered_routes, discovery_sparse):
        findings = []

        await self.emit_event(
            "INFO", "Stage 4 starting: Supply Chain Risks",
            {"stage": 4, "module": self.MODULE_NAME},
        )

        manifest_candidates = self._route_candidates(
            target, discovered_routes, self.MANIFEST_PATHS,
            ("package", "requirements", "pipfile", "gemfile", "composer",
             "pom", "gradle", "npmrc", "yarn"),
            minimum=4, allow_fallback=discovery_sparse,
        )

        for url, source in manifest_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        findings.append(self.finding(
                            title=f"Dependency Manifest Exposed: {path}",
                            description="Manifest file publicly accessible; reveals dependency versions.",
                            severity=Severity.HIGH,
                            mitre_id="T1195.002",
                            evidence=f"GET {url} → HTTP 200, {len(body)} bytes",
                            remediation="Block access to manifest files via web server config.",
                            raw_data={"path": path, "size": len(body), "source": source},
                            mode="live",
                            evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                        ))

                        for pattern, desc in self.VULNERABLE_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                if "log4j" in desc.lower():
                                    cve, sev = "CVE-2021-44228", Severity.CRITICAL
                                elif "django" in desc.lower():
                                    cve, sev = "CVE-2023-31047", Severity.HIGH
                                else:
                                    cve, sev = "check manually", Severity.MEDIUM

                                findings.append(self.finding(
                                    title=f"Vulnerable Component: {desc} in {path}",
                                    description=(
                                        f"Version {matches[0][-1] if isinstance(matches[0], tuple) else matches[0]} "
                                        f"of {desc} is listed. Known vulnerability {cve}. "
                                        "Supply chain attack possible via dependency confusion or exploit."
                                    ),
                                    severity=sev,
                                    mitre_id="T1195",
                                    evidence=f"Pattern matched: {matches[:2]}",
                                    remediation="Update component to latest secure version; monitor security advisories.",
                                    raw_data={"path": path, "cve": cve, "source": source},
                                    mode="live",
                                    evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
            except Exception:
                pass
            await asyncio.sleep(0.2)

        # Third-party script detection
        script_candidates = self._route_candidates(
            target, discovered_routes, self.SCRIPT_PATHS,
            ("index", "html", "mail", "moodle"),
            minimum=2, fallback_limit=2, allow_fallback=discovery_sparse,
        )
        for url, source in script_candidates:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        for pattern in self.SUSPICIOUS_SCRIPT_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                findings.append(self.finding(
                                    title="Third-Party Script from External Domain",
                                    description=f"External scripts: {matches[:3]}. Potential supply chain risk.",
                                    severity=Severity.MEDIUM,
                                    mitre_id="T1059",
                                    evidence=f"Scripts: {matches[:3]}",
                                    remediation="Use SRI hashes or self-host critical scripts.",
                                    raw_data={"path": urlparse(url).path, "domains": matches[:3], "source": source},
                                    mode="live",
                                    evidence_type="target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
            except Exception:
                pass
            await asyncio.sleep(0.3)

        return findings
