"""
Recon & Exposure Module
=======================
Merged from 4 modules:
  - credential_dumping  (T1003, T1552, T1110.001)
  - data_exfiltration   (T1041, T1020, T1530)
  - lateral_movement    (T1021, T1021.001, T1021.002)
  - supply_chain        (T1195, T1195.002, T1059)

Runs 4 sequential stages over a single shared aiohttp session.
Each stage emits a WebSocket event on start and contributes
findings to a single returned list.
"""

import asyncio
import aiohttp
import re
import random
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
    # from: credential_dumping.py
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
        (r"DB_PASSWORD\s*=\s*\S+",          "Database password in .env"),
        (r"db_password\s*:\s*\S+",          "Database password in config"),
        (r"SECRET_KEY\s*=\s*\S+",           "Secret key exposed"),
        (r"AWS_SECRET_ACCESS_KEY\s*=\s*\S+","AWS credentials exposed"),
        (r"password\s*=\s*['\"][^'\"]+['\"]","Hardcoded password in config"),
        (r"\[default\]\s*aws_",             "AWS credentials file"),
        (r"mysql://\S+:\S+@",               "Database connection string with credentials"),
        (r"postgresql://\S+:\S+@",          "PostgreSQL connection string with credentials"),
    ]

    # =========================================================
    # STAGE 2 — DATA EXFILTRATION
    # from: data_exfiltration.py
    # =========================================================

    EXFIL_PATHS = [
        "/exports",
        "/reports",
        "/downloads",
        "/data",
        "/api/users",
        "/api/v1/users",
        "/api/students",
        "/users.csv",
        "/users.json",
        "/students.csv",
        "/backup.zip",
        "/database_backup.sql",
        "/logs",
        "/log",
        "/access.log",
        "/error.log",
            # Juice Shop
        "/api",
        "/rest",
        "/rest/products",
        "/rest/user",

        "/api/users",
        "/api/v1/users",
        "/api/students",
        "/users.csv",
        "/users.json",
        "/students.csv",
        "/backup.zip",
        "/database_backup.sql",
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
    # from: lateral_movement.py
    # =========================================================

    LATERAL_PROBE_PATHS = [
        "/admin",
        "/rest/admin",

        "/manager",
        "/console",
        "/phpmyadmin",
        "/wp-admin",

        "/.env",
        "/config",
        "/backup",
    ]

    LATERAL_METHODS = [
        "SMB/PsExec",
        "WMI Remote Execution",
        "SSH Forwarding",
        "RDP Session Hijacking",
        "Pass-the-Hash via NTLM",
    ]

    # =========================================================
    # STAGE 4 — SUPPLY CHAIN
    # from: supply_chain.py
    # =========================================================

    MANIFEST_PATHS = [
        "/package.json",
        "/package-lock.json",

        "/swagger",
        "/api-docs",
        "/openapi.json",

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
        "/ftp",
        "/moodle/",
        "/mail/",
    ]

    VULNERABLE_PATTERNS = [
        (r'"version"\s*:\s*"([^"]+)"',           "npm package version"),
        (r"(Django|Flask|Spring|Rails)==([^\n]+)","Framework version"),
        (r"(log4j|log4j2)[^=]*==?([^\n\s]+)",    "Log4j version — check for CVE-2021-44228"),
    ]

    SUSPICIOUS_SCRIPT_PATTERNS = [
        r'<script[^>]+src=["\']https?://(?!cdnjs|unpkg|jsdelivr|ajax\.googleapis)([^"\']+)["\']',
    ]

    def _dedupe_urls(self, urls):
        seen = set()
        deduped = []
        for item in urls:
            url = item[0] if isinstance(item, tuple) else item
            if url not in seen:
                seen.add(url)
                deduped.append(item)
        return deduped

    def _route_candidates(self, target, discovered_urls, fallback_paths, keywords, minimum=3, fallback_limit=None, allow_fallback=True):
        selected = []
        target_base = target.rstrip("/")

        for url in discovered_urls:
            path = urlparse(url).path.lower()
            if any(keyword in path for keyword in keywords):
                selected.append((url, "discovery"))

        if allow_fallback and len(selected) < minimum:
            for path in fallback_paths[: fallback_limit or len(fallback_paths)]:
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
            discovery_sparse = len(discovered_routes) < 5

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
            severity    = Severity.INFO,
            mitre_id    = "T1595",
            evidence    = f"4 stages executed against {target}; discovered_routes={len(discovered_routes)}",
            remediation = "Review all findings above and prioritise CRITICAL and HIGH severity items.",
            raw_data    = {"discovered_routes": len(discovered_routes), "discovery_sparse": discovery_sparse, "provenance": "mixed"},
            mode        = "live",
            evidence_type = "target-derived",
        ))

        return findings

    # =========================================================
    # STAGE 1 — CREDENTIAL DUMPING
    # =========================================================

    async def _stage_credential_dumping(
        self,
        session: aiohttp.ClientSession,
        target: str,
        discovered_routes,
        discovery_sparse: bool,
    ) -> List[Finding]:

        findings: List[Finding] = []

        await self.emit_event(
            "INFO",
            "Stage 1 starting: Credential Exposure",
            {"stage": 1, "module": self.MODULE_NAME},
        )

        self.logger.info("[recon_exposure] Stage 1: Credential file exposure")

        # Config file probe
        credential_candidates = self._route_candidates(
            target,
            discovered_routes,
            self.CREDENTIAL_PATHS,
            ("env", "config", "git", "credential", "secret", "backup", "dump", "database"),
            minimum=5,
            allow_fallback=discovery_sparse,
        )

        for url, source in credential_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        for pattern, desc in self.CREDENTIAL_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                findings.append(self.finding(
                                    title       = f"Credentials Exposed: {path}",
                                    description = (
                                        f"The file '{path}' is publicly accessible and contains "
                                        f"sensitive data matching: {desc}. "
                                        "This gives an attacker direct access to backend systems."
                                    ),
                                    severity    = Severity.CRITICAL,
                                    mitre_id    = "T1552",
                                    evidence    = f"GET {url} → HTTP 200, pattern: {pattern}",
                                    remediation = (
                                        f"1. Immediately remove {path} from web root.\n"
                                        "2. Rotate all exposed credentials.\n"
                                        "3. Add sensitive file patterns to .htaccess deny rules.\n"
                                        "4. Scan web root for other exposed config files."
                                    ),
                                    raw_data    = {"path": path, "pattern": pattern, "source": source},
                                    mode        = "live",
                                    evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
                                break

                    elif resp.status == 403:
                        findings.append(self.finding(
                            title       = f"Sensitive Path Exists But Blocked: {path}",
                            description = (
                                f"'{path}' returned HTTP 403 — the file exists on disk "
                                "but is blocked by server config. "
                                "A misconfiguration could expose it."
                            ),
                            severity    = Severity.MEDIUM,
                            mitre_id    = "T1552",
                            evidence    = f"GET {url} → HTTP 403",
                            remediation = (
                                f"1. Move {path} outside the web root entirely.\n"
                                "2. Do not rely solely on 403 blocks for sensitive files."
                            ),
                                raw_data    = {"path": path, "source": source},
                                mode        = "live",
                                evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                        ))
            except Exception as e:
                self.logger.debug(f"Credential probe {url}: {e}")

            await asyncio.sleep(0.2)

        # Login endpoint probe
        login_candidates = self._route_candidates(
            target,
            discovered_routes,
            ["/admin/login", "/login", "/moodle/login/index.php", "/mail/"],
            ("login", "signin", "auth", "mail"),
            minimum=2,
            fallback_limit=2,
            allow_fallback=discovery_sparse,
        )

        for url, source in login_candidates[:4]:
            login_path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        await self.emit_event("INFO", f"[LOGIN EXPOSURE] Found login endpoint: {login_path}")
                        findings.append(self.finding(
                            title       = f"Login Endpoint Found: {login_path}",
                            description = (
                                f"Login form accessible at '{login_path}'. "
                                "Default credentials (admin/admin, admin/password etc.) "
                                "should be tested. Automated brute force possible if no lockout exists."
                            ),
                            severity    = Severity.MEDIUM,
                            mitre_id    = "T1110.001",
                            evidence    = f"GET {url} → HTTP {resp.status}",
                            remediation = (
                                "1. Change all default credentials immediately.\n"
                                "2. Implement account lockout after 5 failed attempts.\n"
                                "3. Enable MFA on all login endpoints.\n"
                                "4. Monitor login endpoints for brute force patterns."
                            ),
                            raw_data    = {"path": login_path, "source": source},
                            mode        = "live",
                            evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                        ))
            except Exception as e:
                self.logger.debug(f"Login probe {url}: {e}")
            await asyncio.sleep(0.2)

        if not findings:
            findings.append(self.finding(
                title       = "No Credential Exposure Found",
                description = "No exposed config files or accessible login endpoints detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1003",
                evidence    = f"Probed {len(self.CREDENTIAL_PATHS)} paths on {target}",
                remediation = "Continue regular credential hygiene audits.",
                raw_data    = {"mode": "live", "evidence_type": "target-derived"},
                mode        = "live",
                evidence_type = "target-derived",
            ))

        return findings

    # =========================================================
    # STAGE 2 — DATA EXFILTRATION
    # =========================================================

    async def _stage_data_exfiltration(
        self,
        session: aiohttp.ClientSession,
        target: str,
        discovered_routes,
        discovery_sparse: bool,
    ) -> List[Finding]:

        findings: List[Finding] = []

        await self.emit_event(
            "INFO",
            "Stage 2 starting: Data Exfiltration Vectors",
            {"stage": 2, "module": self.MODULE_NAME},
        )

        self.logger.info("[recon_exposure] Stage 2: Data exfiltration vectors")

        exfil_candidates = self._route_candidates(
            target,
            discovered_routes,
            self.EXFIL_PATHS,
            ("api", "rest", "data", "export", "download", "report", "user", "student", "log", "backup", "files", "csv", "json"),
            minimum=4,
            allow_fallback=discovery_sparse,
        )

        for url, source in exfil_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body      = await resp.text(errors="replace")
                        body_size = len(body)

                        if "Index of /" in body:
                            await self.emit_event("INFO", f"[DATA EXFIL] Directory listing exposed at {path}")
                            findings.append(self.finding(
                                title       = f"Directory Listing Exposed: {path}",
                                description = (
                                    f"The path '{path}' has directory listing enabled. "
                                    "An attacker can browse and download all files in this directory."
                                ),
                                severity    = Severity.HIGH,
                                mitre_id    = "T1041",
                                evidence    = f"GET {url} → HTTP 200 with 'Index of /'",
                                remediation = (
                                    "1. Disable directory listing in Apache (Options -Indexes) "
                                    "or Nginx (autoindex off).\n"
                                    "2. Ensure no sensitive files are in publicly accessible directories."
                                ),
                            ))

                        for pattern, desc in self.PII_PATTERNS:
                            matches = re.findall(pattern, body[:5000], re.IGNORECASE)
                            if matches:
                                findings.append(self.finding(
                                    title       = f"Sensitive Data Exposed via {path}",
                                    description = (
                                        f"The endpoint '{path}' returned {body_size} bytes "
                                        f"containing potentially sensitive data: {desc}. "
                                        "This data could be exfiltrated by an attacker."
                                    ),
                                    severity    = Severity.CRITICAL,
                                    mitre_id    = "T1041",
                                    evidence    = f"Pattern '{pattern}' matched in response from {url}",
                                    remediation = (
                                        "1. Restrict access to this endpoint with authentication.\n"
                                        "2. Implement data masking for sensitive fields in API responses.\n"
                                        "3. Apply rate limiting to prevent bulk data extraction.\n"
                                        "4. Audit all API endpoints for excessive data exposure."
                                    ),
                                    raw_data    = {"path": path, "pattern": pattern, "size": body_size, "source": source},
                                    mode        = "live",
                                    evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
                                break

                        if body_size > 50000 and not findings:
                            findings.append(self.finding(
                                title       = f"Large Unauthenticated Response: {path}",
                                description = (
                                    f"'{path}' returned {body_size:,} bytes without authentication. "
                                    "Large unauthenticated responses are a data exfiltration risk."
                                ),
                                severity    = Severity.MEDIUM,
                                mitre_id    = "T1020",
                                evidence    = f"GET {url} → HTTP 200, {body_size:,} bytes",
                                remediation = (
                                    "1. Add authentication to this endpoint.\n"
                                    "2. Implement pagination to limit response sizes.\n"
                                    "3. Add rate limiting."
                                ),
                                raw_data    = {"path": path, "size": body_size, "source": source},
                                mode        = "live",
                                evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                            ))

            except Exception as e:
                self.logger.debug(f"Exfil probe {url}: {e}")

            await asyncio.sleep(0.2)

        if not findings:
            findings.append(self.finding(
                title       = "No Data Exfiltration Vectors Found",
                description = "No exposed data endpoints, directory listings, or PII leakage detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1041",
                evidence    = f"Probed {len(self.EXFIL_PATHS)} paths on {target}",
                remediation = "Continue regular API security audits and access control reviews.",
                raw_data    = {"mode": "live", "evidence_type": "target-derived"},
                mode        = "live",
                evidence_type = "target-derived",
            ))

        return findings

    # =========================================================
    # STAGE 3 — LATERAL MOVEMENT
    # =========================================================

    async def _stage_lateral_movement(
        self,
        session: aiohttp.ClientSession,
        target: str,
        discovered_routes,
        discovery_sparse: bool,
    ) -> List[Finding]:

        findings: List[Finding] = []

        await self.emit_event(
            "INFO",
            "Stage 3 starting: Lateral Movement Vectors",
            {"stage": 3, "module": self.MODULE_NAME},
        )

        self.logger.info("[recon_exposure] Stage 3: Lateral movement vectors")

        lateral_candidates = self._route_candidates(
            target,
            discovered_routes,
            self.LATERAL_PROBE_PATHS,
            ("admin", "manage", "dashboard", "console", "phpmyadmin", "wp-admin", "config", "backup"),
            minimum=3,
            allow_fallback=discovery_sparse,
        )

        for url, source in lateral_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 403):
                        await self.emit_event("INFO", f"[LATERAL MOVEMENT] Found potential vector: {path} (HTTP {resp.status})")
                        method = random.choice(self.LATERAL_METHODS)
                        sev    = Severity.CRITICAL if resp.status in (200, 302) else Severity.HIGH

                        findings.append(self.finding(
                            title       = f"Lateral Movement Vector: {path}",
                            description = (
                                f"Path '{path}' responded with HTTP {resp.status}. "
                                f"In a real attack, this could be leveraged via {method} "
                                "to pivot into adjacent systems."
                            ),
                            severity    = sev,
                            mitre_id    = "T1021",
                            evidence    = f"GET {url} → HTTP {resp.status}",
                            remediation = (
                                "1. Implement network segmentation — restrict east-west traffic.\n"
                                "2. Enforce authentication on all management interfaces.\n"
                                "3. Deploy host-based IDS to detect unusual internal connections.\n"
                                "4. Disable SMB/WMI if not required in your environment."
                            ),
                            raw_data    = {"path": path, "status": resp.status, "method": method, "source": source},
                            mode        = "live",
                            evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                        ))
            except Exception as e:
                self.logger.debug(f"Lateral probe {url}: {e}")

            await asyncio.sleep(0.3)

        if not findings:
            findings.append(self.finding(
                title       = "No Lateral Movement Vectors Found",
                description = "All probed admin/management paths returned 404 or were unreachable.",
                severity    = Severity.INFO,
                mitre_id    = "T1021",
                evidence    = f"Probed {len(self.LATERAL_PROBE_PATHS)} paths on {target}",
                remediation = "Continue monitoring for internal east-west traffic anomalies.",
                raw_data    = {"mode": "live", "evidence_type": "target-derived"},
                mode        = "live",
                evidence_type = "target-derived",
            ))

        return findings

    # =========================================================
    # STAGE 4 — SUPPLY CHAIN
    # =========================================================

    async def _stage_supply_chain(
        self,
        session: aiohttp.ClientSession,
        target: str,
        discovered_routes,
        discovery_sparse: bool,
    ) -> List[Finding]:

        findings: List[Finding] = []

        await self.emit_event(
            "INFO",
            "Stage 4 starting: Supply Chain Risks",
            {"stage": 4, "module": self.MODULE_NAME},
        )

        self.logger.info("[recon_exposure] Stage 4: Supply chain risks")

        # Manifest file exposure
        manifest_candidates = self._route_candidates(
            target,
            discovered_routes,
            self.MANIFEST_PATHS,
            ("package", "requirements", "pipfile", "gemfile", "composer", "pom", "gradle", "npmrc", "yarn", "swagger", "openapi", "api", "rest"),
            minimum=4,
            allow_fallback=discovery_sparse,
        )

        for url, source in manifest_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")

                        await self.emit_event("INFO", f"[SUPPLY CHAIN] Dependency manifest exposed: {path}")
                        findings.append(self.finding(
                            title       = f"Dependency Manifest Exposed: {path}",
                            description = (
                                f"The file '{path}' is publicly accessible. "
                                "This reveals all dependencies and their versions, "
                                "allowing attackers to identify vulnerable components "
                                "or mount a dependency confusion attack."
                            ),
                            severity    = Severity.HIGH,
                            mitre_id    = "T1195.002",
                            evidence    = f"GET {url} → HTTP 200, {len(body)} bytes",
                            remediation = (
                                f"1. Block access to {path} via web server config.\n"
                                "2. Move manifests outside web root.\n"
                                "3. Add to .htaccess: <Files package.json> deny from all </Files>"
                            ),
                            raw_data    = {"path": path, "size": len(body), "source": source},
                            mode        = "live",
                            evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                        ))

                        for pattern, desc in self.VULNERABLE_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                findings.append(self.finding(
                                    title       = f"Component Version Exposed: {desc}",
                                    description = (
                                        f"Version information found in {path}: {matches[:3]}. "
                                        "Attackers can cross-reference these against CVE databases."
                                    ),
                                    severity    = Severity.MEDIUM,
                                    mitre_id    = "T1195",
                                    evidence    = f"Pattern '{pattern}' matched: {matches[:3]}",
                                    remediation = (
                                        "1. Keep all dependencies updated.\n"
                                        "2. Use tools like 'npm audit' or 'safety check' regularly.\n"
                                        "3. Subscribe to security advisories for your dependencies."
                                    ),
                                    raw_data    = {"path": path, "source": source},
                                    mode        = "live",
                                    evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
            except Exception as e:
                self.logger.debug(f"Manifest probe {url}: {e}")
            await asyncio.sleep(0.2)

        # Third-party script analysis
        script_candidates = self._route_candidates(
            target,
            discovered_routes,
            self.SCRIPT_PATHS[:2],
            ("index", "html", "mail", "moodle", "admin", "dashboard", "root"),
            minimum=2,
            fallback_limit=2,
            allow_fallback=discovery_sparse,
        )

        for url, source in script_candidates:
            path = urlparse(url).path or url
            try:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        for pattern in self.SUSPICIOUS_SCRIPT_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                findings.append(self.finding(
                                    title       = "Third-Party Script Loaded from External Domain",
                                    description = (
                                        f"The page at '{path}' loads scripts from external domains: "
                                        f"{matches[:3]}. "
                                        "A compromised CDN or script host could inject malicious code "
                                        "into all users' browsers (supply chain attack)."
                                    ),
                                    severity    = Severity.MEDIUM,
                                    mitre_id    = "T1059",
                                    evidence    = f"External script domains: {matches[:3]}",
                                    remediation = (
                                        "1. Use Subresource Integrity (SRI) hashes for all external scripts.\n"
                                        "2. Self-host critical JavaScript dependencies.\n"
                                        "3. Implement a strict Content-Security-Policy."
                                    ),
                                    raw_data    = {"path": path, "source": source},
                                    mode        = "live",
                                    evidence_type = "target-derived" if source == "discovery" else "fallback-heuristic",
                                ))
            except Exception as e:
                self.logger.debug(f"Script probe {url}: {e}")
            await asyncio.sleep(0.3)

        if not findings:
            findings.append(self.finding(
                title       = "No Supply Chain Vectors Found",
                description = "No exposed manifests or suspicious third-party scripts detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1195",
                evidence    = f"Probed {len(self.MANIFEST_PATHS)} manifest paths on {target}",
                remediation = "Continue regular dependency audits and SRI checks.",
                raw_data    = {"mode": "live", "evidence_type": "target-derived"},
                mode        = "live",
                evidence_type = "target-derived",
            ))

        return findings
