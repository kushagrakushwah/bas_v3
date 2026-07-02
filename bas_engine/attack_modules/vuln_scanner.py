"""
Vuln Scanner Module
Manual request templates for common web security test scenarios.
8 tabs: XSS, SQLi, Command Injection, Path Traversal, XXE, SSRF,
Brute Force, Port Scan.
"""

import asyncio
import aiohttp
import json
import logging
import re
import socket
import ipaddress
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.vuln_scanner")

# Default payload templates for each test type
DEFAULT_TEMPLATES = {
    "xss": {
        "description": "Test for reflected script injection",
        "method": "GET",
        "payload": "<script>alert(1)</script>",
        "param": "q",
        "headers": "{}"
    },
    "sqli": {
        "description": "Test for SQL injection with delay",
        "method": "GET",
        "payload": "' OR SLEEP(5) --",
        "param": "id",
        "headers": "{}"
    },
    "cmd_injection": {
        "description": "Test for OS command injection",
        "method": "GET",
        "payload": "; ping 127.0.0.1 -c 1",
        "param": "file",
        "headers": "{}"
    },
    "path_traversal": {
        "description": "Test for path traversal (read /etc/passwd)",
        "method": "GET",
        "payload": "../../../etc/passwd",
        "param": "file",
        "headers": "{}"
    },
    "xxe": {
        "description": "Test for XML external entity injection",
        "method": "POST",
        "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        "param": "",
        "headers": '{"Content-Type": "application/xml"}'
    },
    "ssrf": {
        "description": "Test for server-side request forgery (AWS metadata)",
        "method": "GET",
        "payload": "http://169.254.169.254/latest/meta-data/",
        "param": "url",
        "headers": "{}"
    },
    "bruteforce": {
        "description": "Check one username/password pair against SSH or webmail",
        "method": "POST",
        "payload": "",
        "param": "",
        "headers": '{"Content-Type": "application/x-www-form-urlencoded"}',
        "auth_type": "auto",
        "username": "admin",
        "password": "admin",
        "login_url": "",
    },
    "portscan": {
        "description": "Check if a specific port is open",
        "method": "TCP",
        "payload": "",   # not used
        "param": "",
        "headers": "{}",
        "port": 80
    },
    "csrf": {
        "description": "Test for Cross-Site Request Forgery",
        "method": "POST",
        "payload": "csrf_token=invalid_token_test",
        "param": "",
        "headers": '{"Content-Type": "application/x-www-form-urlencoded"}'
    },
    "ssti": {
        "description": "Test for Server-Side Template Injection",
        "method": "GET",
        "payload": "{{7*7}}",
        "param": "q",
        "headers": "{}"
    }
}

class VulnScannerModule(BaseAttackModule):
    MODULE_NAME = "vuln_scanner"
    DESCRIPTION = "Send manual security test requests (XSS, SQLi, etc.)"
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS = ["T1190"]

    async def execute(self) -> List[Finding]:
        findings = []
        options = self.options

        test_type = options.get("test_type", "xss")
        template = DEFAULT_TEMPLATES.get(test_type, DEFAULT_TEMPLATES["xss"])

        # H1 fix: validate options.url against SSRF denylist
        raw_url = options.get("url", self.target)
        target = raw_url
        if "://" not in target:
            target = "http://" + target

        parsed_target = urlparse(target)
        hostname = parsed_target.hostname or ""
        
        # 1. Check basic string blocklist
        _lower = target.lower()
        if _lower.startswith("file://") or "localhost" in _lower or "metadata.google.internal" in _lower:
            raise ValueError(f"options.url {raw_url!r} is blocked by SSRF policy.")
            
        # 2. DNS Rebinding and comprehensive IP blocklist
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            
            # Check if it's a lab target
            lab_targets_env = os.environ.get("LAB_TARGETS", "")
            lab_targets = [t.strip() for t in lab_targets_env.split(",") if t.strip()]

            if str(ip_obj) not in lab_targets:
                if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast:
                    raise ValueError(f"options.url {raw_url!r} resolved to forbidden IP {resolved_ip} (SSRF policy)")
                forbidden_ips = {
                    "169.254.169.254", # AWS, Azure, GCP, DO
                    "169.63.129.16",   # Azure
                    "100.100.100.200", # Alibaba
                }
                if str(ip_obj) in forbidden_ips:
                    raise ValueError(f"options.url {raw_url!r} resolved to forbidden metadata IP {resolved_ip}")
                
        except socket.gaierror:
            pass

        method = options.get("method", template.get("method", "GET"))

        # M3 fix: sanitize user-supplied headers — strip dangerous headers
        _FORBIDDEN_HEADERS = {"host", "transfer-encoding", "x-api-key", "content-length", "connection"}
        raw_headers = options.get("headers", {})
        if not isinstance(raw_headers, dict):
            raw_headers = {}
        headers = {
            k: v for k, v in raw_headers.items()
            if k.lower() not in _FORBIDDEN_HEADERS
        }

        body = options.get("body", "")
        timeout_sec = options.get("timeout", 10)
        inject_param = options.get("inject_param", template.get("param", ""))

        # Brute force mode intentionally checks exactly one credential pair.
        if test_type == "bruteforce":
            findings.extend(await self._run_bruteforce(target, options, timeout_sec))
        elif test_type == "portscan":
            findings.extend(await self._run_portscan(target, options, timeout_sec))
        else:
            # Build the actual request
            # If we have an injection parameter, insert payload into query or body
            payload = options.get("payload", template.get("payload", ""))
            if inject_param and method.upper() == "GET":
                # Inject into URL query
                parsed = urlparse(target)
                query = parse_qs(parsed.query)
                # parse_qs returns lists, so we assign a list back
                query[inject_param] = [payload]
                new_query = urlencode(query, doseq=True)
                target = urlunparse(parsed._replace(query=new_query))
            elif inject_param and method.upper() in ("POST", "PUT", "PATCH"):
                # Inject into body (assume JSON or form)
                # If body is JSON, parse and update
                try:
                    # If body is already JSON, parse and update
                    if "{" in body:
                        body_json = json.loads(body)
                        body_json[inject_param] = payload
                        body = json.dumps(body_json)
                        headers["Content-Type"] = "application/json"
                    else:
                        raise ValueError("Not JSON")
                except Exception as e:
                    # If not JSON, treat as form data
                    # Need to parse existing form data to retain other fields like submit buttons
                    parsed_body = parse_qs(body)
                    parsed_body[inject_param] = [payload]
                    body = urlencode(parsed_body, doseq=True)
                    if "Content-Type" not in headers:
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                if payload and method.upper() == "GET":
                    if inject_param:
                        # We handled inject_param earlier, nothing to do here
                        pass
                    elif payload.startswith("http://") or payload.startswith("https://"):
                        if "?" in target:
                            target = target + payload
                        else:
                            target = target.rstrip("/") + "/" + payload
                    else:
                        if "?" not in target and not target.endswith(payload):
                            target = target.rstrip("/") + "/" + payload
                elif payload and method.upper() in ("POST", "PUT", "PATCH"):
                    # If it's a POST/PUT/PATCH request and no inject param is given, the payload itself becomes the body.
                    # This is essential for things like XXE which pass raw XML payloads.
                    body = payload

            # Send the request
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
                try:
                    start = asyncio.get_running_loop().time()
                    async with session.request(
                        method=method.upper(),
                        url=target,
                        headers=headers,
                        data=body if method.upper() in ("POST", "PUT", "PATCH") else None,
                        timeout=aiohttp.ClientTimeout(total=timeout_sec),
                        allow_redirects=False
                    ) as resp:
                        elapsed = asyncio.get_running_loop().time() - start
                        response_body = await resp.text()
                        body_preview = response_body[:1000]
                        if len(response_body) > 1000:
                            body_preview += "... (truncated)"

                        # Analyze response for vulnerabilities based on test type
                        is_vulnerable = False
                        body_lower = response_body.lower()
                        
                        if test_type == "xss":
                            # Check if payload is reflected without encoding
                            is_vulnerable = payload in response_body
                        elif test_type == "sqli":
                            sql_errors = ["syntax error", "mysql_fetch", "sqlite3", "ora-", "postgresql", "unclosed quotation", "you have an error in your sql syntax"]
                            has_error = any(err in body_lower for err in sql_errors)
                            # Primary: error string evidence (reliable)
                            # Secondary: timing ≥ 9s WITHOUT error is suspicious but not conclusive
                            # — reported as MEDIUM to avoid false CRITICAL on slow servers
                            is_vulnerable = has_error
                            timing_only_suspect = (not has_error) and elapsed >= 9.0
                        elif test_type == "cmd_injection":
                            # Command output markers — require text evidence, not just timing
                            cmd_markers = ["uid=0", "uid=(", "root:x:0:0", "ttl=", "bytes from", "uid=33"]
                            has_marker = any(m in body_lower for m in cmd_markers)
                            # Timing alone at a high threshold as secondary confirmation
                            is_vulnerable = has_marker or elapsed >= 8.0
                        elif test_type == "path_traversal" or test_type == "xxe":
                            # Reading /etc/passwd
                            is_vulnerable = "root:x:0:0" in response_body or "root:x:0:0" in body_lower
                        elif test_type == "ssrf":
                            # Assuming AWS metadata test
                            is_vulnerable = "ami-id" in body_lower or "instance-id" in body_lower or '"Token"' in response_body
                        elif test_type == "csrf":
                            # Improved CSRF detection: inspect headers for CSRF mitigations
                            # Only flag if server accepted the request AND shows no CSRF protections
                            resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                            has_samesite = "samesite=strict" in str(resp_headers_lower.get("set-cookie", "")) or \
                                           "samesite=lax" in str(resp_headers_lower.get("set-cookie", ""))
                            has_csrf_header = "x-csrf-token" in resp_headers_lower or \
                                              "x-xsrf-token" in resp_headers_lower or \
                                              "x-frame-options" in resp_headers_lower
                            accepted_request = resp.status in (200, 201, 302)
                            no_rejection_text = "invalid csrf" not in body_lower and \
                                                "forbidden" not in body_lower and \
                                                "csrf" not in body_lower
                            is_vulnerable = accepted_request and no_rejection_text and \
                                            not has_samesite and not has_csrf_header
                        elif test_type == "ssti":
                            # Check if template expression evaluated to 49 instead of reflecting {{7*7}}
                            is_vulnerable = "49" in response_body and "{{7*7}}" not in response_body
                        else:
                            # Fallback generic reflection check
                            is_vulnerable = payload and payload in response_body

                        evidence = {
                            "test_type": test_type,
                            "request": {
                                "method": method,
                                "url": target,
                                "headers": headers,
                                "body_preview": body[:500] if body else None,
                            },
                            "response": {
                                "status": resp.status,
                                "reason": resp.reason,
                                "headers": dict(resp.headers),
                                "body_preview": body_preview,
                                "elapsed_s": round(elapsed, 2),
                                "vulnerable_indicator": is_vulnerable,
                            }
                        }

                        # Resolve severity — handle SQLi timing-only case specially
                        timing_only_suspect = locals().get("timing_only_suspect", False)
                        if timing_only_suspect:
                            severity = Severity.MEDIUM
                        elif is_vulnerable:
                            severity = Severity.CRITICAL
                        else:
                            severity = Severity.INFO

                        if is_vulnerable or timing_only_suspect:
                            await self.emit_event("INFO", f"[VULNERABILITY] {test_type.upper()} indicator found at {target}")

                        title_suffix = "Potential" if is_vulnerable else ("Timing Anomaly — Manual Confirmation Required" if timing_only_suspect else "No")
                        findings.append(self.finding(
                            title=f"{test_type.upper()} Test - {title_suffix} Indicator",
                            description=f"Sent {test_type} probe to {target}. Status: {resp.status}" +
                                        (f" (Response delayed {elapsed:.1f}s — possible blind SQLi, needs manual verification)" if timing_only_suspect else ""),
                            severity=severity,
                            mitre_id="T1190",
                            evidence=json.dumps(evidence, indent=2),
                            remediation="Review input handling and output encoding.",
                            mode="safe",
                            evidence_type="vuln_scan"
                        ))


                except asyncio.TimeoutError:
                    findings.append(self.finding(
                        title="Request Timeout",
                        description=f"Probe timed out after {timeout_sec}s.",
                        severity=Severity.MEDIUM,
                        mitre_id="T1190",
                        evidence=f"Timeout: {timeout_sec}s",
                        remediation="Adjust timeout or check target availability.",
                        mode="safe",
                        evidence_type="vuln_scan"
                    ))
                except Exception as e:
                    logger.exception("Error in vuln_scanner")
                    findings.append(self.finding(
                        title="Error",
                        description=f"Error: {str(e)}",
                        severity=Severity.MEDIUM,
                        mitre_id="T1190",
                        evidence=str(e),
                        remediation="Check input parameters.",
                        mode="safe",
                        evidence_type="vuln_scan"
                    ))

        return findings

    # --- Brute Force ----------------------------------------------------------



    async def _run_bruteforce(self, target: str, options: dict, timeout: int) -> List[Finding]:
        """
        Check username/password pairs against SSH or webmail.
        Supports single pairs (username/password) or bulk lists (credentials_list).
        """
        import asyncssh
        import re
        import ssl

        credentials_list = options.get("credentials_list", [])
        if not credentials_list:
            # Fallback to single credential
            username = str(options.get("username", "")).strip()
            password = str(options.get("password", "")).strip()
            if username and password:
                credentials_list = [{"username": username, "password": password}]
        
        if not credentials_list:
            return [
                self.finding(
                    title="Credential Check Missing Input",
                    description="A username and password (or credentials_list) are required for the vuln_scanner brute force check.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1110",
                    evidence="Missing username or password.",
                    remediation="Provide exactly one username and one password, or a list of credentials.",
                    mode="safe",
                    evidence_type="bruteforce",
                )
            ]

        # Enforce maximum of 100 credentials per scan for safety
        if len(credentials_list) > 100:
            credentials_list = credentials_list[:100]
            await self.emit_event("WARNING", "Credentials list truncated to maximum of 100 pairs.")

        auth_type = str(options.get("auth_type", "auto")).strip().lower()
        if auth_type not in ("auto", "ssh", "webmail"):
            auth_type = "auto"

        parsed = urlparse(target if "://" in target else f"ssh://{target}")
        host = parsed.hostname or target.split(":")[0]
        ssh_port = int(options.get("ssh_port") or parsed.port or 22)

        if auth_type == "auto":
            is_web = parsed.scheme in ("http", "https") or bool(parsed.path and parsed.path.strip("/"))
            if is_web:
                auth_type = "webmail"
                await self.emit_event(
                    "INFO",
                    f"[AUTO-DETECT] target looks like a web URL, checking webmail",
                )
            else:
                ssh_open = await self._vuln_single_is_port_open(host, ssh_port, timeout)
                auth_type = "ssh" if ssh_open else "webmail"
                await self.emit_event(
                    "INFO",
                    f"[AUTO-DETECT] host={host} | SSH port {ssh_port}: "
                    f"{'open, checking SSH' if ssh_open else 'closed, checking webmail'}",
                )

        login_url = str(options.get("login_url", "")).strip() or target
        if not login_url.startswith(("http://", "https://")):
            login_url = f"https://{login_url.strip('/')}"

        user_field = options.get("webmail_user_field", "_user")
        pass_field = options.get("webmail_pass_field", "_pass")
        action_field = options.get("webmail_action_field", "_action")
        action_value = options.get("webmail_action_value", "login")
        token_field_def = options.get("webmail_token_field", "request_token")
        username_param = options.get("username_param", "username")
        password_param = options.get("password_param", "password")
        timeout_s = float(options.get("timeout", timeout or 10))

        # Setup Webmail specific context
        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for Webmail Scanning")
        ssl_ctx = ssl.create_default_context()
        if not ssl_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        token_pattern = r'(?:request_token|_token|token|_csrf)'

        def extract_token(body: str):
            match = re.search(
                r'name=["\'](' + token_pattern + r')["\'][^>]*value=["\']([^"\']{8,})["\']',
                body,
            )
            if match:
                return match.group(1), match.group(2)

            match = re.search(
                r'value=["\']([^"\']{8,})["\'][^>]*name=["\'](' + token_pattern + r')["\']',
                body,
            )
            if match:
                return match.group(2), match.group(1)

            return token_field_def, None

        fail_markers = [
            "invalid_login",
            "login failed",
            "incorrect password",
            "authentication failed",
            "login_failed",
            "unauthorized",
        ]
        pass_markers = [
            "_task=mail",
            "_task=contacts",
            "rcmbody",
            'id="rcmbody"',
            "composebody",
            "mailboxlist",
            "logout",
            "dashboard",
            "welcome",
        ]

        # Hardcode concurrency to 5 requests at a time
        semaphore = asyncio.Semaphore(5)
        
        async def check_single_webmail(cred: dict) -> List[Finding]:
            username = str(cred.get("username", "")).strip()
            password = str(cred.get("password", "")).strip()
            if not username or not password:
                return []
                
            async with semaphore:
                await self.emit_event("INFO", f"[WEBMAIL SINGLE CHECK] {login_url} | username={username}")
                try:
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
                        async with session.get(
                            login_url,
                            timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                            ssl=ssl_ctx,
                            allow_redirects=True,
                        ) as get_resp:
                            body_get = await get_resp.text(errors="replace")
                            canonical_url = str(get_resp.url)
                            is_basic_auth = get_resp.status == 401

                        if is_basic_auth:
                            auth = aiohttp.BasicAuth(username, password)
                            async with session.get(
                                canonical_url,
                                timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                                ssl=ssl_ctx,
                                allow_redirects=False,
                                auth=auth,
                            ) as auth_resp:
                                status = auth_resp.status
                                final_url = auth_resp.headers.get("Location", "")
                                body_post = await auth_resp.text(errors="replace")
                        else:
                            token_field, token_value = extract_token(body_get)
                            post_data = {
                                user_field: username,
                                pass_field: password,
                                action_field: action_value,
                                username_param: username,
                                password_param: password,
                            }
                            if token_value:
                                post_data[token_field] = token_value

                            async with session.post(
                                canonical_url,
                                data=post_data,
                                timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                                ssl=ssl_ctx,
                                allow_redirects=True,
                            ) as post_resp:
                                status = post_resp.status
                                final_url = str(post_resp.url)
                                body_post = await post_resp.text(errors="replace")

                except asyncio.TimeoutError:
                    return [
                        self.finding(
                            title="Webmail Credential Check Timed Out",
                            description=f"Timed out checking credential pair for {username} against {login_url}.",
                            severity=Severity.MEDIUM,
                            mitre_id="T1110",
                            evidence=f"Timeout: {timeout_s}s",
                            remediation="Increase timeout or verify the login URL.",
                            mode="safe",
                            evidence_type="bruteforce",
                        )
                    ]
                except Exception as exc:
                    return [
                        self.finding(
                            title="Webmail Credential Check Error",
                            description=f"Could not check webmail credentials for {username}: {exc}",
                            severity=Severity.MEDIUM,
                            mitre_id="T1110",
                            evidence=str(exc),
                            remediation="Verify the login URL and form field names.",
                            mode="safe",
                            evidence_type="bruteforce",
                        )
                    ]

                body_lower = body_post.lower()
                has_fail = any(marker in body_lower for marker in fail_markers)
                has_pass = any(marker in body_lower for marker in pass_markers)
                success = (
                    (status in (301, 302, 303, 307, 308) and "_task=mail" in final_url)
                    or ("_task=mail" in final_url)
                    or (has_pass and not has_fail)
                    or (is_basic_auth and status == 200 and not has_fail)
                )

                return [
                    self.finding(
                        title="Webmail Credential Valid" if success else "Webmail Credential Invalid",
                        description=f"Checked webmail credential pair for {username} against {login_url}.",
                        severity=Severity.CRITICAL if success else Severity.INFO,
                        mitre_id="T1110.001",
                        evidence=json.dumps(
                            {
                                "auth_type": "webmail",
                                "login_url": login_url,
                                "username": username,
                                "http_status": status,
                                "final_url": final_url,
                                "success": success,
                                "body_preview": body_post[:500],
                            },
                            indent=2,
                        ),
                        remediation=(
                            "Reset the account password and enforce MFA."
                            if success
                            else "No valid credential indicator was observed."
                        ),
                        raw_data={
                            "auth_type": "webmail",
                            "login_url": login_url,
                            "username": username,
                            "attempts": 1,
                            "successes": 1 if success else 0,
                            "http_status": status,
                        },
                        mode="safe",
                        evidence_type="bruteforce",
                    )
                ]

        async def check_single_ssh(cred: dict) -> List[Finding]:
            username = str(cred.get("username", "")).strip()
            password = str(cred.get("password", "")).strip()
            if not username or not password:
                return []
            
            async with semaphore:
                return await self._vuln_single_ssh_check(
                    host=host,
                    port=ssh_port,
                    username=username,
                    password=password,
                    timeout=timeout,
                )

        all_findings = []
        tasks = []
        
        for cred in credentials_list:
            if auth_type == "ssh":
                tasks.append(asyncio.create_task(check_single_ssh(cred)))
            else:
                tasks.append(asyncio.create_task(check_single_webmail(cred)))
                
        # Wait for all checks to complete concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                all_findings.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Error checking credential in bulk bruteforce: {res}")
                
        return all_findings

        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for C2 Fallback Scanning")
        ssl_ctx = ssl.create_default_context()
        if not ssl_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        token_pattern = r'(?:request_token|_token|token|_csrf)'

        def extract_token(body: str):
            match = re.search(
                r'name=["\'](' + token_pattern + r')["\'][^>]*value=["\']([^"\']{8,})["\']',
                body,
            )
            if match:
                return match.group(1), match.group(2)

            match = re.search(
                r'value=["\']([^"\']{8,})["\'][^>]*name=["\'](' + token_pattern + r')["\']',
                body,
            )
            if match:
                return match.group(2), match.group(1)

            return token_field_def, None

        fail_markers = [
            "invalid_login",
            "login failed",
            "incorrect password",
            "authentication failed",
            "login_failed",
            "unauthorized",
        ]
        pass_markers = [
            "_task=mail",
            "_task=contacts",
            "rcmbody",
            'id="rcmbody"',
            "composebody",
            "mailboxlist",
            "logout",
            "dashboard",
            "welcome",
        ]

        await self.emit_event(
            "INFO",
            f"[WEBMAIL SINGLE CHECK] {login_url} | username={username}",
        )

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=ssl_ctx),
            ) as session:
                async with session.get(
                    login_url,
                    timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                    ssl=ssl_ctx,
                    allow_redirects=True,
                ) as get_resp:
                    body_get = await get_resp.text(errors="replace")
                    canonical_url = str(get_resp.url)
                    is_basic_auth = get_resp.status == 401

                if is_basic_auth:
                    auth = aiohttp.BasicAuth(username, password)
                    async with session.get(
                        canonical_url,
                        timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                        ssl=ssl_ctx,
                        allow_redirects=False,
                        auth=auth,
                    ) as auth_resp:
                        status = auth_resp.status
                        final_url = auth_resp.headers.get("Location", "")
                        body_post = await auth_resp.text(errors="replace")
                else:
                    token_field, token_value = extract_token(body_get)
                    post_data = {
                        user_field: username,
                        pass_field: password,
                        action_field: action_value,
                        username_param: username,
                        password_param: password,
                    }
                    if token_value:
                        post_data[token_field] = token_value

                    async with session.post(
                        canonical_url,
                        data=post_data,
                        timeout=aiohttp.ClientTimeout(total=timeout_s, connect=5),
                        ssl=ssl_ctx,
                        allow_redirects=True,
                    ) as post_resp:
                        status = post_resp.status
                        final_url = str(post_resp.url)
                        body_post = await post_resp.text(errors="replace")

        except asyncio.TimeoutError:
            return [
                self.finding(
                    title="Webmail Credential Check Timed Out",
                    description=f"Timed out checking one credential pair against {login_url}.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1110",
                    evidence=f"Timeout: {timeout_s}s",
                    remediation="Increase timeout or verify the login URL.",
                    mode="safe",
                    evidence_type="bruteforce",
                )
            ]
        except Exception as exc:
            return [
                self.finding(
                    title="Webmail Credential Check Error",
                    description=f"Could not check webmail credentials: {exc}",
                    severity=Severity.MEDIUM,
                    mitre_id="T1110",
                    evidence=str(exc),
                    remediation="Verify the login URL and form field names.",
                    mode="safe",
                    evidence_type="bruteforce",
                )
            ]

        body_lower = body_post.lower()
        has_fail = any(marker in body_lower for marker in fail_markers)
        has_pass = any(marker in body_lower for marker in pass_markers)
        success = (
            (status in (301, 302, 303, 307, 308) and "_task=mail" in final_url)
            or ("_task=mail" in final_url)
            or (has_pass and not has_fail)
            or (is_basic_auth and status == 200 and not has_fail)
        )

        return [
            self.finding(
                title="Webmail Credential Valid" if success else "Webmail Credential Invalid",
                description=f"Checked one webmail credential pair for {username} against {login_url}.",
                severity=Severity.CRITICAL if success else Severity.INFO,
                mitre_id="T1110.001",
                evidence=json.dumps(
                    {
                        "auth_type": "webmail",
                        "login_url": login_url,
                        "username": username,
                        "http_status": status,
                        "final_url": final_url,
                        "success": success,
                        "body_preview": body_post[:500],
                    },
                    indent=2,
                ),
                remediation=(
                    "Reset the account password and enforce MFA."
                    if success
                    else "No valid credential indicator was observed for this single pair."
                ),
                raw_data={
                    "auth_type": "webmail",
                    "login_url": login_url,
                    "username": username,
                    "attempts": 1,
                    "successes": 1 if success else 0,
                    "http_status": status,
                },
                mode="safe",
                evidence_type="bruteforce",
            )
        ]

    async def _vuln_single_is_port_open(self, host: str, port: int, timeout: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def _vuln_single_ssh_check(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
    ) -> List[Finding]:
        import asyncssh

        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts=(),
                    connect_timeout=min(timeout, 5),
                    login_timeout=max(timeout, 10),
                    preferred_auth=["password", "keyboard-interactive"],
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
                timeout=max(timeout, 15),
            )
            conn.close()
            result = "success"
        except asyncssh.PermissionDenied:
            result = "auth_failed"
        except ConnectionResetError:
            result = "reset"
        except asyncssh.ConnectionLost:
            result = "reset"
        except asyncio.TimeoutError:
            result = "timeout"
        except ConnectionRefusedError:
            result = "refused"
        except asyncssh.KeyExchangeFailed:
            result = "kex_failed"
        except asyncssh.HostKeyNotVerifiable:
            result = "hostkey_failed"
        except asyncssh.DisconnectError:
            result = "disconnect"
        except Exception as exc:
            err = str(exc).lower()
            if "reset by peer" in err or "connection lost" in err:
                result = "reset"
            elif "too many connections" in err:
                result = "rate_limited"
            else:
                result = f"other: {exc}"

        success = result == "success"
        return [
            self.finding(
                title="SSH Credential Valid" if success else "SSH Credential Invalid",
                description=f"Checked one SSH credential pair for {username} against {host}:{port}.",
                severity=Severity.CRITICAL if success else Severity.INFO,
                mitre_id="T1110.001",
                evidence=json.dumps(
                    {
                        "auth_type": "ssh",
                        "host": host,
                        "port": port,
                        "username": username,
                        "result": result,
                        "success": success,
                    },
                    indent=2,
                ),
                remediation=(
                    "Reset the account password, disable SSH password auth, and enforce MFA."
                    if success
                    else "No valid SSH credential indicator was observed for this single pair."
                ),
                raw_data={
                    "auth_type": "ssh",
                    "host": host,
                    "port": port,
                    "username": username,
                    "attempts": 1,
                    "successes": 1 if success else 0,
                    "result": result,
                },
                mode="safe",
                evidence_type="bruteforce",
            )
        ]

    async def _run_portscan(self, target: str, options: dict, timeout: int) -> List[Finding]:
        findings = []
        port = options.get("port", 80)
        # Extract host from target URL (remove scheme and path)
        parsed = urlparse(target)
        host = parsed.hostname or target.split(":")[0]

        try:
            # Try a TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            open_status = True
            message = f"Port {port} is open on {host}"
            # T2 fix: Only alert high on unexpected/risky ports
            if int(port) in [80, 443]:
                severity = Severity.INFO
            else:
                severity = Severity.HIGH
        except (asyncio.TimeoutError, ConnectionRefusedError):
            open_status = False
            message = f"Port {port} is closed or filtered on {host}"
            severity = Severity.INFO
        except Exception as e:
            open_status = False
            message = f"Error scanning port: {str(e)}"
            severity = Severity.MEDIUM

        findings.append(self.finding(
            title=f"Port {port} - {'Open' if open_status else 'Closed'}",
            description=message,
            severity=severity,
            mitre_id="T1046",
            evidence=f"Host: {host}\nPort: {port}",
            remediation="Restrict unnecessary open ports.",
            mode="safe",
            evidence_type="portscan"
        ))

        return findings
