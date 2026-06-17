"""
Custom HTTP Request Module
Sends arbitrary HTTP requests with user‑defined parameters.
Used for manual testing, API debugging, and payload validation.
"""

import asyncio
import aiohttp
import time
import json
import logging
from typing import List, Dict, Any, Optional

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.custom_http")


class CustomHTTPModule(BaseAttackModule):
    MODULE_NAME = "custom_http"
    DESCRIPTION = "Send custom HTTP requests (manual testing, API probes, payload validation)"
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS = ["T1190"]  # Exploit Public-Facing Application (generic)

    async def execute(self) -> List[Finding]:
        findings = []
        options = self.options

        # Read options
        method = options.get("method", "GET").upper()
        target_url = options.get("url", self.target)
        headers = options.get("headers", {})
        body = options.get("body", "")
        timeout_sec = options.get("timeout", 10)

        # If body is a dict, convert to JSON string and set Content-Type
        if isinstance(body, dict):
            body = json.dumps(body)
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"

        # Log the request for debugging
        logger.info(f"Custom HTTP: {method} {target_url}")

        # Send the request
        async with aiohttp.ClientSession() as session:
            try:
                start = time.time()
                async with session.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    data=body if method in ("POST", "PUT", "PATCH") else None,
                    timeout=aiohttp.ClientTimeout(total=timeout_sec),
                    ssl=False,
                    allow_redirects=False,  # avoid following redirects
                ) as resp:
                    elapsed = time.time() - start
                    response_body = await resp.text()
                    # Truncate response body for evidence
                    body_preview = response_body[:1000]
                    if len(response_body) > 1000:
                        body_preview += "... (truncated)"

                    evidence = {
                        "request": {
                            "method": method,
                            "url": target_url,
                            "headers": headers,
                            "body_preview": body[:500] if body else None,
                        },
                        "response": {
                            "status": resp.status,
                            "reason": resp.reason,
                            "headers": dict(resp.headers),
                            "body_preview": body_preview,
                            "elapsed_s": round(elapsed, 2),
                        }
                    }

                    findings.append(self.finding(
                        title=f"Custom {method} Request – Status {resp.status}",
                        description=f"Sent {method} request to {target_url}. Response: {resp.status} {resp.reason}",
                        severity=Severity.INFO,
                        mitre_id="T1190",
                        evidence=json.dumps(evidence, indent=2),
                        remediation="Check response for expected behaviour or vulnerabilities.",
                        mode="safe",
                        evidence_type="custom_request"
                    ))

            except asyncio.TimeoutError:
                findings.append(self.finding(
                    title="Request Timeout",
                    description=f"Request to {target_url} timed out after {timeout_sec}s.",
                    severity=Severity.MEDIUM,
                    mitre_id="T1190",
                    evidence=f"Timeout: {timeout_sec}s",
                    remediation="Adjust timeout or check target availability.",
                    mode="safe",
                    evidence_type="custom_request"
                ))
            except aiohttp.ClientError as e:
                findings.append(self.finding(
                    title="HTTP Client Error",
                    description=f"Client error: {str(e)}",
                    severity=Severity.MEDIUM,
                    mitre_id="T1190",
                    evidence=str(e),
                    remediation="Check URL, headers, and body format.",
                    mode="safe",
                    evidence_type="custom_request"
                ))
            except Exception as e:
                logger.exception("Unexpected error in custom_http")
                findings.append(self.finding(
                    title="Unexpected Error",
                    description=f"Error: {str(e)}",
                    severity=Severity.MEDIUM,
                    mitre_id="T1190",
                    evidence=str(e),
                    remediation="Review logs and input.",
                    mode="safe",
                    evidence_type="custom_request"
                ))

        return findings