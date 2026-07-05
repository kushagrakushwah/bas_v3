#!/usr/bin/env python3
"""
test_run_all.py
===============
Master test runner — launches ALL attack modules + all 10 vuln_scanner tests.

This is the complete test suite for SecureForge BAS Engine.

SETUP REQUIRED BEFORE RUNNING:
  1. Set API_KEY below (from your running Docker env).
  2. Set PHPSESSID to your current DVWA cookie (for vuln_scanner DVWA tests).
  3. For SSTI test (vuln_scanner test 10): start Flask on the VM first.

WHAT THIS RUNS (10 red modules + 10 vuln_scanner tests = 20 simulations):

  RED MODULES:
    01  ssh_bruteforce       — SSH credential spray (msfadmin:msfadmin)
    02  owasp_web            — Full OWASP Top 10 v2021 web scan
    03  privilege_escalation — Local PrivEsc enumeration (SUID, sudo, cron)
    04  waf_detection        — WAF fingerprint + bypass
    05  recon_exposure       — Cred dump, exfil, lateral move, supply chain
    06  impact_sim           — Post-exploit C2/storage simulation
    07  nmap_scan            — Nmap port/service fingerprint
    08  apt_killchain        — Full 7-stage APT kill chain
    09  vuln_scanner         — All 10 manual test types (separate section)

  VULN SCANNER (10 manual test types):
    VS-01  XSS               — Reflected XSS via DVWA
    VS-02  SQLi              — SQL injection via DVWA
    VS-03  CMD Injection     — OS command injection via DVWA
    VS-04  Path Traversal    — /etc/passwd via file param
    VS-05  XXE               — XML external entity
    VS-06  SSRF              — Server-side request forgery
    VS-07  SSH Brute (single)— msfadmin:msfadmin SSH check
    VS-08  Port Scan         — TCP port check
    VS-09  CSRF              — Cross-site request forgery via DVWA
    VS-10  SSTI              — Flask template injection

TOTAL: 18 simulations launched. Results polled and printed.

RUN:
  python tests/test_run_all.py
"""

import requests
import time
import json

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
BASE_URL  = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET_IP = "192.168.56.102"
API_KEY   = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"    # <-- Set this
PHPSESSID = "6b958dd519b2512263bda5e3e8a05b92"  # <-- Set this for DVWA tests
HEADERS   = {"X-API-Key": API_KEY}
# ──────────────────────────────────────────────────────────────────────────────

DVWA_COOKIE = {"Cookie": f"PHPSESSID={PHPSESSID}; security=low"}

# ─── ALL SIMULATIONS ──────────────────────────────────────────────────────────
ALL_TESTS = [

    # ── RED MODULES ───────────────────────────────────────────────────────────

    {
        "name": "Red-01-SSHBruteforce",
        "target": TARGET_IP,
        "modules": ["ssh_bruteforce"],
        "options": {
            "usernames": ["msfadmin", "root", "admin", "user"],
            "passwords": ["msfadmin", "root", "password", "admin", "123456"],
            "port": 22,
            "verify_host_keys": False,
            "timeout": 10,
        },
        "wait": 70,
    },

    {
        "name": "Red-02-OWASPWeb",
        "target": f"http://{TARGET_IP}",
        "modules": ["owasp_web"],
        "options": {
            "max_depth": 2,
            "max_urls": 50,
            "max_concurrency": 8,
            "time_budget_s": 180,
            "ssl_verify": False,
            "test_auth": True,
            "test_idor": True,
            "test_ssrf": True,
            "test_open_redirect": True,
            "test_csrf": True,
            "test_ssti": True,
            "test_file_upload": True,
            "test_xxe": True,
            "test_headers": True,
            "test_timing_sqli": True,
        },
        "wait": 210,
    },

    {
        "name": "Red-03-PrivEsc",
        "target": TARGET_IP,
        "modules": ["privilege_escalation"],
        "options": {},
        "wait": 45,
    },

    {
        "name": "Red-04-WAFDetection",
        "target": f"http://{TARGET_IP}",
        "modules": ["waf_detection"],
        "options": {"ssl_verify": False},
        "wait": 90,
    },

    {
        "name": "Red-05-ReconExposure",
        "target": f"http://{TARGET_IP}",
        "modules": ["recon_exposure"],
        "options": {"ssl_verify": False},
        "wait": 90,
    },

    {
        "name": "Red-06-ImpactSim",
        "target": f"http://{TARGET_IP}",
        "modules": ["impact_sim"],
        "options": {"ssl_verify": False},
        "wait": 60,
    },

    {
        "name": "Red-07-NmapScan",
        "target": TARGET_IP,
        "modules": ["nmap_scan"],
        "options": {"nmap_scan": {"profile": "quick", "timing": "T4"}},
        "wait": 90,
    },

    {
        "name": "Red-08-APTKillchain",
        "target": TARGET_IP,
        "modules": ["apt_killchain"],
        "options": {"ssl_verify": False},
        "wait": 300,
    },

    # ── VULN SCANNER — 10 TEST TYPES ──────────────────────────────────────────

    {
        "name": "VS-01-XSS",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/xss_r/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "xss",
                "method": "GET",
                "inject_param": "name",
                "payload": "<script>alert(1)</script>",
                "headers": DVWA_COOKIE,
                "timeout": 15,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-02-SQLi",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/sqli/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "sqli",
                "method": "GET",
                "inject_param": "id",
                "payload": "' OR '1'='1",
                "headers": DVWA_COOKIE,
                "timeout": 20,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-03-CMDInjection",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/exec/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "cmd_injection",
                "method": "POST",
                "inject_param": "ip",
                "payload": "127.0.0.1; cat /etc/passwd",
                "extra_form_fields": {"Submit": "Submit"},
                "headers": DVWA_COOKIE,
                "timeout": 20,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-04-PathTraversal",
        "target": f"http://{TARGET_IP}/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "path_traversal",
                "method": "GET",
                "inject_param": "file",
                "payload": "../../../../etc/passwd",
                "timeout": 15,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-05-XXE",
        "target": f"http://{TARGET_IP}/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "xxe",
                "method": "POST",
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                "headers": {"Content-Type": "application/xml"},
                "timeout": 15,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-06-SSRF",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/fi/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "ssrf",
                "method": "GET",
                "inject_param": "page",
                "payload": "http://169.254.169.254/latest/meta-data/",
                "headers": DVWA_COOKIE,
                "timeout": 15,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-07-SSHBrute",
        "target": f"{TARGET_IP}",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "bruteforce",
                "auth_type": "ssh",
                "ssh_port": 22,
                "credentials": [{"username": "msfadmin", "password": "password"}],
                "timeout": 30,
            }
        },
        "wait": 45,
    },

    {
        "name": "VS-08-PortScan",
        "target": f"{TARGET_IP}",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "portscan",
                "ports": "21,22,80,443,3306,5432",
                "timeout": 30,
            }
        },
        "wait": 45,
    },

    {
        "name": "VS-09-CSRF",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/csrf/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "csrf",
                "method": "POST",
                "payload": "password_new=hacked&password_conf=hacked&Change=Change",
                "headers": DVWA_COOKIE,
                "timeout": 15,
            }
        },
        "wait": 30,
    },

    {
        "name": "VS-10-SSTI",
        "target": f"http://{TARGET_IP}:5001/",
        "modules": ["vuln_scanner"],
        "options": {
            "vuln_scanner": {
                "test_type": "ssti",
                "method": "GET",
                "inject_param": "name",
                "payload": "{{7*7}}",
                "timeout": 15,
            }
        },
        "wait": 30,
    },
]
# ──────────────────────────────────────────────────────────────────────────────


def launch(test: dict) -> str | None:
    payload = {
        "name":    test["name"],
        "target":  test["target"],
        "modules": test["modules"],
        "options": test["options"],
    }
    try:
        r = requests.post(BASE_URL, json=payload, headers=HEADERS, timeout=10)
        r.raise_for_status()
        sid = r.json().get("id") or r.json().get("simulation_id")
        print(f"  [+] Launched [{test['name']}]  id={sid}")
        return sid
    except Exception as e:
        print(f"  [-] Failed   [{test['name']}]  -> {e}")
        return None


def poll_all(sid_map: dict[str, str], global_timeout: int = 360) -> dict:
    deadline  = time.time() + global_timeout
    remaining = set(sid_map.values())
    results   = {}

    while remaining and time.time() < deadline:
        time.sleep(8)
        try:
            r = requests.get(BASE_URL, headers=HEADERS, timeout=10)
            sims = r.json()
        except Exception as e:
            print(f"  [!] Poll error: {e}")
            continue

        for sim in sims:
            sid    = sim.get("id") or sim.get("simulation_id")
            status = sim.get("status", "")
            if sid in remaining and status not in ("running", "queued", "pending", ""):
                remaining.discard(sid)
                results[sid] = sim
                name = sim.get("name", sid)
                print(f"  [*] Done [{name}]  status={status}  remaining={len(remaining)}")

    if remaining:
        print(f"  [!] {len(remaining)} simulations still running after timeout.")
    return results


def print_report(tests: list[dict], sid_map: dict[str, str], results: dict):
    print("\n" + "=" * 70)
    print("  SECUREFORGE FULL TEST REPORT")
    print("=" * 70)

    total_findings = 0
    critical = high = medium = low = info = 0

    for test in tests:
        name   = test["name"]
        sid    = sid_map.get(name)
        result = results.get(sid) if sid else None

        print(f"\n{'-' * 60}")
        print(f"  TEST   : {name}")
        print(f"  MODULE : {test['modules'][0]}")
        print(f"  TARGET : {test['target']}")

        if not sid:
            print("  STATUS : [-] Never launched"); continue
        if not result:
            print("  STATUS : [!] Timed out / still running"); continue

        print(f"  STATUS : {result.get('status','?').upper()}")

        for mod in result.get("module_results", []):
            findings = mod.get("findings", [])
            total_findings += len(findings)
            print(f"  FINDINGS : {len(findings)}")
            for f in findings:
                sev   = f.get("severity","?").upper()
                title = f.get("title","?")
                icon  = "[CRITICAL/HIGH]" if sev in ("CRITICAL","HIGH") else ("[MEDIUM]" if sev == "MEDIUM" else "[LOW/INFO]")
                print(f"    {icon} [{sev}] {title}")
                if sev == "CRITICAL": critical += 1
                elif sev == "HIGH":   high += 1
                elif sev == "MEDIUM": medium += 1
                elif sev == "LOW":    low += 1
                else:                 info += 1

    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Total Findings : {total_findings}")
    print(f"  [Critical] : {critical}")
    print(f"  [High]     : {high}")
    print(f"  [Medium]   : {medium}")
    print(f"  [Low]      : {low}")
    print(f"  [Info]     : {info}")
    print("=" * 70)


def main():
    print("=" * 70)
    print("  SecureForge BAS Engine — Complete Test Suite")
    print(f"  Target       : {TARGET_IP}")
    print(f"  Simulations  : {len(ALL_TESTS)}")
    print("=" * 70)

    if "REPLACE" in API_KEY:
        print("\n[-] ERROR: Set your API_KEY before running this script."); return
    if "REPLACE" in PHPSESSID:
        print("\n[!] WARNING: PHPSESSID not set — DVWA tests will likely fail.")
        print("   Get it from: DVWA -> F12 -> Application -> Cookies -> PHPSESSID\n")

    sid_map: dict[str, str] = {}

    print("\n[1/3] Launching all simulations...\n")
    for test in ALL_TESTS:
        sid = launch(test)
        if sid:
            sid_map[test["name"]] = sid
        time.sleep(1.5)

    if not sid_map:
        print("\n[-] No simulations launched. Check API_KEY and backend connection."); return

    # The longest module is APT killchain (300s) — wait overall 6 minutes
    overall_wait = 360
    print(f"\n[2/3] Polling {len(sid_map)} simulations (up to {overall_wait}s)...\n")
    results = poll_all(sid_map, global_timeout=overall_wait)

    print("\n[3/3] Generating full report...\n")
    print_report(ALL_TESTS, sid_map, results)


if __name__ == "__main__":
    main()
