#!/usr/bin/env python3
"""
test_owasp_web.py
=================
Tests the owasp_web module (full OWASP Top 10 v2021 scanner) against
http://192.168.56.102 (DVWA / Metasploitable).

The module auto-crawls, injects XSS/SQLi/LFI/SSRF payloads, tests headers,
auth, IDOR, JWT, mass assignment, CSRF, and SSTI.

HOW TO USE:
  1. Set API_KEY below.
  2. Run: python tests/test_owasp_web.py
"""

import requests
import time

BASE_URL  = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET    = "http://192.168.56.102"
API_KEY   = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"   # <-- Set this
HEADERS   = {"X-API-Key": API_KEY}

PAYLOAD = {
    "name": "Test-OWASPWeb",
    "target": TARGET,
    "modules": ["owasp_web"],
    "options": {
        "max_depth": 2,
        "max_urls": 60,
        "max_concurrency": 8,
        "time_budget_s": 180,
        "request_timeout_s": 8,
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
}

WAIT_SECS = 210

def main():
    print("=" * 60)
    print("  SecureForge — OWASP Web Module Test")
    print(f"  Target : {TARGET}")
    print("=" * 60)

    if "REPLACE" in API_KEY:
        print("❌  Set API_KEY before running."); return

    try:
        r = requests.post(BASE_URL, json=PAYLOAD, headers=HEADERS, timeout=10)
        r.raise_for_status()
        sim = r.json()
        sid = sim.get("id") or sim.get("simulation_id")
        print(f"✅  Launched  id={sid}")
    except Exception as e:
        print(f"❌  Launch failed: {e}"); return

    print(f"\nWaiting {WAIT_SECS}s for completion (OWASP scan is slow)...")
    time.sleep(WAIT_SECS)

    r2  = requests.get(BASE_URL, headers=HEADERS)
    all_sims = r2.json()
    result = next((s for s in all_sims if (s.get("id") or s.get("simulation_id")) == sid), None)

    if not result:
        print("⚠️  Simulation not found — still running? Check dashboard."); return

    print(f"\nStatus: {result.get('status','?').upper()}")
    for mod in result.get("module_results", []):
        findings = mod.get("findings", [])
        print(f"\nFindings: {len(findings)}")
        for f in findings:
            sev   = f.get("severity","?").upper()
            title = f.get("title","?")
            icon  = "🔴" if sev in ("CRITICAL","HIGH") else ("🟡" if sev == "MEDIUM" else "🔵")
            print(f"  {icon} [{sev}] {title}")

if __name__ == "__main__":
    main()
