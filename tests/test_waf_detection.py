#!/usr/bin/env python3
"""
test_waf_detection.py
=====================
Tests the waf_detection module against http://192.168.56.102.

Sends XSS, SQLi, CMD injection, Path Traversal, and header payloads to probe
for a WAF. Metasploitable has no WAF so results should show 'WAF Not Detected'
with full payload pass-through.

HOW TO USE:
  1. Set API_KEY below.
  2. Run: python tests/test_waf_detection.py
"""

import requests
import time

BASE_URL  = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET    = "http://192.168.56.102"
API_KEY   = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"   # <-- Set this
HEADERS   = {"X-API-Key": API_KEY}

PAYLOAD = {
    "name": "Test-WAFDetection",
    "target": TARGET,
    "modules": ["waf_detection"],
    "options": {
        "ssl_verify": False,
        "test_parameter": "q",
        "request_timeout": 8,
        "max_payloads": 50,
    },
}

WAIT_SECS = 90

def main():
    print("=" * 60)
    print("  SecureForge — WAF Detection Module Test")
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

    print(f"\nWaiting {WAIT_SECS}s for completion...")
    time.sleep(WAIT_SECS)

    r2  = requests.get(BASE_URL, headers=HEADERS)
    all_sims = r2.json()
    result = next((s for s in all_sims if (s.get("id") or s.get("simulation_id")) == sid), None)

    if not result:
        print("⚠️  Not found — check dashboard."); return

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
