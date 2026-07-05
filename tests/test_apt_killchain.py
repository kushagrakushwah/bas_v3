#!/usr/bin/env python3
"""
test_apt_killchain.py
=====================
Tests the apt_killchain module against 192.168.56.102.

This is the full multi-stage red-team kill chain:
  Stage 1: Reconnaissance (service fingerprint)
  Stage 2: Login Attack (credential spray)
  Stage 3: Session Validation
  Stage 4: OWASP Web Scanning
  Stage 5: Privilege Escalation Vectors
  Stage 6: Persistence Probes
  Stage 7: Impact Simulation

HOW TO USE:
  1. Set API_KEY below.
  2. Run: python tests/test_apt_killchain.py
  NOTE: This takes the longest — up to 5 minutes.
"""

import requests
import time

BASE_URL  = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET    = "192.168.56.102"
API_KEY   = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"   # <-- Set this
HEADERS   = {"X-API-Key": API_KEY}

PAYLOAD = {
    "name": "Test-APTKillchain",
    "target": TARGET,
    "modules": ["apt_killchain"],
    "options": {
        "ssl_verify": False,
    },
}

WAIT_SECS = 300   # APT killchain runs 7 stages — give it 5 minutes

def main():
    print("=" * 60)
    print("  SecureForge — APT Kill Chain Module Test")
    print(f"  Target : {TARGET}")
    print("  NOTE: 7-stage kill chain — allow up to 5 minutes")
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

    print(f"\nWaiting {WAIT_SECS}s ({WAIT_SECS//60}min) for completion...")
    deadline = time.time() + WAIT_SECS
    while time.time() < deadline:
        time.sleep(15)
        try:
            r2 = requests.get(BASE_URL, headers=HEADERS, timeout=10)
            all_sims = r2.json()
            result = next((s for s in all_sims if (s.get("id") or s.get("simulation_id")) == sid), None)
            if result:
                status = result.get("status", "")
                elapsed = int(time.time() - (deadline - WAIT_SECS))
                print(f"  [{elapsed}s] status={status}")
                if status not in ("running", "queued", "pending", ""):
                    _print_report(result)
                    return
        except Exception as e:
            print(f"  ⚠️  Poll error: {e}")

    print("⚠️  Timeout reached — check dashboard for results.")

def _print_report(result: dict):
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
