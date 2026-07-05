#!/usr/bin/env python3
"""
test_nmap_scan.py
=================
Tests the nmap_scan module against 192.168.56.102 (Metasploitable).

Runs 3 profiles: quick, standard, web — each as a separate simulation.

HOW TO USE:
  1. Set API_KEY below.
  2. Ensure nmap is installed in the bas-engine Docker container.
  3. Run: python tests/test_nmap_scan.py
"""

import requests
import time

BASE_URL  = "http://127.0.0.1:8000/api/v1/simulations/"
TARGET    = "192.168.56.102"
API_KEY   = "e21db8c9c690b97861f9ba68d4540d2d2fedf1dffc0d69bf98d826dccb6a3936"   # <-- Set this
HEADERS   = {"X-API-Key": API_KEY}

TESTS = [
    {
        "name": "Test-Nmap-Quick",
        "options": {
            "nmap_scan": {
                "profile": "quick",
                "timing": "T4",
                "subnet_scan": False,
            }
        },
    },
    {
        "name": "Test-Nmap-Standard",
        "options": {
            "nmap_scan": {
                "profile": "standard",
                "timing": "T4",
                "subnet_scan": False,
            }
        },
    },
    {
        "name": "Test-Nmap-Web",
        "options": {
            "nmap_scan": {
                "profile": "web",
                "timing": "T4",
                "subnet_scan": False,
            }
        },
    },
]

WAIT_SECS = 90

def launch(test: dict) -> str | None:
    payload = {
        "name": test["name"],
        "target": TARGET,
        "modules": ["nmap_scan"],
        "options": test["options"],
    }
    try:
        r = requests.post(BASE_URL, json=payload, headers=HEADERS, timeout=10)
        r.raise_for_status()
        sid = r.json().get("id") or r.json().get("simulation_id")
        print(f"  ✅  Launched [{test['name']}]  id={sid}")
        return sid
    except Exception as e:
        print(f"  ❌  Failed   [{test['name']}]  → {e}")
        return None

def main():
    print("=" * 60)
    print("  SecureForge — Nmap Scan Module Test")
    print(f"  Target : {TARGET}")
    print("=" * 60)

    if "REPLACE" in API_KEY:
        print("❌  Set API_KEY before running."); return

    sids = {}
    for test in TESTS:
        sid = launch(test)
        if sid:
            sids[test["name"]] = sid
        time.sleep(2)

    print(f"\nWaiting {WAIT_SECS}s for all nmap scans to complete...")
    time.sleep(WAIT_SECS)

    r2  = requests.get(BASE_URL, headers=HEADERS)
    all_sims = r2.json()

    print("\n--- NMAP REPORT ---")
    for name, sid in sids.items():
        result = next((s for s in all_sims if (s.get("id") or s.get("simulation_id")) == sid), None)
        print(f"\n{'─'*50}")
        print(f"  Profile : {name}")
        if not result:
            print("  ⚠️  Still running / not found"); continue
        print(f"  Status  : {result.get('status','?').upper()}")
        for mod in result.get("module_results", []):
            findings = mod.get("findings", [])
            print(f"  Findings: {len(findings)}")
            for f in findings[:10]:   # cap display at 10 per profile
                sev   = f.get("severity","?").upper()
                title = f.get("title","?")
                icon  = "🔴" if sev in ("CRITICAL","HIGH") else ("🟡" if sev == "MEDIUM" else "🔵")
                print(f"    {icon} [{sev}] {title}")

if __name__ == "__main__":
    main()
