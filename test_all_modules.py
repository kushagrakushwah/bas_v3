import requests
import time
import json
import os

base_url = "http://127.0.0.1:8000/api/v1/simulations/"

# Add your API key here! You can hardcode it or read it from the environment.
API_KEY = "REPLACE_WITH_OPENSSL_RAND_HEX_32"
headers = {
    "X-API-Key": API_KEY
}
modules = [
    "ssh_bruteforce",
    "owasp_web",
    "privilege_escalation",
    "waf_detection",
    "recon_exposure",
    "impact_sim",
    "nmap_scan",
    "apt_killchain"
]

tests = []
for mod in modules:
    payload = {
        "name": f"Full Scan - {mod}",
        "target": "192.168.56.102",
        "modules": [mod],
        "options": {}
    }
    try:
        # Pass the headers containing the API Key
        r = requests.post(base_url, json=payload, headers=headers)
        r.raise_for_status()
        print(f"Launched {mod}")
    except Exception as e:
        print(f"Failed to launch {mod}: {e}")

print("Waiting 45 seconds for all modules to finish...")
time.sleep(45)

# Pass the headers here too
response = requests.get(base_url, headers=headers)
data = response.json()
data.sort(key=lambda x: x.get("created_at", ""), reverse=True)

print("\n--- REPORT ---")
# Print the results of the 8 latest runs
for sim in data[:8]:
    print(f"\n--- {sim.get('name')} ---")
    print(f"Status: {sim.get('status')}")
    for mod in sim.get('module_results', []):
        print(f"Findings: {len(mod.get('findings', []))}")
        for finding in mod.get('findings', []):
            print(f" - [{finding.get('severity')}] {finding.get('title')}")