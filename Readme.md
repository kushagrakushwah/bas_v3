# SecureForge

> **Containerized Breach & Attack Simulation platform for detection validation, SOC scoring, and adversary emulation — built on FastAPI, Next.js, and Kubernetes.**

---

## Overview

SecureForge is a highly advanced, self-hosted **BAS (Breach & Attack Simulation) platform** designed specifically for security engineering teams that need a reliable, repeatable way to test their detection stack without touching production systems.

Instead of writing custom scripts for every test, SecureForge orchestrates modular attack simulations, streams live telemetry in real-time, maps all findings to the **MITRE ATT&CK® Framework**, and dynamically scores your SOC coverage — all from a beautiful, modern web dashboard.

The system runs entirely in containers:
* **The Backend (`bas_engine`)**: A powerful Python/FastAPI engine that handles simulation orchestration, finding storage, asynchronous task execution, and WebSocket event emission.
* **The Frontend (`secureforge-frontend`)**: A gorgeous, reactive Next.js application that handles the full operator workflow: launching simulations, watching live event streams, reviewing reports, and inspecting the cluster.

Unlike SaaS products, SecureForge runs **on your infrastructure, in your cluster, against your environment** — giving you 100% visibility and zero data exfiltration risks.

> **Authorization Required:** This platform is intended for use in authorized environments only. Please read the [Disclaimer](#-disclaimer) below.

---

## Key Features & Capabilities

### The Attack Simulation Engine
* **18 Modular Attack Modules:** A completely pluggable architecture allowing you to deploy network scans, brute force attacks, web exploitation, and complex Killchains without touching the core logic.
* **Parallel Execution:** Launch multiple attacks simultaneously with isolated, non-blocking event streams.
* **Real-time Telemetry:** Watch the attack unfold live over WebSockets directly in the dashboard.

### Detection & Validation
* **MITRE ATT&CK® Mapping:** Every single finding is mapped to specific MITRE Tactics and Techniques (e.g., T1190, T1059).
* **SOC Validation Scoring:** Automatically calculate your detection coverage rate, identify blind spots, and flag undetected critical findings.
* **Smart Alert Generation:** Converts simulation results into actionable alerts for defensive teams.

### Observability & Analytics
* **Live Event Stream:** Watch payloads, HTTP requests, and SSH connection attempts in real-time.
* **Executive Dashboards:** High-level KPI cards, severity distribution charts, trend lines, and execution summaries for management review.
* **ELK Stack Integration:** Full support for log forwarding and Kibana visualization in Kubernetes deployments.

---

## The Module Arsenal

SecureForge comes packed with **18 highly detailed attack modules** split across two categories:

### Red Team & Network Modules
1. **APT Killchain (T1110, T1190, T1059):** A terrifying 7-stage autonomous attack that simulates an Advanced Persistent Threat (APT). It automatically chains together Recon, Credential Attacks, Web Exploits, Privilege Escalation, and Persistence probes in one massive simulation.
2. **Nmap Subnet Scan:** Discovers hosts, open ports, and services across your infrastructure.
3. **SSH Bruteforce:** Tests credential resilience using customizable dictionary attacks.
4. **OWASP Web Scanner:** Crawls and analyzes web targets for top OWASP vulnerabilities (missing security headers, exposed server versions, TLS downgrade, etc).
5. **WAF Detection:** Analyzes the target's response to malicious payloads to identify the presence and type of Web Application Firewall (WAF).
6. **Recon & Exposure:** Passively aggregates external exposure data and OSINT.
7. **Privilege Escalation:** Simulates attempts to break out of low-privilege boundaries.
8. **Impact Simulator:** Tests destructive techniques (safely simulated) like data wiping and encryption staging.

### Vulnerability Scanner Modules
1. **XSS (Cross-Site Scripting):** Probes for reflected and stored JavaScript injection points.
2. **SQLi (SQL Injection):** Tests both error-based and blind/timing-based SQL injection to extract database content.
3. **CMD Injection:** Attempts to execute arbitrary OS commands (e.g., `cat /etc/passwd`) via vulnerable inputs.
4. **Path Traversal (LFI/RFI):** Attempts to break out of web directories to read sensitive local files.
5. **XXE (XML External Entity):** Injects malicious XML payloads to extract internal data.
6. **SSRF (Server-Side Request Forgery):** Tricks the server into querying internal cloud metadata endpoints (e.g., AWS `169.254.169.254`).
7. **CSRF (Cross-Site Request Forgery):** Checks if state-changing endpoints are protected by tokens or SameSite cookies.
8. **SSTI (Server-Side Template Injection):** Probes templating engines (Jinja2, Twig) for arbitrary code execution.
9. **Webmail Bruteforce:** Specialized attacks against OWA and custom webmail portals.
10. **Port Scanner:** A fast, lightweight TCP scanner for specific web infrastructure targets.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  secureforge-frontend                │
│         (Next.js / TypeScript / TailwindCSS)         │
│  Dashboard │ Launch │ Realtime │ Reports │ Analytics │
│  Alerts │ MITRE │ SOC │ Infrastructure               │
└───────────────────┬──────────────────────────────────┘
                    │ HTTP + WebSocket
┌───────────────────▼──────────────────────────────────┐
│                    bas_engine                        │
│                  (FastAPI / Python)                  │
│  Attack Orchestrator │ Event Bus │ Finding Store     │
│  Simulation Runner │ Validation │ WS Broadcaster     │
│  Kubernetes Client │ Metrics API │ ELK Forwarder     │
└──────┬─────────────────────────────────┬─────────────┘
       │                                 │
┌──────▼──────┐                 ┌────────▼────────┐
│  Kubernetes │                 │   ELK Stack     │
│   Cluster   │                 │ Elasticsearch   │
│  (pods/HPA/ │                 │ Logstash        │
│   metrics)  │                 │ Kibana          │
└─────────────┘                 └─────────────────┘
```

The backend exposes a **REST API** for simulation control and a `/ws` **WebSocket endpoint** for live event streaming. The frontend connects to both. Infrastructure data is pulled directly from the Kubernetes API server via the in-cluster or kubeconfig client. 

---

## Quick Start (Local Setup)

The entire infrastructure (Frontend Dashboard, Python BAS Engine, PostgreSQL Database, and Elasticsearch) is containerized, allowing you to launch the stack with a single command.

### 1. Clone the Repository
```bash
git clone https://github.com/kushagrakushwah/bas_v3.git
cd bas_v3
```

### 2. Configure Environment Variables
Copy the example environment file to `.env`. This is **required** to configure database credentials and NextAuth.

```bash
# Windows (PowerShell/CMD)
copy .env.example .env

# macOS / Linux
cp .env.example .env
```
*Note: Open the `.env` file and ensure `API_KEY`, `NEXTAUTH_SECRET`, and database credentials are set before proceeding. You can generate random keys using `openssl rand -hex 32`.*

### 3. Launch the Platform
From the root directory, run:
```bash
docker-compose up -d --build
```

### 4. Access the Platform
Once the containers have started, the platform is live:
- **SecureForge Dashboard (UI)**: [http://localhost:3001](http://localhost:3001)
- **Backend API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)

### 5. Shutting Down
To stop the platform:
```bash
docker-compose down
```
*(To wipe all data, add the `-v` flag: `docker-compose down -v`)*

---

## Disclaimer

SecureForge is designed exclusively for use in **authorized environments**. This means:
1. You have **explicit written permission** to run simulations against the target systems and network.
2. You are operating within a controlled lab, staging environment, or a production system where you have full authorization.
3. You understand that attack simulation generates real network traffic and may trigger security tooling.

**Unauthorized use of this platform against systems you do not own or have permission to test is illegal.** The authors and contributors accept no liability for misuse.

---
