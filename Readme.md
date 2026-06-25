# SecureForge

**Containerized Breach & Attack Simulation platform for detection validation, SOC scoring, and adversary emulation — built on FastAPI, Next.js, and Kubernetes.**

---

## Overview

SecureForge is a self-hosted BAS (Breach & Attack Simulation) platform designed for security teams that need a reliable, repeatable way to test their detection stack without touching production. It orchestrates modular attack simulations, streams telemetry in real time, maps findings to MITRE ATT&CK, and scores SOC coverage — all from a modern web dashboard.

The system runs entirely in containers. The backend (`bas_engine`) handles simulation orchestration, finding storage, and WebSocket event emission. The frontend (`secureforge-frontend`) is a Next.js application that covers the full operator workflow: launching simulations, watching live events, reviewing reports, analyzing findings, and inspecting the cluster.

This is not a SaaS product. It runs on your infrastructure, in your cluster, against your environment — with full visibility into what's being simulated and what was detected.

> **Authorization required.** This platform is intended for use in authorized environments only. See [Disclaimer](#disclaimer).

---

## Key Features

### Simulation Engine
- Launch attack simulations from a configurable module library.
- Modular, pluggable attack modules — add new ones without touching core logic.
- Parallel simulation execution with isolated event streams.
- Nmap-style subnet discovery: port ranges, scan profiles, timing profiles, banner grabbing.
- Real-time event emission over WebSockets.

### Detection & Validation
- Finding collection tied to each simulation run.
- MITRE ATT&CK ID mapping per finding.
- SOC validation scoring: coverage rate, blind spots, undetected findings.
- Alert generation from simulation results.

### Observability
- Live event stream with replay timeline.
- ELK stack integration for log forwarding and Kibana visualization (in K8s deployments).
- Analytics charts: severity distribution, trend lines, execution summaries.
- Executive summary view with KPI cards.

### Infrastructure Visibility
- Kubernetes pod and namespace listing.
- CPU and memory metrics via metrics-server.
- Node health and cluster summary.
- HPA and deployment status.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  secureforge-frontend                │
│         (Next.js / TypeScript / TailwindCSS)         │
│  Dashboard │ Launch │ Realtime │ Reports │ Analytics  │
│  Alerts │ MITRE │ SOC │ Infrastructure               │
└───────────────────┬──────────────────────────────────┘
                    │ HTTP + WebSocket
┌───────────────────▼──────────────────────────────────┐
│                    bas_engine                        │
│                  (FastAPI / Python)                  │
│  Attack Orchestrator │ Event Bus │ Finding Store      │
│  Simulation Runner │ Validation │ WS Broadcaster     │
│  Kubernetes Client │ Metrics API │ ELK Forwarder      │
└──────┬─────────────────────────────────┬─────────────┘
       │                                 │
┌──────▼──────┐                 ┌────────▼────────┐
│  Kubernetes │                 │   ELK Stack     │
│   Cluster   │                 │ Elasticsearch   │
│  (pods/HPA/ │                 │ Logstash        │
│   metrics)  │                 │ Kibana          │
└─────────────┘                 └─────────────────┘
```

The backend exposes a REST API for simulation control and a `/ws` WebSocket endpoint for live event streaming. The frontend connects to both. Infrastructure data is pulled directly from the Kubernetes API server via the in-cluster or kubeconfig client. In Kubernetes environments, events are forwarded to Logstash and queryable in Kibana.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, TypeScript, TailwindCSS, NextAuth |
| Backend | FastAPI, Python 3.11+ |
| WebSockets | FastAPI WebSocket, `websockets` |
| Database | PostgreSQL |
| Containerization | Docker, Docker Compose |
| Orchestration | Kubernetes (local or managed) |
| Observability | Elasticsearch (Docker) / ELK Stack (K8s) |

---

## Repository Structure

```
secureforge/
├── bas_engine/                  # FastAPI backend — core simulation engine
│   ├── main.py                  # App entrypoint, router registration
│   ├── modules/                 # Attack modules (pluggable)
│   ├── engine/                  # Orchestrator, event bus, runner
│   └── ...
│
├── secureforge-frontend/        # Next.js frontend — primary UI
│   ├── app/                     # App Router pages (Dashboard, Reports, Analytics, etc.)
│   ├── components/              # Shared UI components
│   └── ...
│
├── kubernetes/                  # Kubernetes manifests
│   ├── 00-namespace.yaml
│   ├── 01-elk-stack.yaml
│   ├── 02-bas-engine.yaml
│   ├── 03-hpa.yaml
│   ├── 04-dashboard.yaml
│   └── dashboard-svc.yaml
│
└── docker-compose.yml           # Docker Compose configuration for local dev
```

---

## Prerequisites

Before you begin, ensure your machine has the following installed:
1. **Git**: To clone the repository.
2. **Docker Desktop**: This includes the Docker Engine and Docker Compose.
   - Ensure Docker Desktop is running before proceeding.

> **Note**: Because SecureForge uses a modern, containerized architecture, you do not need to install Python, Node.js, or complex databases directly on your host machine. Docker will handle everything automatically.

---

## 🚀 Quick Start (Local Setup)

The entire infrastructure (Frontend Dashboard, Python BAS Engine, PostgreSQL Database, and Elasticsearch) is containerized, allowing you to launch the stack with a single command.

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/secureforge.git
cd secureforge
```

### 2. Configure Environment Variables
Copy the example environment file to `.env`. This is **required** to configure database credentials and NextAuth.

```bash
# Windows (PowerShell/CMD)
copy .env.example .env

# macOS / Linux
cp .env.example .env
```
*Note: Open the `.env` file and ensure `NEXTAUTH_SECRET` and database credentials are set before proceeding.*

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

## Kubernetes Deployment

All manifests are available in `kubernetes/`. Apply them in numerical order:

### 1. Setup Namespace & Logging
```bash
kubectl apply -f kubernetes/00-namespace.yaml
kubectl apply -f kubernetes/01-elk-stack.yaml
```

### 2. Deploy the Application Stack
```bash
kubectl apply -f kubernetes/02-bas-engine.yaml
kubectl apply -f kubernetes/03-hpa.yaml
kubectl apply -f kubernetes/04-dashboard.yaml
kubectl apply -f kubernetes/dashboard-svc.yaml
```

### 3. Verify Deployment
```bash
kubectl get pods -n secureforge
kubectl get services -n secureforge
```

---

## Important Notes

- **API Authentication**: The backend API is secured via an `X-API-Key` header. The key is read from the `API_KEY` environment variable.
- **SSRF Protection**: Web attack modules use safe external canary URLs and block internal/loopback IPs (e.g., `127.0.0.1`, `10.x.x.x`) to prevent engine compromise during testing.
- **Pluggable Modules**: Attack modules reside in `bas_engine/modules/`. New modules can be added without modifying the core orchestrator.
- **Metrics**: Infrastructure metrics require `metrics-server` to be installed in the Kubernetes cluster.

---

## Disclaimer

SecureForge is designed exclusively for use in **authorized environments**. This means:
- You have explicit written permission to run simulations against the target systems and network.
- You are operating within a controlled lab, staging environment, or a production system where you have full authorization.
- You understand that attack simulation generates real network traffic and may trigger security tooling.

**Unauthorized use of this platform against systems you do not own or have permission to test is illegal.** The authors and contributors accept no liability for misuse.

---

## License

Review the `LICENSE` file in the repository root. This software is provided for authorized security testing and research purposes.