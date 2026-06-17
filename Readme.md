# SecureForge

**Containerized Breach & Attack Simulation platform for detection validation, SOC scoring, and adversary emulation — built on FastAPI, Next.js, and Kubernetes.**

---

## Overview

SecureForge is a self-hosted BAS (Breach & Attack Simulation) platform designed for security teams that need a reliable, repeatable way to test their detection stack without touching production. It orchestrates modular attack simulations, streams telemetry in real time, maps findings to MITRE ATT&CK, and scores SOC coverage — all from a modern web dashboard.

The system runs entirely in containers. The backend (`bas_engine`) handles simulation orchestration, finding storage, and WebSocket event emission. The primary frontend (`secureforge-frontend`) is a Next.js app that covers the full operator workflow: launching simulations, watching live events, reviewing reports, analyzing findings, and inspecting the cluster. An older Streamlit dashboard (`dashboard/`) is still in the repo and remains usable as a lightweight alternative, but the Next.js frontend is the actively maintained UI.

This is not a SaaS product. It runs on your infrastructure, in your cluster, against your environment — with full visibility into what's being simulated and what was detected.

> **Authorization required.** This platform is intended for use in authorized environments only. See [Disclaimer](#disclaimer).

---

## Key Features

### Simulation Engine
- Launch attack simulations from a configurable module library
- Modular, pluggable attack modules — add new ones without touching core logic
- Parallel simulation execution with isolated event streams
- Nmap-style subnet discovery: port ranges, scan profiles, timing profiles, banner grabbing
- Real-time event emission over WebSockets

### Detection & Validation
- Finding collection tied to each simulation run
- MITRE ATT&CK ID mapping per finding
- SOC validation scoring: coverage rate, blind spots, undetected findings
- Alert generation from simulation results

### Observability
- Live event stream with replay timeline
- ELK stack integration for log forwarding and Kibana visualization
- Analytics charts: severity distribution, trend lines, execution summaries
- Executive summary view with KPI cards

### Infrastructure Visibility
- Kubernetes pod and namespace listing
- CPU and memory metrics via metrics-server
- Node health and cluster summary
- HPA and deployment status

### Reporting
- Simulation history table with full drilldown
- Per-finding detail panels
- Exportable report structure

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

The backend exposes a REST API for simulation control and a `/ws` WebSocket endpoint for live event streaming. The frontend connects to both. Infrastructure data is pulled directly from the Kubernetes API server via the in-cluster or kubeconfig client. Events are forwarded to Logstash and queryable in Kibana.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Primary Frontend | Next.js 14, TypeScript, TailwindCSS |
| Legacy Frontend | Streamlit (Python) |
| Backend | FastAPI, Python 3.11+ |
| WebSockets | FastAPI WebSocket, `websockets` |
| Kubernetes Client | `kubernetes` Python SDK |
| Containerization | Docker, Docker Compose |
| Orchestration | Kubernetes (local or managed) |
| Observability | ELK Stack (Elasticsearch, Logstash, Kibana) |
| Metrics | metrics-server, `kubectl top` |
| Scanning | Nmap (via subprocess / python-nmap) |

---

## Repository Structure

```
secureforge/
├── bas_engine/                  # FastAPI backend — core simulation engine
│   ├── main.py                  # App entrypoint, router registration
│   ├── routers/                 # Route handlers (simulations, findings, alerts, etc.)
│   ├── modules/                 # Attack modules (pluggable)
│   ├── engine/                  # Orchestrator, event bus, runner
│   ├── services/                # Kubernetes client, ELK forwarder, metrics
│   ├── models/                  # Pydantic schemas
│   ├── storage/                 # Simulation and finding persistence
│   └── requirements.txt
│
├── secureforge-frontend/        # Next.js frontend — primary UI
│   ├── app/                     # App Router pages
│   │   ├── page.tsx             # Command center / dashboard
│   │   ├── launch/              # Simulation launch configuration
│   │   ├── realtime/            # Live event stream
│   │   ├── reports/             # Simulation history and findings drilldown
│   │   ├── analytics/           # Charts and trend analysis
│   │   ├── alerts/              # Alert listings
│   │   ├── mitre/               # ATT&CK coverage map
│   │   ├── soc/                 # SOC validation and scoring
│   │   └── infrastructure/      # Kubernetes and cluster metrics
│   ├── components/              # Shared UI components
│   ├── lib/                     # API client, WS client, utilities
│   └── package.json
│
├── dashboard/                   # Legacy Streamlit dashboard (older UI)
│   ├── app.py
│   └── requirements.txt
│
├── kubernetes/                  # Kubernetes manifests
│   ├── namespace.yaml
│   ├── bas-engine-deployment.yaml
│   ├── bas-engine-service.yaml
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   ├── elk-deployment.yaml
│   ├── elk-service.yaml
│   ├── hpa.yaml
│   └── metrics-server.yaml
│
└── docs/
    └── images/                  # Screenshots (see Screenshots section)
```

---

## Screenshots

> Place screenshots in `docs/images/`. The filenames below are referenced throughout this README.

### Command Center
![Command Center](docs/images/command-center.png)
*Main dashboard with KPI cards, recent assessments, active findings, and severity summary charts.*

### Launch Center
![Launch Center](docs/images/launch-center.png)
*Simulation configuration: module selection, target input, and Nmap options (subnet, port range, scan profile, timing profile, banner grabbing) when `nmap_scan` module is selected.*

### Live Operations — Realtime Stream
![Realtime Stream](docs/images/realtime-stream.png)
*WebSocket event feed with per-event severity, module tag, and timestamp. Includes replay timeline for reviewing past simulation events.*

### Reports
![Reports](docs/images/reports.png)
*Simulation history table with status, duration, and finding count. Drilldown panel shows per-finding detail including MITRE IDs, severity, and raw output.*

### Analytics
![Analytics](docs/images/analytics.png)
*Charts for severity distribution, simulation trend over time, module execution breakdown, and finding frequency.*

### Alerts
![Alerts](docs/images/alerts.png)
*Alerts generated from simulation findings. Each alert includes source module, severity, affected target, and timestamp.*

### MITRE ATT\&CK Coverage
![MITRE](docs/images/mitre-coverage.png)
*ATT&CK matrix view showing which tactics and techniques have been exercised and which findings mapped to each ID.*

### SOC Validation
![SOC Validation](docs/images/soc-validation.png)
*SOC scoring panel: detection coverage %, blind spot count, undetected finding breakdown, and validation run history.*

### Infrastructure
![Infrastructure](docs/images/infrastructure.png)
*Kubernetes view: pod list by namespace, node health, CPU/memory usage via metrics-server, HPA status, and cluster summary.*

### Kibana — ELK Telemetry
![Kibana](docs/images/kibana-discover.png)
*Kibana Discover view showing ingested simulation events from Logstash. Useful for full-text search and long-term telemetry analysis.*

### Kubernetes Terminal Proof
![kubectl](docs/images/kubectl-pods.png)
*Terminal output of `kubectl get pods -n secureforge` and `kubectl top nodes` confirming the running stack.*

### Architecture Diagram *(optional)*
![Architecture](docs/images/architecture-diagram.png)
*Optional: high-level architecture showing frontend → backend → Kubernetes → ELK data flow.*

---

## Prerequisites

Before you begin, ensure your machine has the following installed:
1. **Git**: To clone the repository.
   - Download: [git-scm.com](https://git-scm.com/downloads)
2. **Docker Desktop**: This includes the Docker Engine and Docker Compose.
   - Download: [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
   - Ensure Docker Desktop is running before proceeding.

> **Note**: Because SecureForge uses a modern, containerized architecture, you do not need to install Python, Node.js, or complex databases directly on your host machine. Docker will handle everything automatically.

---

## 🚀 Quick Start (Local Setup)

Because the entire infrastructure (Frontend Dashboard, Python BAS Engine, PostgreSQL Database, and Elasticsearch) is containerized, you can launch the entire stack with a single command.

### 1. Clone the Repository
Open your terminal and clone the repository to your local machine:

```bash
git clone https://github.com/your-username/secureforge.git
cd secureforge
```

### 2. Launch the Platform
Make sure you are in the root `secureforge` directory (where the `docker-compose.yml` file is located) and run:

```bash
docker-compose up -d --build
```

### 3. Access the Platform
Once the terminal returns to the prompt and the containers have started, your platform is live!

- **SecureForge Dashboard (UI)**: [http://localhost:3001](http://localhost:3001)
- **Backend API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)

### 4. View Live Logs (Optional)
To view the raw Python engine output or debug modules, you can stream the backend logs:

```bash
docker logs -f secureforge-bas-engine-1
```
*(Press `Ctrl+C` to exit the log stream without killing the server).*

### 5. Shutting Down
When you are done testing and want to shut off the platform to free up RAM/CPU:

```bash
docker-compose down
```

> **Complete Wipe**: If you want to completely wipe all data (delete databases, simulation history, and logs) to start from a clean slate next time, run: `docker-compose down -v --rmi all`



---

## Running the Legacy Streamlit Dashboard

> The Streamlit dashboard in `dashboard/` is the older UI. It remains functional and useful for quick local use, but the Next.js frontend is the actively maintained interface. Use this if you need a minimal Python-only setup.

```bash
cd dashboard
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

The Streamlit app will open at `http://localhost:8501`.

---

## Kubernetes Deployment

All manifests are in `kubernetes/`. Apply them in order:

### 1. Create the namespace

```bash
kubectl apply -f kubernetes/namespace.yaml
```

### 2. Deploy the backend

```bash
kubectl apply -f kubernetes/bas-engine-deployment.yaml
kubectl apply -f kubernetes/bas-engine-service.yaml
```

### 3. Deploy the frontend

```bash
kubectl apply -f kubernetes/frontend-deployment.yaml
kubectl apply -f kubernetes/frontend-service.yaml
```

### 4. Deploy ELK

```bash
kubectl apply -f kubernetes/elk-deployment.yaml
kubectl apply -f kubernetes/elk-service.yaml
```

### 5. Apply HPA and metrics-server

```bash
kubectl apply -f kubernetes/metrics-server.yaml
kubectl apply -f kubernetes/hpa.yaml
```

### Verify everything is running

```bash
kubectl get pods -n secureforge
kubectl get services -n secureforge
kubectl top nodes
kubectl top pods -n secureforge
```

### Access Kibana

```bash
kubectl port-forward svc/kibana 5601:5601 -n secureforge
```

Then open `http://localhost:5601`.

### Apply all at once (if order doesn't matter for your setup)

```bash
kubectl apply -f kubernetes/
```

---

## Important Notes

- **Attack modules** are in `bas_engine/modules/`. Each module is a self-contained class that implements a standard interface. New modules can be added without modifying the core orchestrator.
- **Parallel simulations** are supported. The engine tracks each run independently with its own event stream.
- **Nmap scans** require Nmap to be installed on the machine running the backend (or inside the backend container). Scan options include custom subnet ranges, port lists, scan profiles (`SYN`, `TCP Connect`, `UDP`), timing profiles (`T1`–`T5`), and optional banner grabbing.
- **MITRE ATT&CK IDs** are assigned per finding at the module level. The MITRE page aggregates these across all runs.
- **SOC scoring** compares what was simulated against what was detected. Anything that ran but didn't generate a detection becomes a blind spot.
- **Alerts** are generated server-side when findings exceed configured severity thresholds. They're not just UI labels — they're stored and queryable.
- **Infrastructure metrics** require `metrics-server` to be installed in the cluster. Without it, CPU/memory data won't be available in the Infrastructure page.
- The WebSocket connection in the Realtime page will auto-reconnect on disconnect. Events are buffered server-side for replay.

---

## Troubleshooting

**Backend won't start — module import error**
Make sure you're running from the repo root, not from inside `bas_engine/`:
```bash
# from repo root
uvicorn bas_engine.main:app --host localhost --port 8000
```

**Frontend can't reach the backend**
Check that `NEXT_PUBLIC_API_URL` in `.env.local` matches where the backend is actually running. CORS is enabled in the FastAPI app by default for `localhost:3000`.

**WebSocket not connecting**
Confirm the backend is running and `NEXT_PUBLIC_WS_URL` points to the right host and port. If running behind a proxy or in Kubernetes, make sure WebSocket upgrade headers are forwarded.

**`kubectl top` returns no data**
`metrics-server` must be installed and running. Apply `kubernetes/metrics-server.yaml` and wait a minute for it to collect data.

**Nmap scan returns no results**
Ensure Nmap is installed on the backend host: `nmap --version`. If running in a container, confirm the image includes Nmap.

**Kibana shows no events**
Check that `LOGSTASH_HOST` and `LOGSTASH_PORT` in the backend environment are correct and that Logstash is reachable. Verify the index pattern in Kibana matches what the backend is forwarding.

**Streamlit dashboard shows stale data**
The legacy dashboard may not auto-refresh on all views. Reload the page or restart the Streamlit app if data appears out of sync.

---

## Disclaimer

SecureForge is designed exclusively for use in **authorized environments**. This means:

- You have explicit written permission to run simulations against the target systems and network.
- You are operating within a controlled lab, staging environment, or a production system where you have full authorization.
- You understand that attack simulation generates real network traffic and may trigger security tooling.

**Unauthorized use of this platform against systems you do not own or have permission to test is illegal.** The authors and contributors accept no liability for misuse.

---

## License

Review the `LICENSE` file in the repository root. This software is provided for authorized security testing and research purposes. Redistribution and commercial use may be subject to additional restrictions — check the license terms before deployment.

---

*Built for security teams that need to test their stack, not just assume it works.*