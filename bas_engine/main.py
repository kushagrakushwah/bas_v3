from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
from datetime import datetime
from bas_engine.alerts.alert_manager import (
    process_alert
)
from bas_engine.api.routes.recon import (
    router as recon_router
)
from fastapi import WebSocket

from bas_engine.core.events.ws_manager import (
    manager
)
from bas_engine.api.routes import (
    simulations,
    modules,
    results,
    health,
    events,
    ws,
    metrics,
    replay,
    infrastructure,
    integrations
)
from bas_engine.core.orchestrator import AttackOrchestrator
from bas_engine.core.event_bus import EventBus
from bas_engine.utils.logger import setup_logging
from bas_engine.utils.elk_client import ELKClient
from bas_engine.database.connection import engine, Base
import bas_engine.database.models

# Setup
setup_logging()
logger = logging.getLogger("secureforge")

app = FastAPI(
    title="SecureForge BAS Engine",
    description="Breach & Attack Simulation Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    logger.info("  SecureForge BAS Engine starting up...")
    app.state.event_bus   = EventBus()
    app.state.orchestrator = AttackOrchestrator(app.state.event_bus)
    app.state.elk_client  = ELKClient()
    await app.state.elk_client.connect()
    
    # Initialize Database Tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # --- THE MISSING WIRE ---
    # Listen to all internal events and forward them to Logstash
    async def forward_to_elk(event):

        try:

            # -------------------------------------------
            # ELK PIPELINE
            # -------------------------------------------

            await app.state.elk_client.push_event(
                "secureforge-bas",
                event
            )

            # -------------------------------------------
            # ALERT PIPELINE
            # -------------------------------------------

            await process_alert(event)
            await ws.broadcast_event(event)

        except Exception as e:

            logger.debug(
                f"ELK Forwarding error: {e}"
            )
    app.state.event_bus.subscribe("*", forward_to_elk)
    logger.info("  All services initialized and ELK telemetry wired.")

@app.on_event("shutdown")
async def shutdown():
    logger.info("SecureForge shutting down...")
    await app.state.elk_client.close()

# Routers
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(modules.router, prefix="/api/v1/modules", tags=["Attack Modules"])
app.include_router(simulations.router, prefix="/api/v1/simulations", tags=["Simulations"])
app.include_router(results.router, prefix="/api/v1/results", tags=["Results"])
app.include_router(
    events.router,
    prefix="/api/v1/events",
    tags=["Events"]
)
app.include_router(
    infrastructure.router,
    prefix="/api/v1/infrastructure",
    tags=["Infrastructure"]
)
app.include_router(
    integrations.router,
    prefix="/api/v1/integrations",
    tags=["Integrations"]
)
app.include_router(
    metrics.router,
    prefix="/api/v1/metrics",
    tags=["Metrics"],
)
app.include_router(
    replay.router,
    prefix="/api/v1/replay",
    tags=["Replay"]
)
app.include_router(ws.router)
@app.get("/")
async def root():
    return {"status": "operational", "service": "SecureForge BAS Engine"}
app.include_router(

    recon_router,

    prefix="/api/v1/recon",

    tags=["Recon"]
)
@app.websocket("/ws/global")
async def global_websocket(
    websocket: WebSocket
):
    await manager.connect(
        "global",
        websocket
    )

    try:
        while True:
            await websocket.receive_text()

    except Exception:
        manager.disconnect(
            "global",
            websocket
        )

    await manager.connect(

        simulation_id,

        websocket
    )

    try:

        while True:

            await websocket.receive_text()

    except Exception:

        manager.disconnect(

            simulation_id,

            websocket
        )
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, workers=1)