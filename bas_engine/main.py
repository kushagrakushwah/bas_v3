from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
import os
from datetime import datetime
from bas_engine.alerts.alert_manager import (
    process_alert
)
from bas_engine.api.routes.recon import (
    router as recon_router
)
from fastapi import WebSocket, Depends

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
    integrations,
    auth
)
from bas_engine.api.routes.ws import validate_ticket
from bas_engine.core.orchestrator import AttackOrchestrator
from bas_engine.core.event_bus import EventBus
from bas_engine.utils.logger import setup_logging
from bas_engine.utils.elk_client import ELKClient
from bas_engine.database.connection import engine, Base
import bas_engine.database.models
from bas_engine.api.middleware.api_key_auth import verify_api_key, verify_api_key_value, verify_jwt_token, _JWT_SECRET

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
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public paths that bypass API key auth
PUBLIC_PATH_PREFIXES = (
    "/api/v1/health",
    "/ws/",
    "/",
)

@app.middleware("http")
async def global_api_key_middleware(request: Request, call_next):
    """Enforce API key on all /api/v1/ routes except public paths."""
    request.state.role = "Operator" # Default role
    path = request.url.path
    # Allow public paths and WebSocket upgrades
    if path == "/" or path.startswith("/ws/") or path.startswith("/api/v1/health") or path.startswith("/api/v1/auth"):
        return await call_next(request)
    # Enforce key on all other API paths
    if path.startswith("/api/v1/"):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            if verify_jwt_token(token):
                import jwt
                try:
                    payload = jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
                    request.state.role = payload.get("role", "Operator")
                except:
                    pass
                return await call_next(request)

        key = request.headers.get("X-API-Key", "")
        if verify_api_key_value(key):
            request.state.role = "Administrator"
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={"detail": "Invalid or missing authentication. Pass Authorization Bearer token or X-API-Key."}
        )
    return await call_next(request)

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
    
    # Clean up orphaned simulations
    from bas_engine.database.connection import AsyncSessionLocal
    from sqlalchemy import update
    from bas_engine.database.models import SimulationDB
    from bas_engine.models.simulation import SimulationStatus
    
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(SimulationDB)
            .where(SimulationDB.status.in_([SimulationStatus.RUNNING, SimulationStatus.QUEUED]))
            .values(status=SimulationStatus.FAILED)
        )
        await session.commit()
    
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
        except Exception as e:
            logger.debug(f"ELK Forwarding error: {e}")

        try:
            # -------------------------------------------
            # ALERT PIPELINE
            # -------------------------------------------
            await process_alert(event)
            await ws.broadcast_event(event)
        except Exception as e:
            logger.error(f"Event broadcast error: {e}")
    app.state.event_bus.subscribe("*", forward_to_elk)
    logger.info("  All services initialized and ELK telemetry wired.")

@app.on_event("shutdown")
async def shutdown():
    logger.info("SecureForge shutting down...")
    await app.state.elk_client.close()

# Routers
app.include_router(health.router, prefix="/api/v1/health", tags=["Health"])
app.include_router(
    modules.router,
    prefix="/api/v1/modules",
    tags=["Attack Modules"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    simulations.router,
    prefix="/api/v1/simulations",
    tags=["Simulations"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    results.router, 
    prefix="/api/v1/results", 
    tags=["Results"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    events.router,
    prefix="/api/v1/events",
    tags=["Events"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    infrastructure.router,
    prefix="/api/v1/infrastructure",
    tags=["Infrastructure"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    integrations.router,
    prefix="/api/v1/integrations",
    tags=["Integrations"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    auth.router,
    prefix="/api/v1/auth",
    tags=["Authentication"]
    # No API key dependency here, it is public
)
app.include_router(
    metrics.router,
    prefix="/api/v1/metrics",
    tags=["Metrics"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(
    replay.router,
    prefix="/api/v1/replay",
    tags=["Replay"],
    dependencies=[Depends(verify_api_key)]
)
app.include_router(ws.router)
@app.get("/")
async def root():
    return {"status": "operational", "service": "SecureForge BAS Engine"}
app.include_router(
    recon_router,
    prefix="/api/v1/recon",
    tags=["Recon"],
    dependencies=[Depends(verify_api_key)]
)
@app.websocket("/ws/global")
async def global_websocket(
    websocket: WebSocket,
    ticket: str = None
):
    if not ticket or not validate_ticket(ticket):
        await websocket.close(code=1008)
        return

    await websocket.accept()
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

if __name__ == "__main__":
    uvicorn.run("main:app", host=os.getenv("API_HOST", "0.0.0.0"), port=8000, workers=1)  # nosec B104