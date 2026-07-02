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
    auth,
    reports
)
from bas_engine.api.routes.ws import validate_ticket, cleanup_tickets_loop
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

# NEW-M: Add SlowAPI rate limiter
from bas_engine.api.middleware.rate_limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Rate limiter is imported from bas_engine.api.middleware.rate_limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "Accept"],
)

@app.middleware("http")
async def enforce_size_limit(request: Request, call_next):
    MAX_BYTES = 10 * 1024 * 1024  # 10 MB limit
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})
    return await call_next(request)

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
                    payload = jwt.decode(
                        token, 
                        _JWT_SECRET, 
                        algorithms=["HS256"],
                        options={"verify_iat": True, "verify_nbf": True}
                    )
                    request.state.role = payload.get("role", "Operator")
                except jwt.PyJWTError as e:
                    logger.debug(f"Middleware JWT parse failed: {e}")
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
        
    # Start WS ticket cleanup loop
    import asyncio
    asyncio.create_task(cleanup_tickets_loop())
    
    # --- REDIS EVENT LISTENER ---
    import json
    import redis.asyncio as redis_async
    async def redis_listener():
        redis_url = os.environ.get("REDIS_URL")
        if not redis_url: return
        try:
            r = redis_async.from_url(redis_url)
            pubsub = r.pubsub()
            await pubsub.subscribe("secureforge_events")
            while True:
                try:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if message and message["type"] == "message":
                        data = message["data"]
                        if isinstance(data, bytes):
                            data = data.decode('utf-8')
                        event = json.loads(data)
                        await forward_to_elk(event)
                except Exception as e:
                    logger.error(f"Redis get_message error: {e}")
                await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Redis listener error: {e}")
            
    asyncio.create_task(redis_listener())
    
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
app.include_router(
    reports.router,
    prefix="/api/v1",
    tags=["Reports"],
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

if __name__ == "__main__":
    uvicorn.run("main:app", host=os.getenv("API_HOST", "0.0.0.0"), port=8000, workers=1)  # nosec B104