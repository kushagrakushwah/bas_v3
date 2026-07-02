"""
Health Check Endpoint
=====================
Returns the live health of every critical dependency.

NEW-4 fix: the previous static stub always returned 200 regardless of whether
Postgres, Redis, Celery, or Elasticsearch were reachable. This gave operators
no signal that simulations were being queued into a void.

The endpoint now performs a real connectivity probe against each dependency
and returns a 200 only when all are healthy. Any single failure returns 503
with a per-service breakdown so the operator knows exactly what is down.
"""

import asyncio
import os
import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger("secureforge.health")

router = APIRouter()


async def _check_postgres() -> dict:
    """Verify the PostgreSQL connection pool is alive."""
    try:
        from bas_engine.database.connection import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "healthy"}
    except Exception as exc:
        logger.warning(f"Health: Postgres probe failed — {exc}")
        return {"status": "degraded", "error": str(exc)}


async def _check_redis() -> dict:
    """Verify the Redis broker responds to PING."""
    try:
        import redis.asyncio as aioredis
        redis_url = os.environ.get("REDIS_URL")
        if not redis_url:
            return {"status": "unconfigured"}
        r = aioredis.from_url(redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        return {"status": "healthy"}
    except Exception as exc:
        logger.warning(f"Health: Redis probe failed — {exc}")
        return {"status": "degraded", "error": str(exc)}


async def _check_celery() -> dict:
    """
    Verify at least one Celery worker is alive by inspecting active workers.
    Uses a 2-second timeout so the health endpoint never hangs.
    """
    try:
        from bas_engine.worker import celery_app
        # run_in_executor to avoid blocking the event loop on Celery I/O
        loop = asyncio.get_running_loop()
        inspect = await loop.run_in_executor(
            None, lambda: celery_app.control.inspect(timeout=2).ping()
        )
        if inspect:
            return {"status": "healthy", "workers": len(inspect)}
        return {"status": "degraded", "error": "No Celery workers responded"}
    except Exception as exc:
        logger.warning(f"Health: Celery probe failed — {exc}")
        return {"status": "degraded", "error": str(exc)}


async def _check_elasticsearch() -> dict:
    """Verify Elasticsearch is reachable via its cluster health API."""
    try:
        import aiohttp
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{es_url}/_cluster/health",
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                data = await resp.json()
                colour = data.get("status", "red")
                if colour in ("green", "yellow"):
                    return {"status": "healthy", "cluster_status": colour}
                return {"status": "degraded", "cluster_status": colour}
    except Exception as exc:
        logger.warning(f"Health: Elasticsearch probe failed — {exc}")
        return {"status": "degraded", "error": str(exc)}


@router.get("")
async def health_check():
    """
    Live dependency health check.

    Returns 200 only when all critical services are reachable.
    Returns 503 with a per-service breakdown on any failure.
    """
    postgres, redis, celery, elasticsearch = await asyncio.gather(
        _check_postgres(),
        _check_redis(),
        _check_celery(),
        _check_elasticsearch(),
        return_exceptions=False,
    )

    services = {
        "postgres":      postgres,
        "redis":         redis,
        "celery":        celery,
        "elasticsearch": elasticsearch,
    }

    all_healthy = all(
        s.get("status") == "healthy"
        for s in services.values()
    )

    status_code = 200 if all_healthy else 503
    overall = "healthy" if all_healthy else "degraded"

    # NEW-I: Sanitize internal error messages so we don't leak connection strings or topology
    sanitized_services = {}
    for name, data in services.items():
        if data.get("status") == "healthy":
            sanitized_services[name] = data
        else:
            sanitized_services[name] = {"status": data.get("status"), "error": "service unavailable"}

    return JSONResponse(
        status_code=status_code,
        content={
            "status":  overall,
            "service": "secureforge-bas",
            "services": sanitized_services,
        },
    )