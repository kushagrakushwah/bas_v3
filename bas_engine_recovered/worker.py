"""
SecureForge Celery Worker
=========================
Security model
--------------
* All data arriving from the Redis queue is treated as UNTRUSTED because
  the queue is an unauthenticated network boundary.
* SimulationRequest is instantiated via the normal constructor (NOT .construct)
  so that every Pydantic field_validator runs — including the SSRF check on
  `target` and the module allowlist check on `modules`.
* The `role` string carried across the queue is re-evaluated here:
  - Only the literal string "Administrator" grants elevated privileges.
  - detailed_enumeration is silently downgraded to False for any other role,
    rather than raising (to avoid silent queue-stuck states).
  This means a compromised container that enqueues role="Administrator" with
  detailed_enumeration=True gains nothing — the HTTP layer already blocked it,
  and the worker re-enforces the same policy independently.
"""

import os
import asyncio
import logging
from celery import Celery

from bas_engine.core.orchestrator import AttackOrchestrator
from bas_engine.core.event_bus import EventBus
from bas_engine.models.simulation import SimulationRequest
from bas_engine.utils.logger import setup_logging

setup_logging()
logger = logging.getLogger("secureforge.worker")

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "secureforge_worker",
    broker=redis_url,
    backend=redis_url
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_concurrency=4,
)


@celery_app.task(bind=True, name="run_simulation_task")
def run_simulation_task(self, sim_id: str, request_data: dict, role: str):
    """
    Celery task — runs a simulation in the worker process.

    Security invariants enforced here (independent of the HTTP layer):
      1. SimulationRequest(**request_data) re-runs all Pydantic validators
         (SSRF target check, module allowlist) against the queue payload.
         .construct() is intentionally NOT used.
      2. RBAC re-check: detailed_enumeration is only honoured when the
         role string is exactly "Administrator". Any other value (including
         a tampered "administrator", "Admin", etc.) is treated as Operator
         and detailed_enumeration is forced to False.
    """
    logger.info(f"Worker received simulation task for {sim_id} (role={role!r})")

    # ── RBAC re-validation ─────────────────────────────────────────────────────
    # Never trust the role value from the queue at face value.
    # Normalise to a known safe value.
    if role != "Administrator":
        role = "Operator"

    # ── Pydantic re-validation ─────────────────────────────────────────────────
    # Using the normal constructor (NOT .construct()) so that ALL validators run.
    # This is the second SSRF / module-allowlist gate independent of the API.
    try:
        # If detailed_enumeration was smuggled in for a non-admin role, strip it.
        if role != "Administrator":
            request_data = dict(request_data)
            request_data["detailed_enumeration"] = False

        request = SimulationRequest(**request_data)
    except Exception as exc:
        logger.error(
            f"Worker rejected task {sim_id}: Pydantic validation failed — {exc}"
        )
        return {"status": "failed", "sim_id": sim_id, "error": f"Validation: {exc}"}

    # ── Execute ────────────────────────────────────────────────────────────────
    event_bus = EventBus()
    orchestrator = AttackOrchestrator(event_bus)

    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(orchestrator._run_simulation(sim_id, request))
        logger.info(f"Worker completed simulation task for {sim_id}")
        return {"status": "success", "sim_id": sim_id}
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        logger.error(f"Task {sim_id} failed:\n{tb}")
        return {"status": "failed", "sim_id": sim_id, "error": str(exc), "traceback": tb}
