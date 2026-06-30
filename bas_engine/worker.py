import os
import asyncio
from celery import Celery
import logging

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
    worker_concurrency=4
)

@celery_app.task(bind=True, name="run_simulation_task")
def run_simulation_task(self, sim_id: str, request_data: dict, role: str):
    """
    Celery task that runs the simulation synchronously by wrapping the asyncio execution.
    """
    logger.info(f"Starting background simulation task for {sim_id}")
    
    # We must instantiate the required dependencies per worker process
    event_bus = EventBus()
    orchestrator = AttackOrchestrator(event_bus)
    request = SimulationRequest.construct(**request_data)
    
    # Run the async loop
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    try:
        # We invoke the orchestrator's inner run method
        loop.run_until_complete(orchestrator._run_simulation(sim_id, request))
        return {"status": "success", "sim_id": sim_id}
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logger.error(f"Task failed with traceback: {tb}")
        return {"status": "failed", "sim_id": sim_id, "error": str(e), "traceback": tb}
