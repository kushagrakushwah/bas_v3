from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from bas_engine.core.orchestrator import AttackOrchestrator
from bas_engine.core.event_bus import EventBus
from bas_engine.core.reporting.report_generator import ReportGenerator
from bas_engine.api.middleware.api_key_auth import verify_api_key

router = APIRouter(prefix="/reports", tags=["reports"])

# We instantiate these directly or they could be injected via Depends
# For simplicity, we just use the repository to fetch the sim result.
from bas_engine.repositories.simulation_repo import SimulationRepository
repo = SimulationRepository()

@router.get("/{sim_id}/markdown", response_class=PlainTextResponse)
async def get_report_markdown(sim_id: str, _ = Depends(verify_api_key)):
    sim = await repo.get_simulation(sim_id)
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
        
    generator = ReportGenerator()
    md_content = generator.generate_markdown(sim)
    return md_content
