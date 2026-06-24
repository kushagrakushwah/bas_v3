from fastapi import APIRouter, Request, HTTPException
from bas_engine.models.simulation import SimulationRequest, SimulationResult, SimulationSummary
from typing import List

router = APIRouter()

@router.post("/", response_model=SimulationResult)
async def launch_simulation(request: Request, sim_req: SimulationRequest):
    """Launch a new Breach & Attack Simulation."""
    if sim_req.detailed_enumeration and getattr(request.state, "role", "") != "Administrator":
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required to launch red team modules."
        )
    orchestrator = request.app.state.orchestrator
    return await orchestrator.launch(sim_req)

@router.get("/", response_model=List[SimulationResult])
async def list_simulations(request: Request):
    """List all historical and running simulations."""
    return await request.app.state.orchestrator.list_all()

@router.get("/summary", response_model=SimulationSummary)
async def get_summary(request: Request):
    """Get high-level statistics for the dashboard."""
    return await request.app.state.orchestrator.summary()