import logging
from fastapi import APIRouter, Request, HTTPException
from bas_engine.models.simulation import SimulationRequest, SimulationResult, SimulationSummary
from typing import List

router = APIRouter()
_audit_logger = logging.getLogger("secureforge.audit")


@router.post("/", response_model=SimulationResult)
async def launch_simulation(request: Request, sim_req: SimulationRequest):
    """Launch a new Breach & Attack Simulation."""
    role = getattr(request.state, "role", "Operator")

    if sim_req.detailed_enumeration and role != "Administrator":
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required to launch red team modules.",
        )

    # #77 fix: structured audit trail — every simulation launch is logged with
    # operator identity, source IP, target, and selected modules so that all
    # red-team activity on the platform has a durable paper trail.
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    _audit_logger.info(
        "SIMULATION_LAUNCH | role=%s | ip=%s | target=%s | modules=%s | detailed_enum=%s | name=%r",
        role,
        client_ip,
        sim_req.target,
        ",".join(sim_req.modules),
        sim_req.detailed_enumeration,
        sim_req.name,
    )

    orchestrator = request.app.state.orchestrator
    try:
        return await orchestrator.launch(sim_req, role=role)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

@router.get("/", response_model=List[SimulationResult])
async def list_simulations(request: Request):
    """List all historical and running simulations."""
    return await request.app.state.orchestrator.list_all()

@router.get("/summary", response_model=SimulationSummary)
async def get_summary(request: Request):
    """Get high-level statistics for the dashboard."""
    return await request.app.state.orchestrator.summary()