from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from bas_engine.services.replay_service import (
    ReplayService
)

router = APIRouter()

replay_service = ReplayService()


# ------------------------------------------------
# TIMELINE BY SIMULATION
# ------------------------------------------------

@router.get("/{sim_id}")

async def replay_simulation(
    sim_id: str
):

    return await replay_service.get_simulation_timeline(
        sim_id
    )

# ------------------------------------------------
# STREAM EVENTS TIMELINE (SSE)
# ------------------------------------------------
@router.get("/{sim_id}/stream")
async def stream_simulation_timeline(sim_id: str):
    return StreamingResponse(
        replay_service.stream_timeline(sim_id),
        media_type="text/event-stream"
    )

# ------------------------------------------------
# STORED TIMELINE REPLAY (HONEST MODE)
# ------------------------------------------------
# We have removed true re-execution replay. 
# Replay now uses the honest stored_timeline mode.

# ------------------------------------------------
# RECENT EVENTS
# ------------------------------------------------

@router.get("/recent/events")

async def recent_events():

    return await replay_service.get_recent_events()