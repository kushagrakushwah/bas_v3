from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# ---------------------------------------------------
# ACTIVE CONNECTIONS
# ---------------------------------------------------

active_connections = []

# ---------------------------------------------------
# TICKETS
# ---------------------------------------------------

import uuid
import time
from typing import Dict
from fastapi import Depends
from bas_engine.api.middleware.api_key_auth import verify_api_key

valid_tickets: Dict[str, float] = {}

def create_ticket() -> str:
    ticket = str(uuid.uuid4())
    # valid for 60 seconds
    valid_tickets[ticket] = time.time() + 60
    return ticket

def validate_ticket(ticket: str) -> bool:
    if ticket in valid_tickets:
        if valid_tickets[ticket] > time.time():
            del valid_tickets[ticket]
            return True
        else:
            del valid_tickets[ticket]
    return False

@router.get("/api/v1/ws/ticket", dependencies=[Depends(verify_api_key)])
async def get_ws_ticket():
    return {"ticket": create_ticket()}

# ---------------------------------------------------
# WEBSOCKET ENDPOINT
# ---------------------------------------------------

@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    ticket: str = None
):
    if not ticket or not validate_ticket(ticket):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    active_connections.append(
        websocket
    )

    try:

        while True:

            # keep connection alive

            await websocket.receive_text()

    except WebSocketDisconnect:

        if websocket in active_connections:

            active_connections.remove(
                websocket
            )

# ---------------------------------------------------
# BROADCAST EVENT
# ---------------------------------------------------

async def broadcast_event(
    event
):
    import logging
    import json
    import datetime

    class DateTimeEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return super().default(obj)

    logger = logging.getLogger("secureforge.ws")
    logger.info(f"Broadcasting event to {len(active_connections)} connections: {event.get('type')}")
    
    disconnected = []

    try:
        payload = json.dumps(event, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Failed to serialize event: {e}")
        return

    for connection in active_connections:

        try:

            await connection.send_text(
                payload
            )

        except Exception:

            disconnected.append(
                connection
            )

    for conn in disconnected:

        if conn in active_connections:

            active_connections.remove(
                conn
            )

# ---------------------------------------------------
# CONNECTION STATS
# ---------------------------------------------------

def connection_count():

    return len(
        active_connections
    )