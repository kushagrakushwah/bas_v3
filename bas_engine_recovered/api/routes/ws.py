from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import uuid
import time
from typing import Dict
from fastapi import Depends
from bas_engine.api.middleware.api_key_auth import verify_api_key
import logging
import json
import datetime

router = APIRouter()
logger = logging.getLogger("secureforge.ws")

# ---------------------------------------------------
# ACTIVE CONNECTIONS (Thread-safe)
# ---------------------------------------------------

class SafeConnectionSet:
    def __init__(self):
        self.connections = set()
        self.lock = asyncio.Lock()
        
    async def add(self, websocket: WebSocket):
        async with self.lock:
            self.connections.add(websocket)
            
    async def remove(self, websocket: WebSocket):
        async with self.lock:
            self.connections.discard(websocket)
            
    async def get_all(self):
        async with self.lock:
            return list(self.connections)
            
    async def count(self):
        async with self.lock:
            return len(self.connections)

active_connections = SafeConnectionSet()

# ---------------------------------------------------
# TICKETS
# ---------------------------------------------------

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

async def cleanup_tickets_loop():
    """Background task to remove expired WebSocket tickets periodically."""
    while True:
        await asyncio.sleep(60)  # run every 60 seconds
        now = time.time()
        expired = [k for k, v in valid_tickets.items() if v < now]
        for k in expired:
            valid_tickets.pop(k, None)

@router.get("/api/v1/ws/ticket", dependencies=[Depends(verify_api_key)])
async def get_ws_ticket():
    return {"ticket": create_ticket()}

# ---------------------------------------------------
# WEBSOCKET ENDPOINT
# ---------------------------------------------------

MAX_WS_MESSAGE_BYTES = 4096

@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    ticket: str = None
):
    if not ticket or not validate_ticket(ticket):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await active_connections.add(websocket)

    try:
        while True:
            # wait for text with keepalive timeout
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if len(msg.encode('utf-8')) > MAX_WS_MESSAGE_BYTES:
                    logger.warning("WebSocket client exceeded message size limit")
                    await websocket.close(code=1009)
                    break
                # Currently we don't process client messages other than keepalives,
                # but we could reply with a pong if needed.
            except asyncio.TimeoutError:
                # keepalive ping to ensure connection is still alive
                await websocket.send_text('{"type": "ping"}')
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await active_connections.remove(websocket)

# ---------------------------------------------------
# BROADCAST EVENT
# ---------------------------------------------------

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

async def broadcast_event(event):
    conns = await active_connections.get_all()
    logger.info(f"Broadcasting event to {len(conns)} connections: {event.get('type')}")
    
    try:
        payload = json.dumps(event, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Failed to serialize event: {e}")
        return

    disconnected = []
    for connection in conns:
        try:
            await connection.send_text(payload)
        except Exception:
            disconnected.append(connection)

    for conn in disconnected:
        await active_connections.remove(conn)

# ---------------------------------------------------
# CONNECTION STATS
# ---------------------------------------------------

async def connection_count():
    return await active_connections.count()