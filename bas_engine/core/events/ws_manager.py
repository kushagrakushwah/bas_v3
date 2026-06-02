"""
WebSocket Connection Manager
"""

from collections import defaultdict

from fastapi import WebSocket


class WSManager:

    def __init__(self):

        self.connections = (
            defaultdict(list)
        )

    async def connect(

        self,

        simulation_id,

        websocket: WebSocket,
    ):

        await websocket.accept()

        self.connections[
            simulation_id
        ].append(websocket)

    def disconnect(

        self,

        simulation_id,

        websocket,
    ):

        if simulation_id in self.connections:

            if (
                websocket
                in self.connections[
                    simulation_id
                ]
            ):

                self.connections[
                    simulation_id
                ].remove(websocket)

    async def broadcast(

        self,

        simulation_id,

        data,
    ):

        dead_connections = []

        for ws in self.connections.get(

            simulation_id,

            []
        ):

            try:

                await ws.send_json(
                    data
                )

            except Exception:

                dead_connections.append(
                    ws
                )

        for ws in dead_connections:

            self.disconnect(

                simulation_id,

                ws
            )

    async def broadcast_global(

        self,

        data,
    ):

        dead_connections = []

        for ws in self.connections.get(

            "global",

            []
        ):

            try:

                await ws.send_json(
                    data
                )

            except Exception:

                dead_connections.append(
                    ws
                )

        for ws in dead_connections:

            self.disconnect(

                "global",

                ws
            )

    async def broadcast_all(

        self,

        simulation_id,

        data,
    ):

        await self.broadcast(

            simulation_id,

            data
        )

        await self.broadcast_global(
            data
        )


manager = WSManager()