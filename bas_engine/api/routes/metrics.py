from fastapi import APIRouter
import subprocess

router = APIRouter()


@router.get("/")
async def get_metrics():

    try:

        # -------------------------
        # NODE METRICS
        # -------------------------

        output = subprocess.check_output(
            [
                "kubectl",
                "top",
                "nodes",
                "--no-headers",
            ]
        )

        lines = (
            output.decode()
            .strip()
            .splitlines()
        )

        nodes = []

        cpu_total = 0
        mem_total = 0

        for line in lines:

            parts = line.split()

            node = {
                "name": parts[0],
                "cpu_percent": int(
                    parts[2].replace(
                        "%",
                        ""
                    )
                ),
                "memory_percent": int(
                    parts[4].replace(
                        "%",
                        ""
                    )
                ),
            }

            cpu_total += node[
                "cpu_percent"
            ]

            mem_total += node[
                "memory_percent"
            ]

            nodes.append(node)

        count = max(
            len(nodes),
            1
        )

        return {
            "cpu_percent": round(
                cpu_total / count
            ),
            "memory_percent": round(
                mem_total / count
            ),
            "nodes": nodes,
            "node_count": len(
                nodes
            ),
        }

    except Exception as e:

        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "nodes": [],
            "node_count": 0,
            "error": str(e),
        }