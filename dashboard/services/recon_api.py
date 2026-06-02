import requests


API_URL = (
    "http://127.0.0.1:8000"
)


def discover_subnet(

    target,
    ports,
):

    response = requests.get(

        f"{API_URL}/api/v1/recon/discover",

        params={

            "target": target,

            "ports": ports,
        }
    )

    return response.json()