from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_infrastructure():

    try:
        from kubernetes import (
            client,
            config
        )

        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()

        v1 = client.CoreV1Api()

        pod_list = v1.list_pod_for_all_namespaces()

        pods = []

        for pod in pod_list.items:

            pods.append(
                {
                    "name":
                        pod.metadata.name,

                    "namespace":
                        pod.metadata.namespace,

                    "status":
                        pod.status.phase,
                }
            )

        return {
            "pods": pods,
            "total": len(pods),
        }

    except Exception as e:

        return {
            "pods": [],
            "error": str(e),
        }