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
        # Fallback for docker-compose local environment
        import psutil
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
        except:
            cpu = 0
            mem = 0

        fallback_pods = [
            {"name": "secureforge-bas-engine-1", "namespace": "docker-compose", "status": "Running"},
            {"name": "secureforge-postgres-1", "namespace": "docker-compose", "status": "Running"},
            {"name": "secureforge-elasticsearch-1", "namespace": "docker-compose", "status": "Running"},
            {"name": "secureforge-logstash-1", "namespace": "docker-compose", "status": "Running"},
            {"name": "secureforge-kibana-1", "namespace": "docker-compose", "status": "Running"},
        ]

        return {
            "pods": fallback_pods,
            "total": len(fallback_pods),
            "cpu_usage": cpu,
            "memory_usage": mem,
            "error": str(e),
        }