from fastapi import APIRouter
import logging

router = APIRouter()
logger = logging.getLogger("secureforge.metrics")

@router.get("/")
async def get_metrics():
    try:
        from kubernetes import client, config
        
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
            
        api = client.CustomObjectsApi()
        k8s_nodes = client.CoreV1Api().list_node().items
        
        # Get metrics from metrics-server
        metrics = api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
        
        nodes = []
        cpu_total = 0
        mem_total = 0
        
        # We need node capacity to calculate percentage
        capacity_map = {}
        for n in k8s_nodes:
            cpu_alloc = n.status.allocatable.get('cpu', '1')
            mem_alloc = n.status.allocatable.get('memory', '1000000Ki')
            
            # Very basic parsing (assumes cores are integers or 'm' for milli, memory in Ki)
            c_val = float(cpu_alloc) if 'm' not in str(cpu_alloc) else float(cpu_alloc.replace('m',''))/1000.0
            m_val = float(mem_alloc.replace('Ki','')) if 'Ki' in mem_alloc else 1000000.0
            
            capacity_map[n.metadata.name] = {'cpu': c_val, 'memory': m_val}
            
        for item in metrics.get('items', []):
            name = item['metadata']['name']
            usage = item['usage']
            
            # usage cpu is typically '150m' or '10000000n', memory '1000000Ki'
            cpu_u = usage.get('cpu', '0n')
            mem_u = usage.get('memory', '0Ki')
            
            if 'n' in cpu_u:
                c_used = float(cpu_u.replace('n','')) / 1e9
            elif 'm' in cpu_u:
                c_used = float(cpu_u.replace('m','')) / 1e3
            else:
                c_used = float(cpu_u)
                
            m_used = float(mem_u.replace('Ki','').replace('Mi','').replace('Gi','')) if any(x in mem_u for x in ['Ki','Mi','Gi']) else 0.0
            if 'Mi' in mem_u: m_used *= 1024
            if 'Gi' in mem_u: m_used *= 1024 * 1024
            
            cap = capacity_map.get(name, {'cpu': 1.0, 'memory': 1.0})
            
            cpu_pct = int((c_used / cap['cpu']) * 100) if cap['cpu'] > 0 else 0
            mem_pct = int((m_used / cap['memory']) * 100) if cap['memory'] > 0 else 0
            
            # clamp
            cpu_pct = min(100, max(0, cpu_pct))
            mem_pct = min(100, max(0, mem_pct))
            
            nodes.append({
                "name": name,
                "cpu_percent": cpu_pct,
                "memory_percent": mem_pct
            })
            
            cpu_total += cpu_pct
            mem_total += mem_pct

        count = max(len(nodes), 1)

        return {
            "cpu_percent": round(cpu_total / count),
            "memory_percent": round(mem_total / count),
            "nodes": nodes,
            "node_count": len(nodes),
        }

    except Exception as e:
        logger.error(f"Metrics fetch failed: {e}")
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "nodes": [],
            "node_count": 0,
            "error": str(e),
        }