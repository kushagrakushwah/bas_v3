"""
Network Topology Engine

Future:
- attack path visualization
- subnet relationships
- lateral movement graphing
"""

from typing import List, Dict


class NetworkTopology:

    def build_topology(
        self,
        hosts: List[Dict],
    ) -> Dict:
        nodes = []
        edges = []
        
        import ipaddress

        subnets = {}

        for host in hosts:
            host_ip = host.get("host")
            if not host_ip: continue
            
            nodes.append({
                "id": host_ip,
                "label": host.get("hostname") or host_ip,
                "ports": host.get("open_ports", [])
            })
            
            try:
                ip = ipaddress.ip_address(host_ip)
                if isinstance(ip, ipaddress.IPv4Address):
                    # Group by /24 for simple visual topology mapping
                    subnet = str(ipaddress.ip_network(f"{host_ip}/24", strict=False))
                    if subnet not in subnets:
                        subnets[subnet] = []
                    subnets[subnet].append(host_ip)
            except ValueError:
                pass
                
        # Create edges between hosts in the same subnet
        for subnet, ips in subnets.items():
            for i in range(len(ips)):
                for j in range(i + 1, len(ips)):
                    edges.append({
                        "from": ips[i],
                        "to": ips[j],
                        "label": "same_subnet"
                    })

        return {
            "nodes": nodes,
            "edges": edges,
        }