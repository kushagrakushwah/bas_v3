# ---------------------------------------------------
# SIGMA RULE TEMPLATES (Real detection logic)
# ---------------------------------------------------

SIGMA_TEMPLATES = {
    "T1110": {
        "title": "SSH Brute Force — Multiple Authentication Failures",
        "id": "c1f727c6-79df-4c3e-862d-965c71db621a",
        "status": "experimental",
        "description": "Detects SSH brute force via repeated auth failures from same source IP",
        "logsource": {
            "category": "authentication",
            "product": "linux"
        },
        "detection": {
            "selection": {
                "EventID": 4625,
                "process.name": "sshd"
            },
            "timeframe": "60s",
            "condition": "selection | count(source.ip) by source.ip > 5"
        },
        "falsepositives": [
            "Legitimate users with forgotten passwords",
            "Automated scripts with expired credentials"
        ],
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1110", "attack.t1110.001"]
    },
    "T1078": {
        "title": "Valid Accounts Usage — Suspicious Login Time",
        "id": "e2c362a2-386f-4796-98c5-920f04e8d388",
        "status": "experimental",
        "description": "Detects successful logins outside normal business hours",
        "logsource": {
            "category": "authentication",
            "product": "windows"
        },
        "detection": {
            "selection": {
                "EventID": 4624,
                "LogonType": [2, 10]
            },
            "condition": "selection"
        },
        "falsepositives": [
            "Administrators working after hours",
            "Automated overnight maintenance tasks"
        ],
        "level": "medium",
        "tags": ["attack.initial_access", "attack.t1078"]
    },
    "T1190": {
        "title": "Public Facing Application Exploit — Suspicious Payload",
        "id": "31b26f74-601e-450b-b1eb-73d8e5ffebcb",
        "status": "test",
        "description": "Detects common exploit patterns in HTTP requests (e.g., JNDI, ../, Union Select)",
        "logsource": {
            "category": "webserver",
            "product": "apache"
        },
        "detection": {
            "selection": {
                "cs-uri-query|contains": ["jndi:ldap", "../../../../", "UNION SELECT"]
            },
            "condition": "selection"
        },
        "falsepositives": ["Security scanners (e.g., Nessus, Qualys)"],
        "level": "high",
        "tags": ["attack.initial_access", "attack.t1190"]
    },
    "T1595": {
        "title": "Reconnaissance Scanning — High Rate of 404s",
        "id": "76495be2-6e21-4d3b-9a41-118ba8ec7b09",
        "status": "experimental",
        "description": "Detects active scanning by monitoring for a high volume of 404 Not Found errors from a single IP",
        "logsource": {
            "category": "webserver",
            "product": "nginx"
        },
        "detection": {
            "selection": {
                "sc-status": 404
            },
            "timeframe": "1m",
            "condition": "selection | count(c-ip) by c-ip > 50"
        },
        "falsepositives": ["Broken links on popular pages", "Aggressive web crawlers"],
        "level": "low",
        "tags": ["attack.reconnaissance", "attack.t1595"]
    },
    "T1486": {
        "title": "Data Encrypted for Impact — Ransomware Extension",
        "id": "e6f4773c-cf3d-4c55-93df-40cb1f71dfbc",
        "status": "stable",
        "description": "Detects file writes with common ransomware extensions",
        "logsource": {
            "category": "file_event",
            "product": "windows"
        },
        "detection": {
            "selection": {
                "EventID": 11,
                "TargetFilename|endswith": [".encrypted", ".locked", ".wannacry", ".crypt"]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate encryption software (rare to use these exact extensions)"],
        "level": "critical",
        "tags": ["attack.impact", "attack.t1486"]
    },
    "T1505": {
        "title": "Server Software Component — Web Shell Upload",
        "id": "a90425cc-f1b2-4d2d-94c6-4d0f77ea53bc",
        "status": "experimental",
        "description": "Detects creation of scripting files (php, jsp, aspx) in web application directories by the web server process",
        "logsource": {
            "category": "file_event",
            "product": "linux"
        },
        "detection": {
            "selection": {
                "process.name": ["nginx", "apache2", "httpd", "tomcat"],
                "file.path|startswith": ["/var/www/html/", "/opt/tomcat/webapps/"],
                "file.extension": ["php", "jsp", "aspx"]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate application updates by the web server (e.g., WordPress plugin install)"],
        "level": "high",
        "tags": ["attack.persistence", "attack.t1505", "attack.t1505.003"]
    },
    "T1548": {
        "title": "Privilege Escalation — Sudo Usage by Unauthorized User",
        "id": "f5d75ba6-7b89-4e0d-b47e-8c3397960fc5",
        "status": "experimental",
        "description": "Detects execution of sudo by users not typically authorized or unexpected commands",
        "logsource": {
            "category": "process_creation",
            "product": "linux"
        },
        "detection": {
            "selection": {
                "process.name": "sudo",
                "process.command_line|contains": ["/bin/bash", "/bin/sh", "su -"]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate admin activities"],
        "level": "medium",
        "tags": ["attack.privilege_escalation", "attack.t1548", "attack.t1548.003"]
    },
    "T1046": {
        "title": "Network Service Scanning — Nmap Usage",
        "id": "6d3c3d5e-63f5-4d7a-8f7f-2877fb6a18d3",
        "status": "test",
        "description": "Detects the execution of nmap for discovery",
        "logsource": {
            "category": "process_creation",
            "product": "linux"
        },
        "detection": {
            "selection": {
                "process.name": "nmap"
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate admin network scanning"],
        "level": "low",
        "tags": ["attack.discovery", "attack.t1046"]
    }
}
# ---------------------------------------------------
# DYNAMIC SIGMA RULE GENERATOR
# ---------------------------------------------------

import uuid
import datetime
import yaml

class SigmaGenerator:

    def __init__(self):
        self.supported_tactics = [
            "T1110", "T1078", "T1190", "T1595", "T1486", "T1505", "T1548", "T1046"
        ]

    # ------------------------------------------------
    # GENERATE RULE
    # ------------------------------------------------

    def generate_rule(
        self,
        finding: dict
    ):
        mitre_id = finding.get("mitre_id")
        if not mitre_id:
            return None

        # Base ID without sub-technique for high-level matching
        base_id = mitre_id.split('.')[0]
        
        # Extract evidence or payload if available
        evidence = finding.get("evidence", "No evidence provided")
        raw_data = finding.get("raw_data", {})
        
        # We will build a dynamic selection block based on the type of attack
        selection = {}
        logsource = {}
        condition = "selection"
        title = f"Dynamic Rule for {mitre_id}"
        desc = finding.get("title", f"Detects {mitre_id} activity")
        level = finding.get("severity", "medium").lower()

        if base_id == "T1110":
            title = "SSH Brute Force Detection"
            logsource = {"category": "authentication", "product": "linux"}
            selection = {"EventID": 4625, "process.name": "sshd"}
            condition = "selection | count(source.ip) by source.ip > 5"
            # Try to grab IP from evidence
            if "Target:" in evidence:
                target_ip = evidence.split("Target: ")[-1].split()[0]
                selection["destination.ip"] = target_ip
                
        elif base_id == "T1190":
            title = "Public Facing Application Exploit"
            logsource = {"category": "webserver", "product": "apache"}
            # Extract payload from evidence if possible
            payloads = []
            if "Payload:" in evidence:
                payload = evidence.split("Payload: ")[-1].split("\\n")[0].strip()
                payloads.append(payload)
            else:
                payloads = ["jndi:ldap", "../../../../", "UNION SELECT"]
            selection = {"cs-uri-query|contains": payloads}
            
        elif base_id == "T1505":
            title = "Web Shell Upload"
            logsource = {"category": "file_event", "product": "linux"}
            selection = {"process.name": ["nginx", "apache2", "httpd", "tomcat"]}
            if "Created:" in evidence:
                path = evidence.split("Created: ")[-1].strip()
                selection["file.path"] = path
            else:
                selection["file.extension"] = ["php", "jsp", "aspx"]

        elif base_id == "T1046":
            title = "Network Scanning Activity"
            logsource = {"category": "process_creation", "product": "linux"}
            selection = {"process.name": ["nmap", "masscan", "rustscan"]}
            if "Target:" in evidence:
                target_ip = evidence.split("Target: ")[-1].strip()
                selection["process.command_line|contains"] = target_ip

        elif base_id == "T1486":
            title = "Ransomware File Extension"
            logsource = {"category": "file_event", "product": "windows"}
            selection = {"EventID": 11, "TargetFilename|endswith": [".encrypted", ".locked"]}
            
        else:
            # Generic template for other MITRE IDs
            title = f"Generic rule for {mitre_id}"
            logsource = {"category": "process_creation", "product": "windows"}
            selection = {"EventID": 1}

        # Construct the Sigma Dict
        rule_id = str(uuid.uuid4())
        date_str = datetime.datetime.utcnow().strftime("%Y/%m/%d")
        
        sigma_dict = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": desc,
            "date": date_str,
            "author": "SecureForge BAS",
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": condition
            },
            "falsepositives": ["Legitimate administrative activity", "Security scanners"],
            "level": level,
            "tags": [f"attack.{base_id.lower()}"]
        }
        
        # Convert to YAML
        try:
            sigma_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)
        except Exception:
            sigma_yaml = str(sigma_dict)

        return {
            "status": "success",
            "sigma_rule": sigma_yaml,
            "mitre_id": mitre_id
        }

    # ------------------------------------------------
    # GENERATE MULTIPLE
    # ------------------------------------------------

    def generate_rules(
        self,
        findings: list
    ):
        rules = []
        seen_ids = set()

        for finding in findings:
            # We don't want identical rules for the same finding
            # but payloads might be different. Let's just generate for all.
            generated = self.generate_rule(finding)
            if generated:
                rules.append(generated)

        return rules