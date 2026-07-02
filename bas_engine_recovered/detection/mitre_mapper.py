# ---------------------------------------------------
# MITRE ATT&CK TACTIC MAPPING
# ---------------------------------------------------

MITRE_TACTICS = {

    # ------------------------------------------------
    # INITIAL ACCESS
    # ------------------------------------------------

    "T1190": "Initial Access",
    "T1133": "Initial Access",
    "T1078": "Initial Access",
    "T1195": "Initial Access",
    "T1195.002": "Initial Access",

    # ------------------------------------------------
    # EXECUTION
    # ------------------------------------------------

    "T1059": "Execution",
    "T1059.007": "Execution",
    "T1203": "Execution",

    # ------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------

    "T1098": "Persistence",
    "T1053": "Persistence",
    "T1053.003": "Persistence",
    "T1505": "Persistence",
    "T1543.002": "Persistence",

    # ------------------------------------------------
    # PRIVILEGE ESCALATION
    # ------------------------------------------------

    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    "T1548.001": "Privilege Escalation",
    "T1548.003": "Privilege Escalation",
    "T1574.007": "Privilege Escalation",
    "T1611": "Privilege Escalation",

    # ------------------------------------------------
    # DEFENSE EVASION
    # ------------------------------------------------

    "T1027": "Defense Evasion",
    "T1562": "Defense Evasion",

    # ------------------------------------------------
    # CREDENTIAL ACCESS
    # ------------------------------------------------

    "T1110": "Credential Access",
    "T1110.001": "Credential Access",
    "T1003": "Credential Access",
    "T1552": "Credential Access",
    "T1557": "Credential Access",

    # ------------------------------------------------
    # RECONNAISSANCE
    # ------------------------------------------------

    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",

    # ------------------------------------------------
    # DISCOVERY
    # ------------------------------------------------

    "T1046": "Discovery",
    "T1087": "Discovery",
    "T1083": "Discovery",
    "T1590": "Discovery",

    # ------------------------------------------------
    # LATERAL MOVEMENT
    # ------------------------------------------------

    "T1021": "Lateral Movement",
    "T1021.001": "Lateral Movement",
    "T1021.002": "Lateral Movement",

    # ------------------------------------------------
    # COLLECTION
    # ------------------------------------------------

    "T1114": "Collection",

    # ------------------------------------------------
    # EXFILTRATION
    # ------------------------------------------------

    "T1041": "Exfiltration",
    "T1020": "Exfiltration",
    "T1530": "Exfiltration",
    # ------------------------------------------------
    # COMMAND AND CONTROL
    # ------------------------------------------------

    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1105": "Command and Control",
    "T1573": "Command and Control",
    # ------------------------------------------------
    # IMPACT
    # ------------------------------------------------

    "T1486": "Impact",
    "T1490": "Impact",
    "T1498": "Impact",
    "T1499": "Impact",
}


# ---------------------------------------------------
# GET TACTIC
# ---------------------------------------------------

def get_tactic(mitre_id: str):

    if not mitre_id:
        return "Unknown"

    return MITRE_TACTICS.get(
        mitre_id,
        "Unknown"
    )