"""
Centralized constants for detection engines.
"""

MITRE_ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

TACTIC_TECHNIQUE_COUNTS = {
    "Reconnaissance": 10,
    "Resource Development": 8,
    "Initial Access": 9,
    "Execution": 14,
    "Persistence": 19,
    "Privilege Escalation": 13,
    "Defense Evasion": 42,
    "Credential Access": 17,
    "Discovery": 32,
    "Lateral Movement": 9,
    "Collection": 17,
    "Command and Control": 17,
    "Exfiltration": 9,
    "Impact": 13
}

MITRE_SUBTECHNIQUES = {
    "T1110": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
    "T1059": ["T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008"],
    "T1548": ["T1548.001", "T1548.002", "T1548.003", "T1548.004", "T1548.005", "T1548.006"],
    "T1053": ["T1053.002", "T1053.003", "T1053.005", "T1053.006", "T1053.007"],
    "T1552": ["T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005", "T1552.006", "T1552.007"],
    "T1021": ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006"],
    "T1071": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"],
    "T1195": ["T1195.001", "T1195.002", "T1195.003"],
}
