# MITRE ATT&CK technique mappings for AISOP detections

MITRE_MAPPING = {

    "Encoded PowerShell Execution": {
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell to execute malicious commands.",
        "severity": "High"
    },

    "Password Spray": {
        "technique_id": "T1110.003",
        "technique": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Multiple authentication attempts using a common password across accounts.",
        "severity": "High"
    },

   "RunKeyPersistence": {
        "technique_id": "T1547.001",
        "technique": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may configure registry run keys for persistence.",
        "severity": "Critical"
   }

}

def apply_mitre_mapping(alert: dict) -> dict:
    rule_name = alert.get("alert_type")
    mapping = MITRE_MAPPING.get(rule_name)

    if not mapping:
        return alert

    alert["mitre_technique_id"] = mapping["technique_id"]
    alert["mitre_technique"] = mapping["technique"]
    alert["mitre_tactic"] = mapping["tactic"]
    alert["mitre_description"] = mapping["description"]
    alert["mitre_severity"] = mapping["severity"]

    return alert