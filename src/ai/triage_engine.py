import pandas as pd


def generate_triage_summary(incident_row):

    user = incident_row.get("user", "unknown user")
    host = incident_row.get("host", "unknown host")
    alert_types = incident_row.get("alert_types", "")
    severity = incident_row.get("severity", "Low")

    summary = f"Suspicious activity detected involving user {user} on host {host}. Alerts observed: {alert_types}."

    if "Encoded PowerShell" in alert_types:
        risk = (
            "Encoded PowerShell execution is commonly used to obscure malicious scripts "
            "and may indicate attacker command execution."
        )
    elif "Password Spray" in alert_types:
        risk = (
            "Repeated failed login attempts may indicate password spraying or brute-force activity."
        )
    else:
        risk = "Multiple security alerts were correlated and should be investigated."

    recommended_actions = [
        f"Review authentication activity for {user}",
        f"Inspect host activity on {host}",
        "Validate legitimacy of triggered detections",
        "Investigate related network activity"
    ]

    return {
        "summary": summary,
        "risk_assessment": risk,
        "recommended_actions": recommended_actions,
        "severity": severity
    }


def generate_triage_table(incidents_df: pd.DataFrame):

    triage_records = []

    for _, row in incidents_df.iterrows():

        triage = generate_triage_summary(row)

        triage_records.append({
            "incident_id": row["incident_id"],
            "severity": triage["severity"],
            "summary": triage["summary"],
            "risk": triage["risk_assessment"],
            "recommended_actions": "; ".join(triage["recommended_actions"])
        })

    return pd.DataFrame(triage_records)