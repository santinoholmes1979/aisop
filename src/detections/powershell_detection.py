import pandas as pd

from src.detections.mitre_mapping import apply_mitre_mapping


def detect_encoded_powershell(events_df: pd.DataFrame):

    process_events = events_df[events_df["event_type"] == "process"]

    suspicious = process_events[
        process_events["command_line"].fillna("").str.contains("-enc", case=False)
    ]

    alerts = []

    for _, row in suspicious.iterrows():

        alert = {
            "timestamp": row["timestamp"],
            "alert_type": "Encoded PowerShell Execution",
            "severity": "High",
            "user": row["user"],
            "host": row["host"],
            "process_name": row["process_name"],
            "command_line": row["command_line"],
        }

        alert = apply_mitre_mapping(alert)

        alerts.append(alert)

    return pd.DataFrame(alerts)