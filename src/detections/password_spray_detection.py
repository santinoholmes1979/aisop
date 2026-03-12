import pandas as pd
from src.detections.mitre_mapping import apply_mitre_mapping


def detect_password_spray(df):

    alerts = []

    # simple password spray heuristic
    grouped = df.groupby("source_ip")

    for source_ip, group in grouped:

        if group["user"].nunique() >= 3:

            for _, row in group.iterrows():

                alert = {
                    "timestamp": row["timestamp"],
                    "alert_type": "Password Spray",
                    "severity": "High",
                    "user": row["user"],
                    "host": row["host"],
                    "source_ip": row["source_ip"],
                }

                alert = apply_mitre_mapping(alert)

                alerts.append(alert)

    return pd.DataFrame(alerts)


  

