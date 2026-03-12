import pandas as pd
from src.detections.mitre_mapping import apply_mitre_mapping


def detect_run_key_persistence(df):
    alerts = []

    if df.empty:
        return pd.DataFrame(alerts)

    required_columns = ["timestamp", "user", "host"]
    for col in required_columns:
        if col not in df.columns:
            return pd.DataFrame(alerts)

    registry_path_col = None
    registry_value_col = None

    if "registry_path" in df.columns:
        registry_path_col = "registry_path"

    if "registry_value" in df.columns:
        registry_value_col = "registry_value"

    if registry_path_col is None:
        return pd.DataFrame(alerts)

    suspicious = df[
        df[registry_path_col]
        .fillna("")
        .astype(str)
        .str.contains(r"currentversion\\run|currentversion\\runonce", case=False, regex=True)
    ]

    for _, row in suspicious.iterrows():
        alert = {
            "timestamp": row["timestamp"],
            "alert_type": "RunKeyPersistence",
            "severity": "Critical",
            "user": row["user"],
            "host": row["host"],
            "registry_path": row.get("registry_path", ""),
            "registry_value": row.get("registry_value", ""),
        }

        alert = apply_mitre_mapping(alert)
        alerts.append(alert)

    return pd.DataFrame(alerts)