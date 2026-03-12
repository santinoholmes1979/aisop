import pandas as pd
from uuid import uuid4


def build_incidents(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return pd.DataFrame(
            columns=[
                "incident_id",
                "title",
                "user",
                "host",
                "severity",
                "alert_count",
                "alert_types",
                "status",
            ]
        )

    working_df = alerts_df.copy()

    if "user" not in working_df.columns:
        working_df["user"] = None

    if "host" not in working_df.columns:
        working_df["host"] = None

    working_df["correlation_key"] = working_df["user"].fillna("") + "|" + working_df["host"].fillna("")

    # If host is missing but user exists, still correlate by user
    working_df.loc[
        (working_df["host"].isna()) | (working_df["host"] == ""),
        "correlation_key"
    ] = working_df["user"].fillna("")

    grouped = working_df.groupby("correlation_key", dropna=False)

    incidents = []

    for _, group in grouped:
        first_row = group.iloc[0]

        user = first_row.get("user", None)
        host = first_row.get("host", None)

        if group["severity"].eq("High").any():
            severity = "High"
        elif group["severity"].eq("Medium").any():
            severity = "Medium"
        else:
            severity = "Low"

        alert_types = ", ".join(sorted(group["alert_type"].dropna().unique().tolist()))

        if user and host:
            title = f"Suspicious activity involving {user} on {host}"
        elif user:
            title = f"Suspicious activity involving {user}"
        elif host:
            title = f"Suspicious activity on {host}"
        else:
            title = "Correlated security incident"

        incidents.append(
            {
                "incident_id": str(uuid4())[:8],
                "title": title,
                "user": user,
                "host": host,
                "severity": severity,
                "alert_count": len(group),
                "alert_types": alert_types,
                "status": "Open",
            }
        )

    return pd.DataFrame(incidents)