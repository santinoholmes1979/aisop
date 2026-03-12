import pandas as pd


def classify_event(row):
    event_type = str(row.get("event_type", ""))
    status = str(row.get("status", ""))
    action = str(row.get("action", ""))
    process_name = str(row.get("process_name", ""))
    command_line = str(row.get("command_line", ""))

    if event_type == "auth":
        if status.lower() == "failed":
            return "Authentication Failure", "Medium"
        if status.lower() == "success":
            return "Successful Login", "Low"
        return "Authentication Event", "Low"

    if event_type == "process":
        if "-enc" in command_line.lower():
            return "Encoded PowerShell Execution", "High"
        if process_name.lower() == "powershell.exe":
            return "PowerShell Execution", "Medium"
        return "Process Execution", "Low"

    if event_type == "network":
        if action.lower() == "allowed":
            return "Outbound Network Connection", "Low"
        if action.lower() == "blocked":
            return "Blocked Network Connection", "Medium"
        return "Network Activity", "Low"

    return "Unknown Event", "Low"


def build_event_timeline(events_df: pd.DataFrame) -> pd.DataFrame:
    if events_df.empty:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "timeline_event",
                "severity",
                "user",
                "host",
                "details",
            ]
        )

    working_df = events_df.copy()
    working_df = working_df.sort_values("timestamp").reset_index(drop=True)

    timeline_rows = []

    for _, row in working_df.iterrows():
        timeline_event, severity = classify_event(row)

        details_parts = []

        if pd.notna(row.get("process_name")) and str(row.get("process_name")) != "None":
            details_parts.append(f"process={row.get('process_name')}")

        if pd.notna(row.get("command_line")) and str(row.get("command_line")) not in ["None", "nan"]:
            details_parts.append(f"cmd={row.get('command_line')}")

        if pd.notna(row.get("source_ip")) and str(row.get("source_ip")) not in ["None", "nan"]:
            details_parts.append(f"src_ip={row.get('source_ip')}")

        if pd.notna(row.get("destination_ip")) and str(row.get("destination_ip")) not in ["None", "nan"]:
            details_parts.append(f"dst_ip={row.get('destination_ip')}")

        if pd.notna(row.get("action")) and str(row.get("action")) not in ["None", "nan"]:
            details_parts.append(f"action={row.get('action')}")

        if pd.notna(row.get("status")) and str(row.get("status")) not in ["None", "nan"]:
            details_parts.append(f"status={row.get('status')}")

        timeline_rows.append(
            {
                "timestamp": row.get("timestamp"),
                "timeline_event": timeline_event,
                "severity": severity,
                "user": row.get("user"),
                "host": row.get("host"),
                "details": " | ".join(details_parts),
            }
        )

    return pd.DataFrame(timeline_rows)