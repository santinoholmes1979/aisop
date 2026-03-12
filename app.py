import streamlit as st
import pandas as pd

from reporting.investigation_report import generate_investigation_report

if "case_notes" not in st.session_state:
    st.session_state.case_notes = {}

if "incident_statuses" not in st.session_state:
    st.session_state.incident_statuses = {}

if "incident_assignees" not in st.session_state:
    st.session_state.incident_assignees = {}


# MITRE ATT&CK Stage Mapping
ATTACK_STAGE_MAP = {
    "Password Spray": "Credential Access",
    "PasswordSpray": "Credential Access",
    "Encoded PowerShell Execution": "Execution",
    "EncodedPowerShell": "Execution",
    "RunKeyPersistence": "Persistence"
}


from src.ingestion.loaders import (
    load_auth_events,
    load_process_events,
    load_network_events,
    load_registry_events,
)

from src.ingestion.normalizer import combine_normalized_events
from src.detections.powershell_detection import detect_encoded_powershell
from src.detections.password_spray_detection import detect_password_spray
from src.cases.incident_builder import build_incidents
from src.ai.triage_engine import generate_triage_table
from src.dashboards.timeline_builder import build_event_timeline
from src.detections.persistence_detection import detect_run_key_persistence


st.set_page_config(
    page_title="AISOP",
    page_icon="🛡️",
    layout="wide"
)

def build_attack_chain(related_alerts_df):
    if related_alerts_df.empty:
        return []

    df = related_alerts_df.copy()

    stage_source_col = None

    if "alert_type" in df.columns:
        stage_source_col = "alert_type"
    elif "detection" in df.columns:
        stage_source_col = "detection"
    elif "mitre_tactic" in df.columns:
        stage_source_col = "mitre_tactic"
    else:
        return []

    if stage_source_col == "mitre_tactic":
        observed_stages = (
            df["mitre_tactic"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )
    else:
        df["stage"] = df[stage_source_col].map(ATTACK_STAGE_MAP)
        observed_stages = (
            df["stage"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

    desired_order = [
        "Credential Access",
        "Execution",
        "Persistence"
    ]

    ordered_chain = [stage for stage in desired_order if stage in observed_stages]

    return ordered_chain


    observed_tactics = (
        related_alerts_df["mitre_tactic"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    ordered_chain = [t for t in tactic_order if t in observed_tactics]

    return ordered_chain


def build_aisop_data():
    auth_df = load_auth_events()
    process_df = load_process_events()
    network_df = load_network_events()
    registry_df = load_registry_events()

    normalized_df = combine_normalized_events(
        auth_df,
        process_df,
        network_df,
        registry_df,
    )

    alerts_df = detect_encoded_powershell(normalized_df)
    spray_alerts_df = detect_password_spray(normalized_df)
    persistence_alerts_df = detect_run_key_persistence(normalized_df)

    all_alerts_df = pd.concat(
        [alerts_df, spray_alerts_df, persistence_alerts_df],
        ignore_index=True
)

    incidents_df = build_incidents(all_alerts_df)
    triage_df = generate_triage_table(incidents_df)

    return {
        "normalized_df": normalized_df,
        "alerts_df": all_alerts_df,
        "incidents_df": incidents_df,
        "triage_df": triage_df,
    }

def show_overview():

    data = build_aisop_data()

    normalized_df = data["normalized_df"]
    all_alerts_df = data["alerts_df"]
    incidents_df = data["incidents_df"]
    triage_df = data["triage_df"]

    st.title("AISOP")
    st.subheader("AI Security Operations Platform")

    st.markdown(
        """
        AISOP is a defense-style SOC platform prototype designed to simulate how modern
        security teams ingest telemetry, detect suspicious behavior, prioritize alerts,
        correlate incidents, and accelerate triage with AI-assisted analysis.
        """
    )

    st.info("Phase 1: Project skeleton and application shell")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Events Ingested", str(len(normalized_df)))
    col2.metric("Alerts Generated", str(len(all_alerts_df)))
    col3.metric("Open Incidents", str(len(incidents_df)))
    col4.metric("AI Summaries", "0")
    st.markdown("---")
    st.subheader("Detection Debug")

    if not all_alerts_df.empty and "alert_type" in all_alerts_df.columns:

        st.write(
            "Encoded PowerShell alerts:",
            len(all_alerts_df[all_alerts_df["alert_type"] == "Encoded PowerShell Execution"])
        )

        st.write(
            "Password Spray alerts:",
            len(all_alerts_df[all_alerts_df["alert_type"] == "Password Spray"])
        )

        st.write(
            "RunKeyPersistence alerts:",
            len(all_alerts_df[all_alerts_df["alert_type"] == "RunKeyPersistence"])
        )

    else:
        st.write("No alerts generated yet.")

    st.markdown("---")
    st.subheader("Password Spray Debug")

    if "source_ip" in normalized_df.columns and "user" in normalized_df.columns:

        spray_debug_df = (
            normalized_df[["source_ip", "user"]]
            .dropna()
            .groupby("source_ip")["user"]
            .nunique()
            .reset_index()
            .sort_values("user", ascending=False)
        )

        spray_debug_df.columns = ["source_ip", "unique_users"]

        st.dataframe(spray_debug_df, use_container_width=True)

        if not spray_debug_df.empty:
            st.write(
                "Highest unique-user count from one source IP:",
                int(spray_debug_df["unique_users"].max())
            )
        else:
            st.write("No source_ip/user combinations found.")

    else:
        st.write("normalized_df is missing source_ip or user columns.")

    st.markdown("---")
    st.subheader("Detection Alerts")
    st.write(all_alerts_df["alert_type"].value_counts())

    if not all_alerts_df.empty:
        st.dataframe(all_alerts_df, use_container_width=True)
    else:
        st.write("No alerts detected.")

    st.markdown("---")
    st.subheader("Host / Alert Correlation Debug")

    if not all_alerts_df.empty and "host" in all_alerts_df.columns and "alert_type" in all_alerts_df.columns:
        host_alert_debug = (
            all_alerts_df.groupby(["host", "alert_type"])
            .size()
            .reset_index(name="count")
            .sort_values(["host", "alert_type"])
        )
        st.dataframe(host_alert_debug, use_container_width=True)
    else:
        st.write("Missing host or alert_type columns.")

    st.markdown("---")
    st.subheader("AI Triage Assistant")

    if not triage_df.empty:
        st.dataframe(triage_df, use_container_width=True)
    else:
        st.write("No incidents available for triage.")

    st.markdown("---")
    st.subheader("Incident Preview")

    if not incidents_df.empty:
        st.dataframe(incidents_df, use_container_width=True)
    else:
        st.write("No incidents correlated.")

    st.markdown("---")
    st.subheader("Normalized Telemetry Preview")

    st.dataframe(normalized_df, use_container_width=True)

    left_col, right_col = st.columns([2, 1])

    with left_col:
        st.markdown("### Platform Mission")
        st.write(
            """
            AISOP is being built as a flagship portfolio platform that brings together:

            - telemetry ingestion
            - detection engineering
            - behavioral analytics
            - risk scoring
            - incident correlation
            - AI-assisted triage
            - analyst workflow support
            """
        )

        st.markdown("### Current Build Status")
        st.write(
            """
            The foundation is now in place:
            - project structure created
            - Python virtual environment configured
            - Streamlit app initialized
            - module layout defined for future expansion
            """
        )

    with right_col:
        st.markdown("### Planned Modules")
        st.write(
            """
            - Overview
            - Alerts
            - Investigations
            - AI Triage
            - Hunting
            - Metrics
            """
        )

        st.markdown("### Intended Use Case")
        st.write(
            """
            A prototype analyst-facing platform demonstrating how AI can support SOC
            operations without replacing detection logic or analyst judgment.
            """
        )

    st.info("Phase 1: Project skeleton and application shell")


def show_alerts():
    data = build_aisop_data()
    alerts_df = data["alerts_df"]

    st.title("Alerts")
    st.subheader("Alert Queue")

    if alerts_df.empty:
        st.write("No alerts detected.")
        return

    st.markdown("### Alert Filters")

    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        severity_options = ["All"]
        if "severity" in alerts_df.columns:
            severity_options += sorted(alerts_df["severity"].dropna().unique().tolist())
        selected_severity = st.selectbox("Severity", severity_options)

    with filter_col2:
        alert_type_options = ["All"]
        if "alert_type" in alerts_df.columns:
            alert_type_options += sorted(alerts_df["alert_type"].dropna().unique().tolist())
        selected_alert_type = st.selectbox("Alert Type", alert_type_options)

    with filter_col3:
        host_options = ["All"]
        if "host" in alerts_df.columns:
            host_options += sorted(alerts_df["host"].dropna().astype(str).unique().tolist())
        selected_host = st.selectbox("Host", host_options)

    filtered_alerts_df = alerts_df.copy()

    if selected_severity != "All" and "severity" in filtered_alerts_df.columns:
        filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["severity"] == selected_severity
        ]

    if selected_alert_type != "All" and "alert_type" in filtered_alerts_df.columns:
        filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["alert_type"] == selected_alert_type
        ]

    if selected_host != "All" and "host" in filtered_alerts_df.columns:
        filtered_alerts_df = filtered_alerts_df[
            filtered_alerts_df["host"].fillna("").astype(str) == selected_host
        ]

    st.markdown("---")
    st.markdown("### Filtered Alerts")

    st.dataframe(filtered_alerts_df, use_container_width=True)

    st.markdown("---")
    st.subheader("MITRE ATT&CK Techniques Observed")

    mitre_columns = [
        "alert_type",
        "mitre_tactic",
        "mitre_technique",
        "mitre_technique_id"
    ]

    if not filtered_alerts_df.empty and all(col in filtered_alerts_df.columns for col in mitre_columns):
        mitre_df = filtered_alerts_df[mitre_columns].drop_duplicates()
        st.dataframe(mitre_df, use_container_width=True)
    else:
        st.write("No MITRE mapping available for the current filter selection.")
    
def render_attack_chain(chain):
    if not chain:
        return "No attack chain available."

    return " → ".join([f"[{tactic}]" for tactic in chain])

def render_attack_chain_html(chain):
    if not chain:
        return "<p>No attack chain available.</p>"
    
def render_attack_graph_html(related_alerts_df, attack_chain):
    if not attack_chain:
        return "<p>No attack graph available.</p>"

    node_style = """
        display: inline-block;
        padding: 12px 18px;
        margin: 6px 0;
        border-radius: 14px;
        background-color: #111827;
        color: white;
        font-weight: 600;
        font-size: 14px;
        min-width: 260px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    """

    arrow_style = """
        font-size: 26px;
        font-weight: 700;
        color: #374151;
        line-height: 1.1;
        margin: 2px 0 6px 0;
    """

    stage_to_alert = {}

    if not related_alerts_df.empty:
        df = related_alerts_df.copy()

        stage_source_col = None
        if "alert_type" in df.columns:
            stage_source_col = "alert_type"
        elif "detection" in df.columns:
            stage_source_col = "detection"

        if stage_source_col:
            df["stage"] = df[stage_source_col].map(ATTACK_STAGE_MAP)

            for stage in attack_chain:
                matching = df[df["stage"] == stage]
                if not matching.empty:
                    stage_to_alert[stage] = matching.iloc[0][stage_source_col]
                else:
                    stage_to_alert[stage] = stage
        else:
            for stage in attack_chain:
                stage_to_alert[stage] = stage
    else:
        for stage in attack_chain:
            stage_to_alert[stage] = stage

    parts = ['<div style="display:flex; flex-direction:column; align-items:center; margin-top:8px; margin-bottom:8px;">']

    for i, stage in enumerate(attack_chain):
        label = stage_to_alert.get(stage, stage)
        parts.append(f'<div style="{node_style}">{label}<br><span style="font-size:12px; font-weight:400; opacity:0.85;">{stage}</span></div>')

        if i < len(attack_chain) - 1:
            parts.append(f'<div style="{arrow_style}">↓</div>')

    parts.append("</div>")

    return "".join(parts)


    node_style = """
        display: inline-block;
        padding: 10px 16px;
        margin: 4px;
        border-radius: 999px;
        background-color: #1f2937;
        color: white;
        font-weight: 600;
        font-size: 14px;
    """

    arrow_style = """
        display: inline-block;
        margin: 0 8px;
        font-size: 20px;
        font-weight: 700;
        color: #374151;
    """

    parts = []

    for i, tactic in enumerate(chain):
        parts.append(f'<span style="{node_style}">{tactic}</span>')
        if i < len(chain) - 1:
            parts.append(f'<span style="{arrow_style}">→</span>')

    return f'<div style="margin-top: 8px; margin-bottom: 8px;">{"".join(parts)}</div>'

def calculate_incident_risk_score(related_alerts_df, attack_chain):
    if related_alerts_df.empty:
        return 0, "Low"

    score = 0

    alert_count = len(related_alerts_df)
    stage_count = len(attack_chain)

    # Base points from alert volume
    score += min(alert_count * 5, 25)

    # ATT&CK stage progression
    score += stage_count * 15

    # Higher-risk stages
    if "Execution" in attack_chain:
        score += 15

    if "Persistence" in attack_chain:
        score += 20

    if "Credential Access" in attack_chain:
        score += 10

    # Multi-stage bonus
    if stage_count >= 3:
        score += 10
    elif stage_count == 2:
        score += 5

    score = min(score, 100)

    if score >= 80:
        severity_band = "Critical"
    elif score >= 60:
        severity_band = "High"
    elif score >= 40:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    return score, severity_band

def build_incident_risk_table(alerts_df, incidents_df):
    if incidents_df.empty:
        return pd.DataFrame(columns=["incident_id", "title", "host", "user", "risk_score", "risk_level", "alert_count"])

    rows = []

    for _, incident in incidents_df.iterrows():
        incident_host = incident.get("host", None)
        incident_user = incident.get("user", None)

        related_alerts = alerts_df.copy()

        if incident_host and "host" in related_alerts.columns:
            related_alerts = related_alerts[
                related_alerts["host"].fillna("").astype(str) == str(incident_host)
            ]
        elif incident_user and "user" in related_alerts.columns:
            related_alerts = related_alerts[
                related_alerts["user"].fillna("").astype(str) == str(incident_user)
            ]

        attack_chain = build_attack_chain(related_alerts)
        risk_score, risk_level = calculate_incident_risk_score(related_alerts, attack_chain)

        rows.append({
            "incident_id": incident.get("incident_id", "Unknown"),
            "title": incident.get("title", "Unknown"),
            "host": incident_host,
            "user": incident_user,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "alert_count": incident.get("alert_count", 0),
        })

    risk_df = pd.DataFrame(rows)

    if not risk_df.empty:
        risk_df = risk_df.sort_values(["risk_score", "alert_count"], ascending=[False, False])

    return risk_df

def run_hunt_query(normalized_df, hunt_type, hunt_value):
    if normalized_df.empty or not hunt_value:
        return pd.DataFrame()

    df = normalized_df.copy()
    hunt_value = str(hunt_value).strip().lower()

    if hunt_type == "Host" and "host" in df.columns:
        return df[df["host"].fillna("").astype(str).str.lower().str.contains(hunt_value, na=False)]

    elif hunt_type == "User" and "user" in df.columns:
        return df[df["user"].fillna("").astype(str).str.lower().str.contains(hunt_value, na=False)]

    elif hunt_type == "Process" and "process_name" in df.columns:
        return df[df["process_name"].fillna("").astype(str).str.lower().str.contains(hunt_value, na=False)]

    elif hunt_type == "Command Line" and "command_line" in df.columns:
        return df[df["command_line"].fillna("").astype(str).str.lower().str.contains(hunt_value, na=False)]

    elif hunt_type == "Event Type" and "event_type" in df.columns:
        return df[df["event_type"].fillna("").astype(str).str.lower().str.contains(hunt_value, na=False)]

    return pd.DataFrame()


def show_investigations():
    data = build_aisop_data()

    normalized_df = data["normalized_df"]
    alerts_df = data["alerts_df"]
    incidents_df = data["incidents_df"]
    triage_df = data["triage_df"]

    st.title("Investigations")
    st.subheader("Incident Explorer")

    if incidents_df.empty:
        st.write("No incidents available.")
        return

    incident_options = incidents_df["incident_id"].tolist()
    selected_incident_id = st.selectbox("Select Incident", incident_options)

    selected_incident = incidents_df[
        incidents_df["incident_id"] == selected_incident_id
    ].iloc[0]

    selected_triage = triage_df[
        triage_df["incident_id"] == selected_incident_id
    ]

    selected_user = selected_incident.get("user", None)
    selected_host = selected_incident.get("host", None)

    related_alerts = alerts_df.copy()

    if selected_host and "host" in related_alerts.columns:
        related_alerts = related_alerts[
            related_alerts["host"].fillna("").astype(str) == str(selected_host)
        ]

    related_events = normalized_df.copy()

    if selected_host and "host" in related_events.columns:
        related_events = related_events[
            related_events["host"].fillna("").astype(str) == str(selected_host)
        ]
    elif selected_user and "user" in related_events.columns:
        related_events = related_events[
            related_events["user"].fillna("").astype(str) == str(selected_user)
        ]

    timeline_df = build_event_timeline(related_events)
    attack_chain = build_attack_chain(related_alerts)
    risk_score, risk_level = calculate_incident_risk_score(related_alerts, attack_chain)
    multi_stage = len(attack_chain) >= 2

    st.markdown("---")
    st.subheader("Incident Status Management")

    incident_id = selected_incident["incident_id"]

    if incident_id not in st.session_state.incident_statuses:
        st.session_state.incident_statuses[incident_id] = selected_incident.get("status", "Open")

    status_options = ["Open", "Investigating", "Contained", "Closed"]

    selected_status = st.selectbox(
        "Update Incident Status",
        status_options,
        index=status_options.index(st.session_state.incident_statuses[incident_id])
        if st.session_state.incident_statuses[incident_id] in status_options else 0
    )

    if st.button("Save Status"):
        st.session_state.incident_statuses[incident_id] = selected_status
        st.success(f"Incident status updated to {selected_status}.")
        st.rerun()

    st.write(f"**Current Workflow Status:** {st.session_state.incident_statuses[incident_id]}")

    st.markdown("---")
    st.subheader("Incident Assignment")

    incident_id = selected_incident["incident_id"]

    if incident_id not in st.session_state.incident_assignees:
        st.session_state.incident_assignees[incident_id] = "Unassigned"

    analyst_options = [
        "Unassigned",
        "Ryan Holmes",
        "SOC Analyst 1",
        "SOC Analyst 2",
        "IR Lead"
    ]

    selected_assignee = st.selectbox(
        "Assign Analyst",
        analyst_options,
        index=analyst_options.index(st.session_state.incident_assignees[incident_id])
        if st.session_state.incident_assignees[incident_id] in analyst_options else 0
    )

    if st.button("Save Assignment"):
        st.session_state.incident_assignees[incident_id] = selected_assignee
        st.success(f"Incident assigned to {selected_assignee}.")
        st.rerun()

    st.write(f"**Current Assignee:** {st.session_state.incident_assignees[incident_id]}")




    st.markdown("---")
    st.markdown("### Incident Overview")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Incident ID", selected_incident["incident_id"])
    col2.metric("Severity", selected_incident["severity"])
    col3.metric("Risk Score", f"{risk_score}/100")
    col4.metric("Risk Level", risk_level)
    col5.metric("Alerts", str(selected_incident["alert_count"]))


    st.write(f"**Title:** {selected_incident['title']}")
    st.write(f"**User:** {selected_incident['user']}")
    st.write(f"**Host:** {selected_incident['host']}")
    st.write(f"**Alert Types:** {selected_incident['alert_types']}")
    st.write(f"**Status:** {selected_incident['status']}")

    current_assignee = st.session_state.incident_assignees.get(
    selected_incident["incident_id"],
        "Unassigned"
    )
    st.write(f"**Assigned Analyst:** {current_assignee}")



    st.markdown("---")
    st.markdown("### AI Triage Summary")

    if not selected_triage.empty:
        triage_row = selected_triage.iloc[0]
        st.write(f"**Summary:** {triage_row['summary']}")
        st.write(f"**Risk:** {triage_row['risk']}")
        st.write(f"**Recommended Actions:** {triage_row['recommended_actions']}")
    else:
        st.write("No triage summary available.")

    st.markdown("---")
    st.markdown("### Related Alerts")

    if not related_alerts.empty:
        st.dataframe(related_alerts, use_container_width=True)
    else:
        st.write("No related alerts found.")

    st.markdown("---")
    st.markdown("### MITRE ATT&CK Context")

    mitre_columns = [
        "alert_type",
        "mitre_tactic",
        "mitre_technique",
        "mitre_technique_id"
    ]

    if not related_alerts.empty and all(col in related_alerts.columns for col in mitre_columns):
        incident_mitre_df = related_alerts[mitre_columns].drop_duplicates()
        st.dataframe(incident_mitre_df, use_container_width=True)
    else:
        st.write("No MITRE context available.")

        st.markdown("---")
        st.markdown("---")
    
        st.markdown("---")
    st.markdown("### Attack Chain Visualization")

    if attack_chain:
        attack_chain_text = " → ".join(attack_chain)
        attack_chain_html = render_attack_chain_html(attack_chain)
        attack_graph_html = render_attack_graph_html(related_alerts, attack_chain)
        multi_stage = len(attack_chain) >= 2

        st.write(f"**Observed ATT&CK Flow:** {attack_chain_text}")
       
        st.markdown("**Attack Graph:**")
        st.markdown(attack_graph_html, unsafe_allow_html=True)

        if len(attack_chain) >= 3:
            st.success("Confirmed multi-stage attack chain: Credential Access → Execution → Persistence.")
            st.write(
                "This incident shows suspicious authentication activity followed by execution and persistence on the same host."
            )
        elif multi_stage:
            st.warning(f"Partial multi-stage activity detected: {attack_chain_text}")
            st.write(
                "This incident contains multiple correlated ATT&CK stages, but the full attack sequence is not yet confirmed."
            )
        else:
            st.info("Single-stage activity observed so far.")
            st.write(
                "Only one ATT&CK stage is currently represented in the related alerts for this incident."
            )
    else:
        st.write("No attack chain available for this incident.")


        st.markdown("---")
    st.markdown("### Incident Narrative")

    if attack_chain:

        incident_user = selected_incident.get("user", "unknown user")
        incident_host = selected_incident.get("host", "unknown host")
        incident_title = selected_incident.get("title", "Suspicious activity detected")
        incident_severity = selected_incident.get("severity", "Unknown")

        alert_types = []

        if "alert_type" in related_alerts.columns:
            alert_types = related_alerts["alert_type"].dropna().unique().tolist()

        alert_summary = ", ".join(alert_types)

        if len(attack_chain) >= 3:
            narrative = (
                f"{incident_title} on {incident_host} involves a confirmed multi-stage attack affecting "
                f"user {incident_user}. Observed detections include {alert_summary}. "
                f"The attack sequence progressed through the following ATT&CK stages: "
                f"{' → '.join(attack_chain)}. Incident severity is currently assessed as {incident_severity}."
            )

        elif len(attack_chain) == 2:
            narrative = (
                f"{incident_title} on {incident_host} involves correlated suspicious activity affecting "
                f"user {incident_user}. Detected behaviors include {alert_summary}. "
                f"Observed ATT&CK progression: {' → '.join(attack_chain)}. "
                f"Incident severity is currently assessed as {incident_severity}."
            )

        else:
            narrative = (
                f"{incident_title} on {incident_host} currently reflects single-stage suspicious activity "
                f"affecting user {incident_user}. The observed detection is {alert_summary}. "
                f"ATT&CK stage observed: {attack_chain[0]}. "
                f"Incident severity is currently assessed as {incident_severity}."
            )

        st.info(narrative)

    else:
        st.write("No incident narrative available.")

    st.markdown("---")
    st.subheader("Analyst Case Notes")

    incident_id = selected_incident["incident_id"]

    if "case_notes" not in st.session_state:
        st.session_state.case_notes = {}

    if incident_id not in st.session_state.case_notes:
        st.session_state.case_notes[incident_id] = []

    note_input = st.text_area(
        "Add Investigation Note",
        placeholder="Document observations, hypotheses, or actions taken..."
    )

    if st.button("Add Note"):
        if note_input.strip():
            st.session_state.case_notes[incident_id].append(note_input.strip())
            st.success("Note added.")
            st.rerun()

    st.markdown("### Existing Notes")

    notes = st.session_state.case_notes.get(incident_id, [])

    if not notes:
        st.write("No notes recorded for this incident.")
    else:
        for i, note in enumerate(notes, start=1):
            st.info(f"Note {i}: {note}")


    st.markdown("### Existing Notes")

    notes = st.session_state.case_notes.get(incident_id, [])

    if not notes:
        st.write("No notes recorded for this incident.")
    else:
        for i, note in enumerate(notes, start=1):
            st.info(f"Note {i}: {note}")
    
    st.markdown("---")
    st.markdown("### Investigation Report")

    case_notes = st.session_state.case_notes.get(incident_id, [])

    report_buffer = generate_investigation_report(
        selected_incident,
        related_alerts,
        selected_triage,
        case_notes=case_notes
    )

    st.download_button(
        label="Download Investigation Report (PDF)",
        data=report_buffer,
        file_name=f"aisop_incident_{selected_incident_id}.pdf",
        mime="application/pdf"
    )


    st.markdown("---")
    st.markdown("### Attack Timeline")


    if not timeline_df.empty:
        st.dataframe(timeline_df, use_container_width=True)
    else:
        st.write("No related events found.")

    st.markdown("---")
    st.markdown("### Raw Related Events")

    if not related_events.empty:
        st.dataframe(related_events, use_container_width=True)
    else:
        st.write("No raw related events found.")


def show_ai_triage():
    st.title("AI Triage")
    st.write("This page will generate AI-assisted summaries, explanations, and next steps.")


def show_hunting():
    data = build_aisop_data()
    normalized_df = data["normalized_df"]
    alerts_df = data["alerts_df"]

    st.title("Threat Hunting")
    st.subheader("Telemetry Search and Analyst Pivoting")

    if normalized_df.empty:
        st.write("No telemetry available for hunting.")
        return

    st.markdown("### Hunt Query")

    hunt_col1, hunt_col2 = st.columns([1, 2])

    with hunt_col1:
        hunt_type = st.selectbox(
            "Search Type",
            ["Host", "User", "Process", "Command Line", "Event Type"]
        )

    with hunt_col2:
        hunt_value = st.text_input("Search Value", placeholder="Enter a host, user, process, command line, or event type")

    hunt_results_df = pd.DataFrame()

    if hunt_value.strip():
        hunt_results_df = run_hunt_query(normalized_df, hunt_type, hunt_value)

    st.markdown("---")
    st.subheader("Hunt Results")

    if not hunt_value.strip():
        st.write("Enter a search value to begin hunting.")
    elif hunt_results_df.empty:
        st.write("No matching telemetry found.")
    else:
        st.write(f"Matches found: {len(hunt_results_df)}")
        st.dataframe(hunt_results_df, use_container_width=True)

    st.markdown("---")
    st.subheader("Quick Hunt Suggestions")

    suggestion_col1, suggestion_col2, suggestion_col3 = st.columns(3)

    with suggestion_col1:
        st.code("WS-101")
        st.caption("Pivot on a suspicious host")

    with suggestion_col2:
        st.code("adoe")
        st.caption("Pivot on a suspicious user")

    with suggestion_col3:
        st.code("powershell")
        st.caption("Search for execution activity")

    st.markdown("---")
    st.subheader("Related Alerts")

    if hunt_value.strip() and not alerts_df.empty:
        related_alerts = alerts_df.copy()

        if hunt_type == "Host" and "host" in related_alerts.columns:
            related_alerts = related_alerts[
                related_alerts["host"].fillna("").astype(str).str.lower().str.contains(hunt_value.lower(), na=False)
            ]
        elif hunt_type == "User" and "user" in related_alerts.columns:
            related_alerts = related_alerts[
                related_alerts["user"].fillna("").astype(str).str.lower().str.contains(hunt_value.lower(), na=False)
            ]
        else:
            related_alerts = pd.DataFrame()

        if related_alerts.empty:
            st.write("No related alerts found for this hunt.")
        else:
            st.dataframe(related_alerts, use_container_width=True)
    else:
        st.write("Run a hunt query to view related alerts.")

def show_metrics():
    data = build_aisop_data()
    alerts_df = data["alerts_df"]
    incidents_df = data["incidents_df"]
    incident_risk_df = build_incident_risk_table(alerts_df, incidents_df)

    st.title("Metrics")
    st.subheader("SOC Metrics Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", str(len(alerts_df)))
    col2.metric("Open Incidents", str(len(incidents_df)))
    col3.metric(
        "MITRE Techniques",
        str(alerts_df["mitre_technique_id"].nunique()) if "mitre_technique_id" in alerts_df.columns else "0"
    )

    st.markdown("---")
    st.subheader("Top Risk Incidents")

    if not incident_risk_df.empty:
            top_risk_display = incident_risk_df[
                ["incident_id", "title", "host", "user", "risk_score", "risk_level", "alert_count"]
            ].head(10)
            st.dataframe(top_risk_display, use_container_width=True)
    else:
            st.write("No incidents available for risk ranking.")

    st.subheader("Top Risk Incidents")

    if not incident_risk_df.empty:

        risk_display = incident_risk_df.copy()

            # Add analyst workflow status
        risk_display["status"] = risk_display["incident_id"].apply(
            lambda x: st.session_state.incident_statuses.get(x, "Open")
        )

        risk_display["assignee"] = risk_display["incident_id"].apply(
            lambda x: st.session_state.incident_assignees.get(x, "Unassigned")
        )

        top_risk_display = risk_display[
            ["incident_id", "title", "host", "user", "risk_score", "risk_level", "status", "assignee", "alert_count"]
        ].head(10)


        st.dataframe(top_risk_display, use_container_width=True)

    else:
        st.write("No incidents available for risk ranking.")


    st.markdown("---")
    st.subheader("Most Targeted Hosts")

    if not alerts_df.empty and "host" in alerts_df.columns:
        host_counts = (
            alerts_df["host"]
            .fillna("Unknown")
            .value_counts()
            .reset_index()
        )
        host_counts.columns = ["Host", "Alert Count"]

        st.dataframe(host_counts, use_container_width=True)
        st.bar_chart(host_counts.set_index("Host"))
    else:
        st.write("No host data available.")

    st.markdown("---")
    st.subheader("Top MITRE Techniques")

    mitre_technique_cols = ["mitre_technique_id", "mitre_technique"]

    if not alerts_df.empty and all(col in alerts_df.columns for col in mitre_technique_cols):
        technique_counts = (
            alerts_df[mitre_technique_cols]
            .dropna()
            .value_counts()
            .reset_index(name="Count")
            .sort_values("Count", ascending=False)
        )

        st.dataframe(technique_counts, use_container_width=True)
        st.bar_chart(technique_counts.head(10).set_index("mitre_technique_id")[["Count"]])
    else:
        st.write("No MITRE technique data available.")

    st.markdown("---")
    st.subheader("Most Suspicious Processes")

    if not alerts_df.empty and "process_name" in alerts_df.columns:
        process_counts = (
            alerts_df["process_name"]
            .dropna()
            .astype(str)
            .value_counts()
            .reset_index()
        )
        process_counts.columns = ["Process", "Count"]

        st.dataframe(process_counts, use_container_width=True)
        st.bar_chart(process_counts.head(10).set_index("Process"))
    else:
        st.write("No suspicious process data available.")

    st.markdown("---")
    st.subheader("Most Active Users in Alerts")

    if not alerts_df.empty and "user" in alerts_df.columns:
        user_counts = (
            alerts_df["user"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .reset_index()
        )
        user_counts.columns = ["User", "Alert Count"]

        st.dataframe(user_counts, use_container_width=True)
        st.bar_chart(user_counts.head(10).set_index("User"))
    else:
        st.write("No user activity data available.")

    st.markdown("---")
    st.subheader("MITRE ATT&CK Tactic Coverage")

    if not alerts_df.empty and "mitre_tactic" in alerts_df.columns:
        tactic_counts = alerts_df["mitre_tactic"].value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Count"]

        st.dataframe(tactic_counts, use_container_width=True)
        st.bar_chart(tactic_counts.set_index("Tactic"))
    else:
        st.write("MITRE mapping not present in alerts.")

    st.markdown("---")
    st.subheader("Alert Severity Breakdown")

    if not alerts_df.empty and "severity" in alerts_df.columns:
        severity_counts = alerts_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]

        st.dataframe(severity_counts, use_container_width=True)
        st.bar_chart(severity_counts.set_index("Severity"))
    else:
        st.write("Severity data not available.")


st.sidebar.title("AISOP Navigation")
page = st.sidebar.radio(
    "Go to",
    [
        "Overview",
        "Alerts",
        "Investigations",
        "AI Triage",
        "Hunting",
        "Metrics"
    ]
)

if page == "Overview":
    show_overview()
elif page == "Alerts":
    show_alerts()
elif page == "Investigations":
    show_investigations()
elif page == "AI Triage":
    show_ai_triage()
elif page == "Hunting":
    show_hunting()
elif page == "Metrics":
    show_metrics()

