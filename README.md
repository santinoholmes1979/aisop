# AISOP – AI Security Operations Platform

AISOP is a Python-based Security Operations Platform built with **Streamlit** that simulates how modern SOC teams transform raw telemetry into investigations through detection engineering, incident correlation, MITRE ATT&CK mapping, attack chain analysis, and analyst workflows.

The platform demonstrates how security telemetry evolves into actionable incident response through alert generation, incident enrichment, investigation tooling, timeline reconstruction, and exportable investigation reporting.

---

# Platform Overview

AISOP simulates a modern security operations investigation pipeline:

Telemetry  
→ Detection Rules  
→ Alert Generation  
→ Incident Correlation  
→ MITRE ATT&CK Mapping  
→ Attack Chain Reconstruction  
→ Incident Risk Scoring  
→ Analyst Workflow & Investigation  
→ Investigation Report Export

---

---

# Platform Screenshots

## Incident Investigation Dashboard
![Incident Investigation Dashboard](screenshots/investigation_dashboard.png)

## Attack Chain Visualization
![Attack Chain Visualization](screenshots/attack_chain.png)

## Investigation Timeline
![Investigation Timeline](screenshots/investigation_timeline.png)

## Investigation Report Export
![Investigation Report Export](screenshots/investigation_report.png)

# Key Features

• Incident explorer and investigation dashboard  
• Alert correlation into incidents  
• MITRE ATT&CK tactic and technique mapping  
• Multi-stage attack chain reconstruction  
• Incident risk scoring and severity context  
• Analyst workflow management (status + assignment)  
• Attack graph visualization  
• Event timeline reconstruction  
• Raw event inspection  
• Exportable **Investigation Report (PDF)**

---

# Investigation Workflow

AISOP demonstrates a realistic SOC investigation lifecycle:

1. Alerts are generated from detection rules
2. Alerts are correlated into incidents
3. Incidents are mapped to MITRE ATT&CK
4. Attack chains are reconstructed from related alerts
5. Analysts investigate incidents using timeline and event data
6. Investigation findings can be exported as a report

---

# Example Investigation Views

## Incident Overview
Displays incident severity, risk score, affected host/user, and correlated alerts.

## Attack Chain Visualization
Reconstructs ATT&CK progression such as:

Initial Access → Execution → Persistence

## Investigation Timeline
Shows ordered security events tied to the incident.

## Investigation Report
Analysts can export a SOC-style investigation report summarizing:

• Incident details  
• Related alerts  
• MITRE ATT&CK context  
• Triage summary  

---

# Technology Stack

Python  
Streamlit  
Pandas  
ReportLab (PDF generation)

---

# Running the Project

# Running the Project

Clone the repository:

```bash
git clone https://github.com/santinoholmes1979/aisop.git


---

# Purpose

AISOP is a portfolio project designed to demonstrate applied skills in:

Detection Engineering  
SOC Operations  
Incident Response  
Security Analytics  
Python Security Tooling

---

# Future Improvements

AI-assisted triage summaries  
Interactive incident timeline visualization  
Threat intelligence enrichment  
Automated detection rule evaluation