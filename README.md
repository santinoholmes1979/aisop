# AISOP – AI Security Operations Platform

AISOP is a SOC-style investigation platform built in **Python and Streamlit** that converts raw security telemetry into actionable incident investigations.

The platform demonstrates how detection pipelines evolve into full **Security Operations Center (SOC) workflows**, including alert correlation, ATT&CK mapping, attack chain reconstruction, analyst investigation tools, and investigation report export.

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

Clone the repository:

git clone https://github.com/santinoholmes1979/aisop.git


Install dependencies:



pip install -r requirements.txt


Run the platform:



streamlit run app.py


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