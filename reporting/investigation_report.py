from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from datetime import datetime


def generate_investigation_report(incident, alerts_df, triage_df, case_notes=None):
    if case_notes is None:
        case_notes = []

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    y = 750

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "AISOP Investigation Report")

    y -= 40
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Generated: {datetime.utcnow()}")

    y -= 40
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Incident Summary")

    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Incident ID: {incident['incident_id']}")
    y -= 15
    pdf.drawString(50, y, f"User: {incident.get('user', 'N/A')}")
    y -= 15
    pdf.drawString(50, y, f"Host: {incident.get('host', 'N/A')}")
    y -= 15
    pdf.drawString(50, y, f"Severity: {incident.get('severity', 'N/A')}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Related Alerts")

    y -= 20
    pdf.setFont("Helvetica", 9)

    if not alerts_df.empty:
        for _, row in alerts_df.head(10).iterrows():
            alert_name = row.get("rule_name", row.get("alert_type", row.get("title", "Unknown Alert")))
            line = f"{row.get('timestamp', 'N/A')} | {alert_name} | {row.get('severity', 'N/A')}"
            pdf.drawString(50, y, line)
            y -= 12

            if y < 100:
                pdf.showPage()
                y = 750
                pdf.setFont("Helvetica", 9)
    else:
        pdf.drawString(50, y, "No related alerts found.")
        y -= 12

    y -= 20
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "AI Triage Notes")

    y -= 20
    pdf.setFont("Helvetica", 9)

    if not triage_df.empty:
        for _, row in triage_df.iterrows():
            note = f"{row.get('timestamp', '')} - {row.get('analyst_note', row.get('summary', 'No summary available'))}"
            pdf.drawString(50, y, note)
            y -= 12

            if y < 100:
                pdf.showPage()
                y = 750
                pdf.setFont("Helvetica", 9)
    else:
        pdf.drawString(50, y, "No triage notes available.")
        y -= 12

    y -= 20
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Case Notes")

    y -= 20
    pdf.setFont("Helvetica", 9)

    if case_notes:
        for note in case_notes:
            pdf.drawString(50, y, f"- {str(note)}")
            y -= 12

            if y < 100:
                pdf.showPage()
                y = 750
                pdf.setFont("Helvetica", 9)
    else:
        pdf.drawString(50, y, "No analyst case notes recorded.")
        y -= 12

    pdf.save()
    buffer.seek(0)
    return buffer

