from io import BytesIO
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

import logging
logger = logging.getLogger(__name__)


_styles = None

def get_styles():
    global _styles
    if _styles:
        return _styles

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="TitleCenter",
        fontSize=18,
        leading=22,
        alignment=1,
        fontName="Times-Bold",
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="Heading",
        fontSize=14,
        leading=18,
        fontName="Times-Bold",
        spaceBefore=16,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name="Body",
        fontSize=10,
        leading=14,
        fontName="Times-Roman",
        wordWrap="LTR",
    ))

    _styles = styles
    return styles


#   DATE / DURATION HELPERS
def format_timestamp(ts):
    if not ts:
        return "—"
    try:
        if isinstance(ts, (float, int)):
            return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M:%S")
        return str(ts)
    except Exception:
        return str(ts)


def calculate_duration(start, end):
    if not start or not end:
        return "—"
    try:
        duration = int(end - start)
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        return f"{hours:02}:{minutes:02}:{seconds:02}"
    except Exception:
        return "—"


#   PORT REMEDIATION SUGGESTIONS
PORT_REMEDIATION = {
    22:   "Restrict SSH access, use key-based authentication, and disable password logins.",
    80:   "Enable HTTPS (TLS) to encrypt HTTP traffic.",
    443:  "Ensure SSL/TLS configuration is secure; disable weak protocols and ciphers.",
    8080: "Avoid exposing admin or proxy interfaces publicly; restrict access.",
}

def port_remediation(port: int) -> str:
    return PORT_REMEDIATION.get(
        port,
        "Review service configuration and restrict exposure if unnecessary."
    )


#   METADATA TABLE
def build_metadata(scan: Dict[str, Any]):
    start = scan.get("start_time")
    end = scan.get("end_time")

    data = [
        ["Target",     scan.get("target", "—")],
        ["Scan Type",  scan.get("scan_type", "—").title()],
        ["Scan Date",  format_timestamp(start)],
        ["Duration",   calculate_duration(start, end)],
        ["Status",     scan.get("status", "—").title()],
    ]

    tbl = Table(data, colWidths=[140, 300])
    tbl.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Times-Roman", 10),
        ("FONT", (0, 0), (0, -1), "Times-Bold", 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
    ]))
    return tbl


#   OPEN PORT TABLE + REMEDIATION
def build_open_ports_table(ports: List[Dict[str, Any]]):
    styles = get_styles()
    body_style = styles["Body"]

    if not ports:
        return Paragraph("No open ports detected.", body_style)

    data = [["Port", "Service", "Status", "Remediation"]]

    for p in ports:
        port = p.get("port")
        remediation_para = Paragraph(port_remediation(port), body_style)
        data.append([
            str(port),
            p.get("service", "unknown"),
            "Open",
            remediation_para
        ])

    tbl = Table(data, colWidths=[50, 120, 60, 260], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Times-Bold", 11),

        # body rows
        ("FONT", (0, 1), (-1, -1), "Times-Roman", 10),
        ("VALIGN", (0, 1), (-1, -1), "TOP"),

        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl


#   HEADERS / SSL / CVE TABLES
def build_http_headers_table(issues: List[str]):
    styles = get_styles()
    body_style = styles["Body"]

    if not issues:
        return Paragraph("No insecure HTTP headers detected.", body_style)

    data = [["Issue"]]
    for i in issues:
        data.append([Paragraph(i, body_style)])

    tbl = Table(data, colWidths=[400], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Times-Bold", 11),

        ("FONT", (0, 1), (-1, -1), "Times-Roman", 10),
        ("VALIGN", (0, 1), (-1, -1), "TOP"),

        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    return tbl


def build_ssl_table(issues):
    styles = get_styles()
    body_style = styles["Body"]

    if not issues:
        return Paragraph("No SSL/TLS misconfigurations detected.", body_style)

    data = [["Severity", "Description"]]
    for i in issues:
        desc = Paragraph(i.get("description", "—"), body_style)
        data.append([
            i.get("severity", "—"),
            desc
        ])

    tbl = Table(data, colWidths=[100, 300], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Times-Bold", 11),

        ("FONT", (0, 1), (-1, -1), "Times-Roman", 10),
        ("VALIGN", (0, 1), (-1, -1), "TOP"),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    return tbl


def build_cve_table(cves):
    styles = get_styles()
    body_style = styles["Body"]

    if not cves:
        return Paragraph("No CVE matches detected.", body_style)

    data = [["CVE ID", "Severity", "Description"]]
    for c in cves:
        desc = Paragraph(c.get("description", "—"), body_style)
        data.append([
            c.get("cve_id", "—"),
            c.get("severity", "—"),
            desc
        ])

    tbl = Table(data, colWidths=[90, 80, 260], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONT", (0, 0), (-1, 0), "Times-Bold", 11),

        ("FONT", (0, 1), (-1, -1), "Times-Roman", 10),
        ("VALIGN", (0, 1), (-1, -1), "TOP"),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    return tbl


#   MAIN PDF GENERATOR
def generate_scan_report(scan: Dict[str, Any]) -> BytesIO:
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = get_styles()
    story = []

    # Title
    story.append(Paragraph("VULNERABILITY SCAN REPORT", styles["TitleCenter"]))
    story.append(Spacer(1, 10))

    # Metadata block
    story.append(Paragraph("Scan Information", styles["Heading"]))
    story.append(build_metadata(scan))
    story.append(Spacer(1, 20))

    # MODULE DATA
    mods = scan.get("results", {}).get("modules", {})

    ports = mods.get("port_scan", {}).get("open_ports", [])
    headers = mods.get("http_headers", {}).get("results", {}).get("missing_headers", [])
    ssl = mods.get("ssl_scan", {}).get("vulnerabilities", [])
    cves = mods.get("cve_check", {}).get("cves_found", [])

    total_issues = len(ports) + len(headers) + len(ssl) + len(cves)

    severity = "Low"
    if any(x for x in ssl if x.get("severity") == "high"):
        severity = "High"
    elif headers:
        severity = "Medium"

    story.append(Paragraph("Summary", styles["Heading"]))
    summary_table = Table(
        [
            ["Total Issues Found", str(total_issues)],
            ["Overall Severity", severity],
        ],
        colWidths=[160, 280]
    )
    summary_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Times-Roman", 11),
        ("FONT", (0, 0), (0, -1), "Times-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    #   MODULE TABLES
    story.append(Paragraph("Open Ports & Services", styles["Heading"]))
    story.append(build_open_ports_table(ports))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Insecure HTTP Headers", styles["Heading"]))
    story.append(build_http_headers_table(headers))
    story.append(Spacer(1, 16))

    story.append(Paragraph("SSL/TLS Misconfigurations", styles["Heading"]))
    story.append(build_ssl_table(ssl))
    story.append(Spacer(1, 16))

    story.append(Paragraph("CVE Matches", styles["Heading"]))
    story.append(build_cve_table(cves))
    story.append(Spacer(1, 20))

    story.append(Paragraph(
        "<i>Generated by VASA – Vulnerability Assessment Scanner</i>",
        styles["Body"]
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer