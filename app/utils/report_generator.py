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


# STYLE HANDLING
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
        fontName="Helvetica-Bold",
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="Heading",
        fontSize=14,
        leading=18,
        fontName="Helvetica-Bold",
        spaceBefore=16,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name="Body",
        fontSize=10,
        leading=14
    ))

    _styles = styles
    return styles

def format_timestamp(ts):
    """Convert Unix timestamp or string to human-readable date."""
    if not ts:
        return "—"
    try:
        # Numeric Unix timestamp
        if isinstance(ts, (float, int)):
            return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M:%S")
        # ISO or other strings
        return str(ts)
    except Exception:
        return str(ts)


def calculate_duration(start, end):
    """Return duration HH:MM:SS or —"""
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

# METADATA TABLE
def build_metadata(scan: Dict[str, Any]):
    start = scan.get("start_time")
    end = scan.get("end_time")

    data = [
        ["Target", scan.get("target", "—")],
        ["Scan Type", scan.get("scan_type", "—").title()],
        ["Scan Date", format_timestamp(start)],
        ["Duration", calculate_duration(start, end)],
        ["Status", scan.get("status", "—").title()],
    ]

    tbl = Table(data, colWidths=[140, 300])
    tbl.setStyle(TableStyle([
        ("FONT", (0,0), (-1,-1), "Helvetica", 10),
        ("FONT", (0,0), (0,-1), "Helvetica-Bold", 10),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke)
    ]))

    return tbl


def build_open_ports_table(ports: List[Dict[str,Any]]):
    if not ports:
        return Paragraph("No open ports detected.", get_styles()["Body"])

    data = [["Port", "Service", "Status"]]
    for p in ports:
        data.append([
            str(p.get("port")),
            p.get("service", "unknown"),
            "Open"
        ])

    tbl = Table(data, colWidths=[80, 150, 80], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f2f2f2")])
    ]))

    return tbl


def build_http_headers_table(issues: List[str]):
    if not issues:
        return Paragraph("No insecure HTTP headers detected.", get_styles()["Body"])

    data = [["Issue"]]
    for i in issues:
        data.append([i])

    tbl = Table(data, colWidths=[400], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey)
    ]))

    return tbl


def build_ssl_table(issues: List[Dict]):
    if not issues:
        return Paragraph("No SSL/TLS misconfigurations detected.", get_styles()["Body"])

    data = [["Severity", "Description"]]
    for i in issues:
        data.append([
            i.get("severity", "—"),
            i.get("description", "—")
        ])

    tbl = Table(data, colWidths=[100, 300], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey)
    ]))

    return tbl


def build_cve_table(cves: List[Dict]):
    if not cves:
        return Paragraph("No CVE matches detected.", get_styles()["Body"])

    data = [["CVE ID", "Severity", "Description"]]
    for c in cves:
        data.append([
            c.get("cve_id", "—"),
            c.get("severity", "—"),
            c.get("description", "—")
        ])

    tbl = Table(data, colWidths=[90, 80, 260], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey)
    ]))

    return tbl


# main pdf generator
def generate_scan_report(scan: Dict[str, Any]) -> BytesIO:
    """Generate clean uniform PDF for VASA."""
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

    # Metadata
    story.append(Paragraph("Scan Information", styles["Heading"]))
    story.append(build_metadata(scan))
    story.append(Spacer(1, 20))

    # Modules
    mods = scan.get("results", {}).get("modules", {})

    # PORTS
    story.append(Paragraph("Open Ports & Services", styles["Heading"]))
    story.append(build_open_ports_table(mods.get("port_scan", {}).get("open_ports", [])))
    story.append(Spacer(1, 16))

    # HEADERS
    story.append(Paragraph("Insecure HTTP Headers", styles["Heading"]))
    story.append(build_http_headers_table(
        mods.get("http_headers", {}).get("results", {}).get("missing_headers", [])
    ))
    story.append(Spacer(1, 16))

    # SSL
    story.append(Paragraph("SSL/TLS Misconfigurations", styles["Heading"]))
    story.append(build_ssl_table(
        mods.get("ssl_scan", {}).get("vulnerabilities", [])
    ))
    story.append(Spacer(1, 16))

    # CVEs
    story.append(Paragraph("CVE Matches", styles["Heading"]))
    story.append(build_cve_table(
        mods.get("cve_check", {}).get("cves_found", [])
    ))
    story.append(Spacer(1, 20))

    # Footer
    story.append(Paragraph("<i>Generated by VASA – Vulnerability Assessment Scanner</i>", styles["Body"]))

    doc.build(story)
    buffer.seek(0)
    return buffer