from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from datetime import datetime
import os
from typing import Dict, Any, List, Optional
import logging

# Set up logging
logger = logging.getLogger(__name__)

# ---------- Header & Footer for each page ----------
def add_header_footer(canvas, doc, scan_data):
    """Add header and footer to each page of the PDF."""
    width, height = A4
    canvas.setStrokeColor(colors.HexColor('#2c3e50'))
    canvas.setLineWidth(0.5)

    # Header
    canvas.line(15 * mm, height - 18 * mm, width - 15 * mm, height - 18 * mm)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15 * mm, height - 14 * mm, "VASA — Vulnerability Assessment Scanner Application")
    
    # Footer
    canvas.setFont("Helvetica", 8)
    # Draw the timestamp
    timestamp = f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    canvas.drawString(15 * mm, 10 * mm, timestamp)
    # Draw the page number
    canvas.drawRightString(width - 15 * mm, 10 * mm, f"Page {doc.page}")
    
    # Set the page property for the next page
    if hasattr(doc, '_pageNumber'):
        doc._pageNumber += 1
    else:
        doc._pageNumber = 1

def get_styles():
    """Get or create styles for the PDF."""
    # Create a simple dictionary to hold our styles
    styles = {}
    
    # Base normal style
    normal = ParagraphStyle(
        'Custom_Normal',
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        spaceAfter=10,
        alignment=0  # Left align
    )
    styles['Normal'] = normal
    
    # Title style
    styles['Report_Title'] = ParagraphStyle(
        'Custom_Title',
        parent=normal,
        fontName='Helvetica-Bold',
        fontSize=18,
        spaceAfter=20,
        textColor=colors.HexColor('#2c3e50'),
        alignment=1  # Center align
    )
    
    # Subtitle style
    styles['Report_Subtitle'] = ParagraphStyle(
        'Custom_Subtitle',
        parent=normal,
        alignment=1,  # Center align
        fontSize=11,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=20
    )
    
    # Heading 1 style
    styles['Report_Heading1'] = ParagraphStyle(
        'Custom_Heading1',
        parent=normal,
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#2c3e50'),
        spaceBefore=15,
        spaceAfter=10
    )
    
    # Heading 2 style
    styles['Report_Heading2'] = ParagraphStyle(
        'Custom_Heading2',
        parent=normal,
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#2c3e50'),
        spaceBefore=10,
        spaceAfter=5
    )
    
    # Normal justified style
    styles['Report_Normal_Justified'] = ParagraphStyle(
        'Custom_Normal_Justified',
        parent=normal,
        alignment=4,  # Justify
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=10
    )
    
    # Vulnerability styles
    styles['Report_Vulnerability_High'] = ParagraphStyle(
        'Custom_Vulnerability_High',
        parent=normal,
        textColor=colors.HexColor('#e74c3c'),
        backColor=colors.HexColor('#fadbd8'),
        fontSize=9,
        leading=12,
        padding=3
    )
    
    styles['Report_Vulnerability_Medium'] = ParagraphStyle(
        'Custom_Vulnerability_Medium',
        parent=normal,
        textColor=colors.HexColor('#f39c12'),
        backColor=colors.HexColor('#fef5e7'),
        fontSize=9,
        leading=12,
        padding=3
    )
    
    styles['Report_Vulnerability_Low'] = ParagraphStyle(
        'Custom_Vulnerability_Low',
        parent=normal,
        textColor=colors.HexColor('#3498db'),
        backColor=colors.HexColor('#ebf5fb'),
        fontSize=9,
        leading=12,
        padding=3
    )
    
    return styles

def _create_metadata_table(scan_data: Dict[str, Any], styles: Dict) -> Table:
    """Create a table with scan metadata.
    
    Args:
        scan_data: Dictionary containing scan data
        styles: Dictionary of styles
        
    Returns:
        Table: Formatted table with metadata
    """
    # Prepare data for the table
    data = [
        ["Target", scan_data.get('target', 'N/A')],
        ["Scan ID", scan_data.get('id', 'N/A')],
        ["Status", scan_data.get('status', 'N/A').title()],
        ["Scan Type", str(scan_data.get('scan_type', 'N/A')).title()],
        ["Created At", scan_data.get('created_at', 'N/A')],
        ["Started At", scan_data.get('started_at', 'N/A')],
        ["Completed At", scan_data.get('completed_at', 'N/A') or 'N/A']
    ]
    
    # Create table with 2 columns and apply styles
    table_style = [
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#333333')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]
    
    return Table(data, colWidths=[40 * mm, None], style=table_style)

def _create_vulnerabilities_table(vulns: List[Dict], styles: Dict) -> Table:
    """Create a table with vulnerabilities."""
    if not vulns:
        return [
            Spacer(1, 10 * mm),
            Paragraph("No vulnerabilities found.", styles['Report_Normal_Justified'])
        ]
    
    # Prepare table data
    data = [
        [
            Paragraph("<b>Severity</b>", styles['Report_Normal_Justified']),
            Paragraph("<b>Vulnerability</b>", styles['Report_Normal_Justified']),
            Paragraph("<b>Location</b>", styles['Report_Normal_Justified']),
            Paragraph("<b>Description</b>", styles['Report_Normal_Justified'])
        ]
    ]
    
    for vuln in vulns:
        data.append([
            vuln.get('severity', 'N/A').upper(),
            vuln.get('name', 'N/A'),
            vuln.get('location', 'N/A'),
            vuln.get('description', 'No description available')
        ])
    
    # Create table
    table = Table(data, colWidths=[60, 100, 100, 240], repeatRows=1)
    
    # Style the table
    table.setStyle(TableStyle([
        # Header
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        
        # Rows
        ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        
        # Alternating row colors
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        
        # Cell padding
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    
    return table


def _get_severity_style(severity: str) -> str:
    """Get the appropriate style for a given severity level."""
    severity = (severity or '').lower()
    if 'high' in severity or 'critical' in severity:
        return 'Report_Vulnerability_High'
    elif 'medium' in severity or 'moderate' in severity:
        return 'Report_Vulnerability_Medium'
    return 'Report_Vulnerability_Low'

def generate_scan_report(scan_data: Dict[str, Any]) -> BytesIO:
    """
    Generate a PDF report for a vulnerability scan.
    
    Args:
        scan_data: Dictionary containing scan results
        
    Returns:
        BytesIO: PDF file as bytes
    """
    # Create a buffer to store the PDF
    buffer = BytesIO()
    
    # Get our custom styles
    styles = get_styles()
    
    # Create the PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm
    )
    
    # Prepare elements list
    elements = []
    
    # -------- Title Page --------
    elements.append(Spacer(1, 30 * mm))
    elements.append(Paragraph("Vulnerability Assessment Report", styles['Report_Title']))
    elements.append(Spacer(1, 10 * mm))
    
    # Add target information
    target = scan_data.get('target', 'N/A')
    scan_type = scan_data.get('scan_type', 'N/A').title()
    elements.append(Paragraph(f"Target: <b>{target}</b>", styles['Report_Subtitle']))
    elements.append(Paragraph(f"Scan Type: {scan_type}", styles['Report_Subtitle']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Report_Subtitle']))
    elements.append(Spacer(1, 20 * mm))
    
    # -------- Section 1: Target Information --------
    elements.append(Paragraph("1. Target Information", styles['Report_Heading1']))
    elements.append(_create_metadata_table(scan_data, styles))
    elements.append(Spacer(1, 10 * mm))
    
    # -------- Section 2: Summary of Findings --------
    elements.append(Paragraph("2. Summary of Findings", styles['Report_Heading1']))
    
    # Count vulnerabilities by severity
    vulns = scan_data.get('vulnerabilities', [])
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    
    for vuln in vulns:
        sev = (vuln.get('severity', '').lower() or 'low').lower()
        if 'high' in sev or 'critical' in sev:
            severity_counts['high'] += 1
        elif 'medium' in sev or 'moderate' in sev:
            severity_counts['medium'] += 1
        else:
            severity_counts['low'] += 1
    
    total = sum(severity_counts.values())
    
    # Create summary table
    summary_data = [
        ["Total", "High", "Medium", "Low"],
        [
            str(total),
            str(severity_counts['high']),
            str(severity_counts['medium']),
            str(severity_counts['low'])
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[30 * mm] * 4)
    summary_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#bdc3c7')),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#e74c3c')),  # High count in red
        ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#f39c12')),  # Medium count in orange
        ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#3498db')),  # Low count in blue
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 15 * mm))
    
    # -------- Section 3: Detailed Findings --------
    if vulns:
        elements.append(Paragraph("3. Detailed Findings", styles['Report_Heading1']))
        
        for i, vuln in enumerate(vulns, 1):
            # Vulnerability header
            severity = vuln.get('severity', 'Low').title()
            severity_style = _get_severity_style(severity)
            
            elements.append(Paragraph(
                f"{i}. {vuln.get('title', 'Untitled Vulnerability')}",
                styles['Report_Heading2']
            ))
            
            # Severity badge
            elements.append(Paragraph(
                f"Severity: {severity}",
                styles[severity_style]
            ))
            
            # Description
            if 'description' in vuln:
                elements.append(Paragraph("<b>Description:</b>", styles['Report_Normal_Justified']))
                elements.append(Paragraph(vuln['description'], styles['Report_Normal_Justified']))
            
            # Location/Details
            if 'location' in vuln or 'details' in vuln:
                elements.append(Spacer(1, 5 * mm))
                elements.append(Paragraph("<b>Details:</b>", styles['Report_Normal_Justified']))
                
                details = []
                if 'location' in vuln:
                    details.append(f"<b>Location:</b> {vuln['location']}")
                if 'details' in vuln:
                    if isinstance(vuln['details'], dict):
                        for k, v in vuln['details'].items():
                            details.append(f"<b>{k}:</b> {v}")
                    else:
                        details.append(str(vuln['details']))
                
                for detail in details:
                    elements.append(Paragraph(detail, styles['Report_Normal_Justified']))
            
            # Recommendation
            if 'recommendation' in vuln:
                elements.append(Spacer(1, 5 * mm))
                elements.append(Paragraph("<b>Recommendation:</b>", styles['Report_Normal_Justified']))
                elements.append(Paragraph(vuln['recommendation'], styles['Report_Normal_Justified']))
            
            elements.append(Spacer(1, 10 * mm))
    
    # -------- Section 4: Notes --------
    elements.append(Paragraph("4. Notes", styles['Report_Heading1']))
    elements.append(Paragraph(
        "This report was automatically generated by VASA. The information in this report is provided "
        "for educational and testing purposes only. Ensure all scans are performed with proper authorization "
        "and in compliance with applicable laws and regulations.",
        styles['Report_Normal_Justified']
    ))
    
    # Add page numbers and build the PDF
    def on_page(canvas, doc):
        add_header_footer(canvas, doc, scan_data)
    
    # Build the PDF
    doc.build(elements, onFirstPage=on_page, onLaterPages=on_page)
    
    # Reset buffer position to the beginning
    buffer.seek(0)
    return buffer
    summary_data = [
        ['Status', scan_data.get('status', 'N/A')],
        ['Start Time', scan_data.get('started_at', 'N/A')],
        ['End Time', scan_data.get('completed_at', 'N/A')],
        ['Total Vulnerabilities', str(len(scan_data.get('vulnerabilities', [])))]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BOX', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    
    # Add vulnerabilities section if any
    # Check if we need to add vulnerabilities section
    if 'vulnerabilities' in scan_data and scan_data['vulnerabilities']:
        elements.append(Spacer(1, 10 * mm))
        elements.append(Paragraph("Vulnerabilities Found", styles['Heading1']))
        
        # Add vulnerabilities table
        vuln_data = [
            [
                Paragraph('<b>ID</b>', styles['Normal_Justified']),
                Paragraph('<b>Severity</b>', styles['Normal_Justified']),
                Paragraph('<b>Description</b>', styles['Normal_Justified']),
                Paragraph('<b>Remediation</b>', styles['Normal_Justified'])
            ]
        ]
        
        for i, vuln in enumerate(scan_data['vulnerabilities'], 1):
            severity_style = _get_severity_style(vuln.get('severity', 'low'))
            vuln_data.append([
                str(i),
                Paragraph(vuln.get('severity', 'N/A').upper(), styles[severity_style]),
                vuln.get('description', 'No description available'),
                vuln.get('remediation', 'No remediation available')
            ])
        
        # Create and style the table
        vuln_table = Table(vuln_data, colWidths=[15*mm, 25*mm, 80*mm, 50*mm])
        vuln_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        
        elements.append(vuln_table)
        for vuln in scan_data['vulnerabilities']:
            severity = vuln.get('severity', 'unknown').lower()
            severity_color = {
                'critical': 'red',
                'high': 'darkorange',
                'medium': 'orange',
                'low': 'green',
                'info': 'blue'
            }.get(severity, 'black')
            
            vuln_data.append([
                vuln.get('id', 'N/A'),
                f'<font color="{severity_color}">{severity.upper()}</font>',
                vuln.get('description', 'No description'),
                vuln.get('remediation', 'No remediation provided')
            ])
        
        vuln_table = Table(vuln_data, colWidths=[0.8*inch, 1*inch, 2.5*inch, 2.5*inch], repeatRows=1)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.append(vuln_table)
    
    # Add scan details if available
    if 'details' in scan_data:
        story.append(Spacer(1, 20))
        story.append(Paragraph("Scan Details", styles['Heading1']))
        
        details = []
        for key, value in scan_data['details'].items():
            if isinstance(value, dict):
                value = ", ".join([f"{k}: {v}" for k, v in value.items()])
            details.append(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
        
        story.append(Paragraph("<br/>".join(details), styles['Normal_Justified']))
    
    # Add footer
    story.append(Spacer(1, 20))
    story.append(Paragraph("Generated by VASA Vulnerability Scanner", 
                          style=ParagraphStyle(name='Footer', fontSize=8, alignment=2)))
    
    # Build the PDF
    doc.build(story)
    
    # Reset buffer position to the beginning
    buffer.seek(0)
    return buffer

def save_report_to_file(scan_data: Dict[str, Any], output_dir: str = 'reports') -> str:
    """
    Save the report to a file.
    
    Args:
        scan_data: Dictionary containing scan results
        output_dir: Directory to save the report
        
    Returns:
        str: Path to the saved report
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_name = str(scan_data.get('target', 'scan')).replace('https://', '').replace('http://', '').replace('/', '_')
        filename = f"vulnerability_scan_{target_name}_{timestamp}.pdf"
        filepath = os.path.join(output_dir, filename)
        
        # Generate the PDF
        pdf_content = generate_scan_report(scan_data)
        
        # Write to file
        with open(filepath, 'wb') as f:
            f.write(pdf_content.getvalue())
        
        logger.info(f"Report saved to {filepath}")
        return filepath
    
    except Exception as e:
        logger.error(f"Error saving report: {str(e)}", exc_info=True)
        raise
