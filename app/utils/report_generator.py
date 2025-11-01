from io import BytesIO
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os
from typing import Dict, Any, Union, List
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Define styles at module level to avoid redefinition
_styles = None

def get_styles():
    """Get or create styles, ensuring they're only created once."""
    global _styles
    if _styles is None:
        try:
            _styles = getSampleStyleSheet()
            # Only add styles if they don't exist
            if 'Title' not in _styles:
                _styles.add(ParagraphStyle(
                    name='Title', 
                    fontSize=18, 
                    alignment=1,  # center
                    spaceAfter=20,
                    fontName='Helvetica-Bold'
                ))
            if 'Heading1' not in _styles:
                _styles.add(ParagraphStyle(
                    name='Heading1',
                    fontSize=14,
                    spaceAfter=12,
                    spaceBefore=20,
                    fontName='Helvetica-Bold'
                ))
            if 'Normal_Justified' not in _styles:
                _styles.add(ParagraphStyle(
                    name='Normal_Justified',
                    alignment=4,  # justify
                    fontSize=10,
                    leading=14,
                    fontName='Helvetica'
                ))
            if 'Normal' not in _styles:
                _styles.add(ParagraphStyle(
                    name='Normal',
                    fontSize=10,
                    leading=12,
                    fontName='Helvetica'
                ))
        except Exception as e:
            logger.error(f"Error creating styles: {str(e)}", exc_info=True)
            raise
    return _styles

def _create_metadata_table(scan_data: Dict[str, Any], styles: Dict) -> Table:
    """Create a table with scan metadata."""
    from reportlab.platypus import Table
    
    # Prepare data for the table
    data = [
        ["Target:", scan_data.get('target', 'N/A')],
        ["Scan ID:", scan_data.get('id', 'N/A')],
        ["Status:", scan_data.get('status', 'N/A').title()],
        ["Scan Type:", str(scan_data.get('scan_type', 'N/A')).title()],
        ["Created At:", scan_data.get('created_at', 'N/A')],
        ["Started At:", scan_data.get('started_at', 'N/A')],
        ["Completed At:", scan_data.get('completed_at', 'N/A') or 'N/A']
    ]
    
    # Create table with 2 columns
    table = Table(data, colWidths=[120, 300])
    table.setStyle(TableStyle([
        ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),  # Make first column bold
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.black),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    
    return table

def _create_vulnerabilities_table(vulns: List[Dict], styles: Dict) -> Table:
    """Create a table with vulnerabilities."""
    if not vulns:
        return Paragraph("No vulnerabilities found.", styles['Normal'])
    
    # Prepare table data
    data = [
        ["Severity", "Vulnerability", "Location", "Description"],
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

def generate_scan_report(scan_data: Dict[str, Any]) -> BytesIO:
    """
    Generate a PDF report for a vulnerability scan.
    
    Args:
        scan_data: Dictionary containing scan results
        
    Returns:
        BytesIO: PDF file as bytes
    """
    try:
        # Initialize buffer and document
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,
            rightMargin=36,  # Reduced from 72 for more space
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
            title=f"Vulnerability Scan Report - {scan_data.get('id', '')}"
        )
        
        # Get styles
        styles = get_styles()
        story = []
        
        # Add title
        story.append(Paragraph("VULNERABILITY SCAN REPORT", styles['Title']))
        story.append(Spacer(1, 10))
        
        # Add scan metadata table
        story.append(Paragraph("Scan Information", styles['Heading1']))
        story.append(_create_metadata_table(scan_data, styles))
        story.append(Spacer(1, 20))
        
        # Add vulnerabilities section
        story.append(Paragraph("Vulnerabilities Found", styles['Heading1']))
        
        # Check if we have results
        results = scan_data.get('results')
        if isinstance(results, str):
            try:
                results = json.loads(results)
            except (json.JSONDecodeError, TypeError):
                results = {'vulnerabilities': []}
        
        # Add vulnerabilities table
        vulns = results.get('vulnerabilities', []) if isinstance(results, dict) else []
        story.append(_create_vulnerabilities_table(vulns, styles))
        story.append(Spacer(1, 20))
        
        # Add footer
        story.append(Spacer(1, 20))
        story.append(Paragraph("Report generated by VASA - Vulnerability Assessment and Scanning Application", 
                             styles['Normal_Justified']))
        
        # Build the PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}", exc_info=True)
        # Return a minimal error report
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = get_styles()
        story = [
            Paragraph("Error Generating Report", styles['Title']),
            Spacer(1, 20),
            Paragraph(f"An error occurred while generating the report: {str(e)}", styles['Normal']),
            Spacer(1, 20),
            Paragraph("Please try again or contact support if the problem persists.", styles['Normal'])
        ]
        doc.build(story)
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
    if 'vulnerabilities' in scan_data and scan_data['vulnerabilities']:
        story.append(Spacer(1, 20))
        story.append(Paragraph("Vulnerabilities Found", styles['Heading1']))
        
        vuln_data = [['ID', 'Severity', 'Description', 'Remediation']]
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
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{scan_data.get('id', '')}_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)
    
    # Generate and save the report
    pdf = generate_scan_report(scan_data)
    with open(filepath, 'wb') as f:
        f.write(pdf.getbuffer())
    
    return filepath
