from flask import Blueprint, request, jsonify, g, send_file
import asyncio
import logging
import uuid
from typing import Dict, Any, Optional
import time
import os
from io import BytesIO

import threading

from ..scanners.scan_config import ScanConfig, ScanMode
from ..scanners.scan_manager import ScanManager
from ..middleware.rate_limiter import rate_limit
from ..middleware.safety_checks import safety_checker
from ..db import save_scan, update_scan_status, get_scan, get_recent_scans as db_get_recent_scans
from ..utils.report_generator import generate_scan_report

logger = logging.getLogger(__name__)

# Global rate limiting (100 requests per minute)
DEFAULT_RATE_LIMIT = 100

bp = Blueprint('api', __name__, url_prefix='/api')

# progress tracker bar
def _set_progress(scan_id: str, pct: int, note: str = "") -> None:
    """Update only the progress/message while status stays 'running'."""
    update_scan_status(scan_id, 'running', {
        'progress': int(max(0, min(99, pct))),  # clamp 0..99 while running
        'message': note
    })

def get_client_ip() -> str:
    """Get the client's IP address, handling proxies."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@bp.route('/scan/status/<scan_id>', methods=['GET'])
@rate_limit(max_requests=60, window=60)  # 60 requests per minute for status checks


def get_scan_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404

    # Ensure top-level progress exists and is an int
    prog = 0
    try:
        if 'progress' in scan and scan['progress'] is not None:
            prog = int(scan['progress'])
        elif isinstance(scan.get('results'), dict) and 'progress' in scan['results']:
            prog = int(scan['results']['progress'])
    except Exception:
        prog = 0
    scan['progress'] = max(0, min(100, prog))

    return jsonify(scan)

@bp.route('/scan/<scan_id>/report', methods=['GET'])
@rate_limit(max_requests=30, window=60)  # 30 requests per minute for reports
def get_scan_report(scan_id: str):
    """
    Generate and download a PDF report for a scan.
    
    Response:
        PDF file attachment
    """
    try:
        # Get scan data
        scan = get_scan(scan_id)
        if not scan:
            logger.warning(f'Scan not found: {scan_id}')
            return jsonify({
                'status': 'error',
                'message': 'Scan not found'
            }), 404
        
        logger.info(f'Generating report for scan: {scan_id}')
        
        # Generate PDF
        pdf_buffer = generate_scan_report(scan)
        
        # Return as downloadable file
        response = send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'scan_report_{scan_id}.pdf',
            mimetype='application/pdf'
        )
        
        # Set cache control headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f'Error generating report for scan {scan_id}: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to generate report: {str(e)}'
        }), 500

@bp.route('/scans/recent', methods=['GET'])
@rate_limit(max_requests=60, window=60)  # 60 requests per minute
def list_recent_scans():
    """
    Get recent scans.
    
    Query Parameters:
        limit: Maximum number of scans to return (default: 10, max: 50)
    
    Response:
    [
        {
            "id": "scan-id-123",
            "target": "example.com",
            "status": "completed",
            "scan_type": "quick",
            "created_at": "2023-01-01T12:00:00Z",
            "started_at": "2023-01-01T12:00:05Z",
            "completed_at": "2023-01-01T12:00:30Z"
        },
        ...
    ]
    """
    try:
        # Get limit from query params, default to 10, max 50
        limit = min(int(request.args.get('limit', 10)), 50)
        # Call the database function with the limit parameter
        scans = db_get_recent_scans(limit=limit)
        
        # Format the response
        formatted_scans = []
        for scan in scans:
            formatted_scan = {
                'id': scan['id'],
                'target': scan['target'],
                'status': scan['status'],
                'scan_type': scan['scan_type'],
                'created_at': scan['created_at'],
                'started_at': scan.get('started_at'),
                'completed_at': scan.get('completed_at')
            }
            # Only include results if they exist and the scan is completed
            if scan.get('results') and scan['status'] == 'completed':
                formatted_scan['has_results'] = True
            formatted_scans.append(formatted_scan)
            
        return jsonify(formatted_scans)
        
    except Exception as e:
        logger.error(f'Error getting recent scans: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve recent scans'
        }), 500

@bp.route('/scan', methods=['POST'])
@rate_limit(max_requests=30, window=60)  # 30 requests per minute for new scans
def scan():
    data = request.get_json() or {}
    target = data.get('target')
    if not target:
        return jsonify({'status': 'error', 'message': 'Target is required'}), 400

    # Validate mode
    try:
        mode = ScanMode(data.get('mode', 'quick'))
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid mode'}), 400

    config = ScanConfig(
        target=target,
        mode=mode,
        authorized=data.get('authorized', False)
    )

    # Optional module overrides
    if 'modules' in data and isinstance(data['modules'], dict):
        for k, v in data['modules'].items():
            if hasattr(config.modules, k):
                setattr(config.modules, k, v)

    client_ip = get_client_ip()

    # Create record
    scan_id = str(uuid.uuid4())
    save_scan(
        scan_id=scan_id,
        target=config.target,
        scan_type=config.mode,
        authorized=config.authorized,
        client_ip=client_ip
    )

    safety_checker.start_scan(client_ip)

    def set_progress(pct: int, msg: str = ""):
        # Store progress at the TOP LEVEL so the frontend sees it
        update_scan_status(scan_id, 'running', None, progress=int(max(0, min(99, pct))))

    def worker():
        try:
            update_scan_status(scan_id, 'running', None, progress=0)
            set_progress(5, "Starting")
            manager = ScanManager(config)

            # Optional checkpoints before the heavy call
            set_progress(30, "Ports")
            set_progress(55, "HTTP")
            set_progress(75, "TLS/SSL")
            set_progress(90, "CVE")

            # Run the async pipeline in this thread
            results = asyncio.run(manager.run_scan())

            # Finalize
            update_scan_status(scan_id, 'completed', results, progress=100)

        except Exception as e:
            logger.exception("Scan failed")
            update_scan_status(scan_id, 'failed', {'error': str(e)}, progress=0)
        finally:
            safety_checker.end_scan(client_ip)

    threading.Thread(target=worker, daemon=True).start()

    return jsonify({'status': 'success', 'scan_id': scan_id})

@bp.route('/scan/headers', methods=['POST'])
def headers_scan():
    """
    Scan HTTP headers for security best practices
    
    Request JSON:
    {
        "url": "https://example.com",  # Required
        "timeout": 10,                # Optional, defaults to 10 seconds
        "user_agent": "Custom User Agent"  # Optional
    }
    
    Response:
    {
        "url": "https://example.com",
        "status_code": 200,
        "headers": {
            "server": "nginx/1.18.0",
            "content-type": "text/html",
            ...
        },
        "missing_headers": [
            "Content-Security-Policy",
            "Permissions-Policy"
        ],
        "security_issues": [
            {
                "header": "X-XSS-Protection",
                "issue": "Missing X-XSS-Protection header",
                "severity": "medium",
                "remediation": "Add X-XSS-Protection header with value '1; mode=block'"
            },
            ...
        ]
    }
    """
    data = request.get_json() or {}
    url = data.get('url')
    timeout = data.get('timeout', 10)
    user_agent = data.get('user_agent')
    
    if not url:
        return jsonify({
            'status': 'error',
            'message': 'URL is required'
        }), 400
    
    try:
        scanner = HeadersScanner(timeout=timeout, user_agent=user_agent)
        result = scanner.scan(url)
        return jsonify(result.to_dict())
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Header scan failed: {str(e)}'
        }), 500

