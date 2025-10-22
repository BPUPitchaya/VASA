from flask import Blueprint, request, jsonify, g, send_file
import asyncio
import logging
import uuid
from typing import Dict, Any, Optional
import time
import os
from io import BytesIO

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

def get_client_ip() -> str:
    """Get the client's IP address, handling proxies."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@bp.route('/scan/status/<scan_id>', methods=['GET'])
@rate_limit(max_requests=30, window=60)  # 30 status checks per minute
def get_scan_status(scan_id: str):
    """
    Get the status of a scan.
    
    Response:
    {
        "id": "uuid",
        "target": "example.com",
        "status": "queued" | "running" | "completed" | "failed",
        "scan_type": "quick" | "standard" | "full" | "custom",
        "created_at": "2023-01-01T12:00:00Z",
        "started_at": "2023-01-01T12:00:05Z",
        "completed_at": "2023-01-01T12:00:30Z",
        "results": { ... }  # When status is completed
    }
    """
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({
            'status': 'error',
            'message': 'Scan not found'
        }), 404
        
    return jsonify(scan)

@bp.route('/scan/<scan_id>/report', methods=['GET'])
@rate_limit(max_requests=10, window=60)  # 10 report generations per minute
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
@rate_limit(max_requests=30, window=60)  # 30 recent scans requests per minute
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

@bp.route('/scan', methods=['POST', 'GET'])
@rate_limit(max_requests=5, window=60)  # 5 new scans per minute
async def scan():
    """
    Unified scan endpoint that handles all scan types based on configuration.
    
    GET Request Parameters:
        target: The target to scan (required)
        mode: Scan mode (quick/standard/full/custom, default: quick)
        
    POST Request JSON:
    {
        "target": "example.com",  # Required
        "mode": "quick" | "standard" | "full" | "custom",  # Optional, default: quick
        "authorized": false,  # Required for standard/full scans
        "modules": {
            "port_scan": true,
            "service_scan": true,
            "http_headers": true,
            "ssl_scan": true,
            "cve_check": false,
            "dns_whois": true,
            "save_to_history": true
        }
    }
    """
    try:
        # Log request details for debugging
        logger.info(f"Incoming request: {request.method} {request.url}")
        logger.info(f"Headers: {dict(request.headers)}")
        
        if request.method == 'GET':
            # Handle GET request with query parameters
            data = request.args.to_dict()
            logger.info(f"GET params: {data}")
        else:
            # Handle POST request with JSON body
            if not request.is_json:
                logger.error("Request is not JSON")
                return jsonify({
                    'status': 'error',
                    'message': 'Request must be JSON',
                    'content_type': request.content_type,
                    'received_data': str(request.data)
                }), 400
                
            data = request.get_json()
            logger.info(f"POST JSON data: {data}")
            
        # Validate required fields
        if 'target' not in data:
            logger.error("Missing required field: target")
            return jsonify({
                'status': 'error',
                'message': 'Target is required',
                'received_data': data
            }), 400
            
        # Get target and mode with defaults
        target = data.get('target')
        mode = data.get('mode', 'quick').lower()
        
        logger.info(f"Starting {mode} scan for target: {target}")
        
        # Return a success response with the scan details
        return jsonify({
            'status': 'success',
            'message': f'Scan started for {target} in {mode} mode',
            'target': target,
            'mode': mode
        })
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_type': type(e).__name__
        }), 500
    data = request.get_json() or {}
    target = data.get('target')
    port = data.get('port', 443)
    timeout = data.get('timeout', 10)
    
    if not target:
        return jsonify({
            'status': 'error',
            'message': 'Target is required'
        }), 400
    
    # Create config with proper parameter order and module overrides
    config = ScanConfig(
        target=target,
        mode=ScanMode(data.get('mode', 'quick')),
        authorized=data.get('authorized', False)
    )
    
    # Apply any module overrides from the request
    if 'modules' in data and isinstance(data['modules'], dict):
        for key, value in data['modules'].items():
            if hasattr(config.modules, key):
                setattr(config.modules, key, value)
    client_ip = get_client_ip()
    
    # Generate scan ID and save to database
    scan_id = str(uuid.uuid4())
    save_scan(
        scan_id=scan_id,
        target=config.target,
        scan_type=config.mode,
        authorized=config.authorized,
        client_ip=client_ip
    )
    
    safety_checker.start_scan(client_ip)
    
    # Start the scan in the background
    async def run_scan_async():
        try:
            # Update status to running
            update_scan_status(scan_id, 'running')
            
            # Run the scan
            manager = ScanManager(config)
            results = await manager.run_scan()
            
            # Save successful results
            update_scan_status(scan_id, 'completed', results)
            return results
            
        except Exception as e:
            logger.exception("Scan failed")
            update_scan_status(scan_id, 'failed', {'error': str(e)})
            return {
                'status': 'failed',
                'error': str(e)
            }
        finally:
            safety_checker.end_scan(client_ip)
            
    asyncio.create_task(run_scan_async())
    
    return jsonify({
        'status': 'success',
        'scan_id': scan_id
    })

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
