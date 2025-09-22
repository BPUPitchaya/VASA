from flask import Blueprint, request, jsonify, g
import asyncio
import logging
import uuid
from typing import Dict, Any, Optional
import time

from ..scanners.scan_config import ScanConfig, ScanMode
from ..scanners.scan_manager import ScanManager
from ..middleware.rate_limiter import rate_limit
from ..middleware.safety_checks import safety_checker
from ..db import save_scan, update_scan_status, get_scan, get_recent_scans

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
@rate_limit(max_requests=60, window=60)  # 60 requests per minute for status checks
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
        scans = get_recent_scans(limit)
        
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
async def scan():
    """
    Unified scan endpoint that handles all scan types based on configuration.
    
    Request JSON:
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
            "key_bits": 2048,
            "key_type": "RSA"
        },
        "protocols": ["TLSv1.2", "TLSv1.3"],
        "ciphers": [
            {
                "name": "TLS_AES_256_GCM_SHA384",
                "protocol": "TLSv1.3",
                "strength": 256,
                "secure": true
            },
            ...
        ],
        "vulnerabilities": [
            {
                "id": "heartbleed",
                "severity": "critical",
                "description": "Vulnerable to Heartbleed (CVE-2014-0160)",
                "remediation": "Upgrade OpenSSL to version 1.0.1g or later",
                "cve": "CVE-2014-0160"
            }
        ]
    }
    """
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
