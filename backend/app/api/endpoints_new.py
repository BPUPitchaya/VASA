from flask import Blueprint, request, jsonify
from ..scanners.port_scanner import scan_ports
from ..scanners.http_scanner import HttpScanner
from ..scanners.cve_checker import CVEChecker
import json

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/scan/ports', methods=['POST'])
def port_scan():
    data = request.get_json() or {}
    target = data.get('target')
    ports = data.get('ports', '21-23,80,443,8080,8443')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        results = scan_ports(target, ports)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/scan/http', methods=['POST'])
def http_scan():
    data = request.get_json() or {}
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        scanner = HttpScanner(target)
        results = scanner.scan()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/scan/cve', methods=['POST'])
def cve_scan():
    data = request.get_json() or {}
    banner = data.get('banner')
    service = data.get('service')
    version = data.get('version')
    
    if not banner and not (service and version):
        return jsonify({
            'error': 'Either provide a banner or both service and version',
            'example_banner': {
                'banner': 'Apache/2.4.49 (Unix)'
            },
            'example_service': {
                'service': 'apache',
                'version': '2.4.49'
            }
        }), 400
    
    try:
        if banner:
            results = CVEChecker.check_banner(banner)
            service = service or CVEChecker.get_software_name(banner) if banner else 'unknown'
            version = version or CVEChecker.extract_version(banner) if banner else 'unknown'
        else:
            results = CVEChecker.check_cve(service.lower(), version)
            
        return jsonify({
            'service': service,
            'version': version,
            'vulnerabilities_found': len(results) > 0,
            'vulnerabilities': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/scan/full', methods=['POST'])
def full_scan():
    data = request.get_json() or {}
    target = data.get('target')
    ports = data.get('ports', '21-23,80,443,8080,8443')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        # Run port scan
        port_results = scan_ports(target, ports)
        
        # Run HTTP scan if HTTP/HTTPS ports are open
        http_results = None
        http_ports = [80, 443, 8080, 8081, 8443]
        if any(port in [s['port'] for s in port_results.get('services', [])] for port in http_ports):
            scanner = HttpScanner(target)
            http_results = scanner.scan()
        
        # Run CVE scan on detected services
        cve_results = {}
        for service in port_results.get('services', []):
            if 'banner' in service and service['banner']:
                cve_results[service['port']] = CVEChecker.check_banner(service['banner'])
        
        # Combine results
        results = {
            'status': 'completed',
            'target': target,
            'scan_start': port_results.get('scan_start'),
            'scan_end': port_results.get('scan_end'),
            'port_scan': port_results,
            'http_scan': http_results,
            'cve_scan': cve_results if cve_results else None
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
