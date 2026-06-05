from flask import Blueprint, request, jsonify
from ..scanners.port_scanner import scan_ports
from ..scanners.http_scanner import HttpScanner
from ..scanners.cve_checker import CVEChecker

import json

import time
import threading
from uuid import uuid4
from typing import Dict
from . import bp

#bp = Blueprint('api', __name__, url_prefix='/api')

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
    
# New Async full scan endpoints
"""
_SCANS = {}

def _new_id():
    return uuid4().hex[:10]

def _maybe_wait(scan):
    while scan["ctrl"]["pause"]:
        time.sleep(0.2)

    if scan["ctrl"]["stop"]:
        raise RuntimeError("stopped")

def _grade_severity(port_results, http_results, cve_results):
    sev = "Low"
    high_ports = {22, 23, 445, 3389}
    open_ports = {s["port"] for s in port_results.get("services", [])} if port_results else set()

    if any (p in open_ports for p in high_ports):
        sev = "Medium"  
    if http_results and http_results.get("security") and http_results["security"].get("bad_headers"):
        sev = "High"
    if cve_results and any(cve_results.get(p) for p in cve_results):
        sev = "High"
    return sev

def _run_full_scan_async(scan_id, target, ports):
    scan = _SCANS[scan_id]
    try:
        scan["state"] = "running"; scan["progress"] = 5
        _maybe_wait(scan)

        #Phase 1 : port scna
        port_results = scan_ports(target, ports)
        scan["progress"] = 35
        _maybe_wait(scan)

        #Phase 2 : Http scan
        http_results = None
        http_ports = {80,443,8080,8081,8443}
        open_ports = {s["port"] for s in port_results.get("services", [])}
        if open_ports & http_ports:
            http_results = HttpScanner(target).scan()
        scan["progress"] = 65
        _maybe_wait(scan)

        #Phase 3: CVE Scan
        cve_results = {}
        services = port_results.get("services", [])
        total = max(1, sum(1 for s in services if s.get("banner")))
        done = 0
        for s in services:
            _maybe_wait(scan)
            if s.get("banner"):
                cve_results[s["port"]] = CVEChecker.check_banner(s["banner"])
                done += 1
                scan["progress"] = 65 + int(25 * done/total)

        #Finalize
        severity = _grade_severity(port_results, http_results, cve_results)
        scan["result"] = {
            "status" : "completed",
            "target" : target,
            "port_scan" : port_results,
            "http_scan" : http_results,
            "cve_scan" : cve_results or None
        }
        scan["severity"] = severity
        scan["progress"] = 100
        scan["state"] = "completed"

    except RuntimeError as e:
        if str(e) == "stopped":
            scan["state"] = "stopped"
        else:
            scan["state"] = "failed"; scan["err"] = str(e)
    
    except Exception as e:
        scan["state"] = "failed"
        scan["err"] = str(e)

@bp.post('/scan/start')
def api_start_scan():
    data = request.get_json() or {}
    target = (data.get('target') or '').strip()
    ports  = data.get('ports', '21-23,80,443,8080,8443')
    if not target:
        return jsonify({'error': 'target required'}), 400

    sid = _new_id()
    _SCANS[sid] = {
        "state": "running",
        "progress": 0,
        "severity": "Low",
        "target": target,
        "ports": ports,
        "result": None,
        "err": None,
        "ctrl": {"pause": False, "stop": False},
    }
    threading.Thread(target=_run_full_scan_async, args=(sid, target, ports), daemon=True).start()
    return jsonify({"scan_id": sid}), 201

@bp.get('/scan/<scan_id>/status')
def api_status(scan_id):
    s = _SCANS.get(scan_id)
    if not s:
        return jsonify({'error': 'unknown scan_id'}), 404
    return jsonify({
        "state": s["state"],
        "progress": s["progress"],
        "severity": s["severity"],
        "error": s.get("err"),
    })

@bp.post('/scan/<scan_id>/pause')
def api_pause(scan_id):
    s = _SCANS.get(scan_id)
    if not s: return jsonify({'error': 'unknown scan_id'}), 404
    if s["state"] != "running":
        return jsonify({"ok": False, "reason": f"cannot pause from {s['state']}"}), 409
    s["ctrl"]["pause"] = True
    s["state"] = "paused"
    return jsonify({"ok": True})

@bp.post('/scan/<scan_id>/resume')
def api_resume(scan_id):
    s = _SCANS.get(scan_id)
    if not s: return jsonify({'error': 'unknown scan_id'}), 404
    if s["state"] != "paused":
        return jsonify({"ok": False, "reason": f"not paused (state {s['state']})"}), 409
    s["ctrl"]["pause"] = False
    s["state"] = "running"
    return jsonify({"ok": True})

@bp.post('/scan/<scan_id>/stop')
def api_stop(scan_id):
    s = _SCANS.get(scan_id)
    if not s: return jsonify({'error': 'unknown scan_id'}), 404
    s["ctrl"]["stop"] = True
    return jsonify({"ok": True})

@bp.get('/scan/<scan_id>/results')
def api_results(scan_id):
    s = _SCANS.get(scan_id)
    if not s: return jsonify({'error': 'unknown scan_id'}), 404
    if s["state"] not in ("completed", "failed", "stopped"):
        return jsonify({'error': 'scan not finished'}), 409
    if s["state"] == "failed":
        return jsonify({'error': s.get('err') or 'scan failed'}), 500
    return jsonify(s["result"] or {"issues": []})

"""