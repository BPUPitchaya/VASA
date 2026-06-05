from flask import Blueprint, request, jsonify, make_response, send_file
import socket
import uuid
import time
import logging
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import bp, scans, scan_lock
from ..scanners.headers_scanner import HeadersScanner
from ..scanners.ssl_scanner import run_ssl_scan
from ..scanners.cve_checker import run_cve_check
from ..utils.report_generator import generate_scan_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread pools
scan_executor = ThreadPoolExecutor(max_workers=5)
SCAN_CONTROL = {}  # pause/stop flags


# ---------------------------------------------------------
# PORT SCANNING UTILITIES
# ---------------------------------------------------------

def scan_port(target, port, timeout=2):
    """Scan a single TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))

            if result == 0:
                return {
                    "port": port,
                    "status": "open",
                    "service": get_service_name(port),
                    "banner": None,
                }
            return None

    except Exception:
        return None


def get_service_name(port):
    """Guess service name from port number."""
    names = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        5432: "postgres",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
    }
    return names.get(port, "unknown")


def _check_control(scan_id):
    """Pause/stop support for a running scan."""
    ctrl = SCAN_CONTROL.get(scan_id)
    if not ctrl:
        return

    while ctrl.get("pause"):
        time.sleep(0.2)
        if ctrl.get("stop"):
            raise RuntimeError("stopped")

    if ctrl.get("stop"):
        raise RuntimeError("stopped")


# ---------------------------------------------------------
# MAIN SCAN PIPELINE
# ---------------------------------------------------------

def run_scan(scan_id, target, ports, scan_type, modules):
    """
    Worker that performs:
      - port scan (always)
      - optional http_headers, ssl_scan, cve_check modules
    Results are written into scans[scan_id].
    """
    try:
        logger.info(
            f"scan {scan_id}: starting {scan_type} scan on {len(ports)} ports "
            f"with modules={modules}"
        )

        open_ports = []
        total = len(ports)

        # --------------------------
        # PORT SCANNING (0–50%)
        # --------------------------
        max_workers = 150 if scan_type == "full" else 50
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            jobs = {executor.submit(scan_port, target, p): p for p in ports}

            for i, future in enumerate(as_completed(jobs)):
                _check_control(scan_id)
                port = jobs[future]

                result = future.result()
                if result:
                    open_ports.append(result)

                progress = int(((i + 1) / total) * 50)  # 0–50%

                with scan_lock:
                    scan = scans.get(scan_id)
                    if not scan:
                        return
                    scan["open_ports"] = open_ports
                    scan["open_ports_count"] = len(open_ports)
                    scan["scanned_ports"] = i + 1
                    scan["progress"] = progress
                    scan["results"]["modules"]["port_scan"]["open_ports"] = open_ports

        # --------------------------
        # HTTP HEADERS MODULE (50–70%)
        # --------------------------
        if "http_headers" in modules:
            _check_control(scan_id)
            logger.info(f"scan {scan_id}: running http_headers module")

            try:
                scanner = HeadersScanner(timeout=10)
                http_res = scanner.scan(target)  # adds https:// if missing

                with scan_lock:
                    scan = scans.get(scan_id)
                    if scan:
                        scan["results"]["modules"]["http_headers"] = {
                            "results": http_res.to_dict()
                        }
                        # bump progress a bit
                        scan["progress"] = max(scan.get("progress", 50), 70)
            except Exception as e:
                logger.warning(f"scan {scan_id}: http_headers failed: {e}")
                with scan_lock:
                    scan = scans.get(scan_id)
                    if scan:
                        scan["results"]["modules"]["http_headers"] = {
                            "error": str(e),
                            "results": None,
                        }

        # --------------------------
        # SSL MODULE (70–85%)
        # --------------------------
        if "ssl_scan" in modules:
            _check_control(scan_id)
            logger.info(f"scan {scan_id}: running ssl_scan module")

            # adjust args to your run_ssl_scan signature if different
            ssl_res = run_ssl_scan(target, open_ports)

            with scan_lock:
                scan = scans.get(scan_id)
                if scan:
                    scan["results"]["modules"]["ssl_scan"] = {
                        "results": ssl_res
                    }
                    scan["progress"] = max(scan.get("progress", 70), 85)

        # --------------------------
        # CVE MODULE (85–95%)
        # --------------------------
        if "cve_check" in modules:
            _check_control(scan_id)
            logger.info(f"scan {scan_id}: running cve_check module")

            # adjust args to your run_cve_check signature if different
            cve_res = run_cve_check(open_ports)

            with scan_lock:
                scan = scans.get(scan_id)
                if scan:
                    scan["results"]["modules"]["cve_check"] = {
                        "cves_found": cve_res
                    }
                    scan["progress"] = max(scan.get("progress", 85), 95)

        # --------------------------
        # FINISH
        # --------------------------
        with scan_lock:
            scan = scans.get(scan_id)
            if scan:
                scan["status"] = "completed"
                scan["progress"] = 100
                scan["end_time"] = time.time()

        logger.info(f"scan {scan_id}: completed successfully")

    except RuntimeError as e:
        if str(e) == "stopped":
            logger.info(f"scan {scan_id}: stopped by user")
            with scan_lock:
                scan = scans.get(scan_id)
                if scan:
                    scan["status"] = "stopped"
                    scan["end_time"] = time.time()
        else:
            raise

    except Exception as e:
        logger.error(f"scan {scan_id} failed: {e}", exc_info=True)
        with scan_lock:
            scan = scans.get(scan_id)
            if scan:
                scan["status"] = "failed"
                scan["error"] = str(e)
                scan["end_time"] = time.time()

    finally:
        SCAN_CONTROL.pop(scan_id, None)


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------

@bp.route("/scan", methods=["POST", "OPTIONS"])
def start_scan():
    if request.method == "OPTIONS":
        return _cors()

    data = request.get_json() or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "quick")
    modules = data.get("modules") or ["port_scan"]

    if not target:
        return jsonify({"status": "error", "message": "Target is required"}), 400

    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"status": "error", "message": "Could not resolve hostname"}), 400

    scan_id = str(uuid.uuid4())

    # quick = small list, full = long list
    common_ports = [
        80, 443, 8080, 8443,
        21, 22, 23, 25, 53, 110, 143,
        445, 993, 995, 3306, 5432, 6379, 27017,
    ]
    if scan_type == "full":
        ports = list(dict.fromkeys(common_ports + list(range(1, 1001))))
    else:
        ports = common_ports

    # create initial scan entry synchronously to avoid /status 404
    now = time.time()
    with scan_lock:
        scans[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "running",
            "progress": 0,
            "start_time": now,
            "end_time": None,
            "results": {
                "modules": {
                    "port_scan": {"open_ports": []}
                }
            },
            "open_ports": [],
            "open_ports_count": 0,
            "scanned_ports": 0,
            "total_ports": len(ports),
        }
        SCAN_CONTROL[scan_id] = {"pause": False, "stop": False}

    # kick off background worker
    scan_executor.submit(run_scan, scan_id, target, ports, scan_type, modules)

    return jsonify({
        "status": "started",
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "modules": modules,
        "ports_to_scan": len(ports),
    }), 202


@bp.route("/scan/status/<scan_id>")
def get_scan_status(scan_id):
    with scan_lock:
        scan = scans.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify(scan)


@bp.route("/scan/<scan_id>/pause", methods=["POST"])
def pause_scan(scan_id):
    ctrl = SCAN_CONTROL.get(scan_id)
    if not ctrl:
        return jsonify({"ok": False, "error": "invalid scan id"}), 404

    ctrl["pause"] = True
    with scan_lock:
        scan = scans.get(scan_id)
        if scan:
            scan["status"] = "paused"
    return jsonify({"ok": True})


@bp.route("/scan/<scan_id>/resume", methods=["POST"])
def resume_scan(scan_id):
    ctrl = SCAN_CONTROL.get(scan_id)
    if not ctrl:
        return jsonify({"ok": False, "error": "invalid scan id"}), 404

    ctrl["pause"] = False
    with scan_lock:
        scan = scans.get(scan_id)
        if scan:
            scan["status"] = "running"
    return jsonify({"ok": True})


@bp.route("/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    ctrl = SCAN_CONTROL.get(scan_id)
    if not ctrl:
        return jsonify({"ok": False, "error": "invalid scan id"}), 404

    ctrl["stop"] = True
    with scan_lock:
        scan = scans.get(scan_id)
        if scan:
            scan["status"] = "stopping"
    return jsonify({"ok": True})


def _cors():
    resp = make_response()
    resp.headers.add("Access-Control-Allow-Origin", "*")
    resp.headers.add("Access-Control-Allow-Headers", "Content-Type")
    resp.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
    return resp

@bp.route("/scan/<scan_id>/pdf", methods=["GET"])
def download_scan_pdf(scan_id):
    """Return a generated PDF report for this scan."""
    with scan_lock:
        scan = scans.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Generate PDF from the in-memory scan dict
    pdf_buf = generate_scan_report(scan)

    # Flask can stream BytesIO directly
    return send_file(
        pdf_buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vasa-scan-{scan_id}.pdf",
    )