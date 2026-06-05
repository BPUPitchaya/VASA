import socket
import concurrent.futures
import re
import sys
import traceback
import time
import datetime
from datetime import timezone
from typing import Dict, List, Union, Tuple, Optional, Callable
import ipaddress
import logging
import threading

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from .cve_checker import CVEChecker

# Common service ports and their typical services
COMMON_SERVICES = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    115: 'sftp',
    135: 'msrpc',
    139: 'netbios-ssn',
    143: 'imap',
    194: 'irc',
    389: 'ldap',
    443: 'https',
    445: 'microsoft-ds',
    1433: 'ms-sql-s',
    1521: 'oracle',
    1723: 'pptp',
    2049: 'nfs',
    2082: 'cpanel',
    2083: 'cpanel-ssl',
    2086: 'cpanel-whm',
    2087: 'cpanel-whm-ssl',
    2095: 'cpanel-webmail',
    2096: 'cpanel-webmail-ssl',
    3306: 'mysql',
    3389: 'ms-wbt-server',
    5432: 'postgresql',
    5900: 'vnc',
    8080: 'http-proxy',
    8443: 'https-alt',
    8888: 'sun-answerbook',
    10000: 'snet-sensor-mgmt',
    27017: 'mongod',
    27018: 'mongod-shardsvr',
    27019: 'mongod-configsvr'
}

def get_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to get a banner from the specified port.
    
    Args:
        target: Target IP or hostname
        port: Port number to connect to
        timeout: Connection timeout in seconds
        
    Returns:
        Banner string if successful, empty string otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
        return ""

def get_service_info(port: int, banner: str = "") -> Dict[str, str]:
    """
    Get service information based on port number and banner.
    
    Args:
        port: Port number
        banner: Banner string (if available)
        
    Returns:
        Dictionary containing service information
    """
    service_info = {
        "name": COMMON_SERVICES.get(port, "unknown"),
        "port": port,
        "protocol": "tcp"
    }
    
    # Basic service detection based on banner
    if banner:
        banner_lower = banner.lower()
        if "apache" in banner_lower or "httpd" in banner_lower:
            service_info["server"] = "apache"
            service_info["type"] = "web"
        elif "nginx" in banner_lower:
            service_info["server"] = "nginx"
            service_info["type"] = "web"
        elif "iis" in banner_lower or "microsoft" in banner_lower:
            service_info["server"] = "iis"
            service_info["type"] = "web"
        elif "ssh" in banner_lower:
            service_info["server"] = "openssh"
            service_info["type"] = "remote-access"
        elif "ftp" in banner_lower:
            service_info["server"] = "ftp"
            service_info["type"] = "file-transfer"
    
    return service_info

def is_valid_ip(ip: str) -> bool:
    """Check if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    """Basic domain validation."""
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.herror):
        return False

def port_scan(target: str,
              port: int,
              connect_timeout: float = 1.0,         # was 2–3s+
              grab_banner: bool = False,             # new: off in quick mode
              banner_timeout: float = 0.30) -> Dict:
    """
    Scan a single port on the target and gather service information.
    
    Args:
        target: IP address or domain to scan
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Dict containing port scan results
    """
    result = {
        "port": port,
        "is_open": False,
        "service": {"name": "unknown", "protocol": "tcp"},
        "error": None
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(connect_timeout)
    try:
        start_time = time.time()
        is_open = sock.connect_ex((target, port)) == 0
        connect_time = (time.time() - start_time) * 1000

        if is_open:
            result["is_open"] = True
            result["connect_time_ms"] = round(connect_time, 2)

            # only try to read a banner if explicitly asked
            if grab_banner:
                try:
                    sock.settimeout(banner_timeout)
                    banner = get_banner(target, port, timeout=banner_timeout)
                    service_info = get_service_info(port, banner)
                    result["service"] = service_info
                except Exception as banner_error:
                    result["banner_error"] = str(banner_error)
        return result
    except socket.timeout:
        result["error"] = "Connection timed out"; return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused";   return result
    except OSError as e:
        result["error"] = f"OS error: {e}";       return result
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"; return result
    finally:
        try: sock.shutdown(socket.SHUT_RDWR)
        except: pass
        try: sock.close()
        except: pass

def parse_ports(ports_str: str) -> List[int]:
    """Parse port string into a list of port numbers."""
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))  

def scan_ports(target: str,
                ports: str = '21-23,80,443,8080,8443',
                max_workers: Optional[int] = None,
                progress_cb: Optional[Callable[[int,int,Optional[int],Optional[str]], None]] = None,
                cancel_token:Optional[object] = None,
                pause_token: Optional[object] = None) -> Dict:
    """
    Quick scan wrapper. Uses short timeouts and no banner grabbing.
    """
    if not max_workers or max_workers < 1:
        # this will be recomputed inside _perform_scan too, but keeping a sane default here helps tests
        max_workers = 256
    return _perform_scan(target=target,ports=ports,max_workers=max_workers,full_scan=False,progress_cb=progress_cb,cancel_token = cancel_token, pause_token = pause_token)


def scan_ports_full(target: str,
                    ports: str = '1-1024,3306,3389,5432,5900,6379,8000,8080,8443,27017',
                    max_workers: Optional[int] = None,
                    progress_cb: Optional[Callable[[int,int,Optional[int], Optional[str]], None]] = None,
                    cancel_token : Optional[object] = None,
                    pause_token: Optional[object] = None) -> Dict:
    """
    Full scan entry point. Accepts timeout and max_worker for compatibility.
    """
    if not max_workers or max_workers < 1:
        max_workers = 128
    return _perform_scan(target=target,ports=ports,max_workers=max_workers,full_scan=True,progress_cb=progress_cb,cancel_token = cancel_token, pause_token = pause_token)

def _perform_scan(
    target: str,
    ports: str,
    max_workers: int,
    full_scan: bool = False,
    progress_cb=None,
    cancel_token: Optional[object] = None,
    pause_token: Optional[object] = None,
) -> Dict:
    """
    Internal scanner that performs concurrent TCP connect checks.

    - full_scan: enables slightly longer timeouts and banner grabbing
    - progress_cb(scanned, total, port, status): optional callback
    - cancel_token: threading.Event or asyncio.Event; if set, abort promptly
    - pause_token : threading.Event or asyncio.Event; when not set, pause safely
    """
    def _is_set(tok) -> bool:
        if tok is None:
            return False
        fn = getattr(tok, "is_set", None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                return False
        # fallback for odd tokens (truthy => set)
        return bool(tok)

    def _pause_point():
        """
        If pause_token is provided and *not* set, block in short sleeps until
        it becomes set again or cancellation is requested.
        Works with both threading.Event and asyncio.Event (via is_set()).
        """
        if pause_token is None:
            return
        # default policy: running when set; paused when not set
        if not _is_set(pause_token):
            logger.info("Scan paused")
            while not _is_set(pause_token):
                if _is_set(cancel_token):
                    break
                time.sleep(0.5)  # cooperative short sleep to release GIL
            logger.info("Scan resumed")

    start_wall = time.time()
    logger.info("Starting %s scan for %s (ports=%s)",
                "full" if full_scan else "quick", target, ports)

    scan_results = {
        'target': target,
        'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'end_time': None,
        'duration_seconds': None,
        'scan_type': 'full' if full_scan else 'quick',
        'open_ports': [],
        'total_ports_scanned': 0,
        'error': None,
        'status': 'running',
        'scan_details': {
            'target_resolution': None,
            'host_status': 'unknown',
            'scan_arguments': {
                'ports': ports,
                'max_workers': max_workers,
                'full_scan': full_scan
            }
        },
        'scan_stats': {
            'total_ports': 0,
            'open_ports': 0,
            'filtered_ports': 0,
            'closed_ports': 0,
            'error_ports': 0,
            'total_ports_scanned': 0,
            'scan_duration_seconds': 0
        }
    }

    try:
        # ---- early cancel / pause gate ----
        if _is_set(cancel_token):
            scan_results['status'] = 'stopped'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
            return scan_results
        _pause_point()

        # ---- resolve host ----
        try:
            target_ip = socket.gethostbyname(target)
            scan_results['scan_details']['target_resolution'] = target_ip
            scan_results['scan_details']['host_status'] = 'up'
            logger.info("Resolved %s -> %s", target, target_ip)
        except socket.gaierror as e:
            msg = f"Could not resolve hostname {target}: {e}"
            logger.error(msg)
            scan_results['error'] = msg
            scan_results['status'] = 'failed'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
            return scan_results

        # ---- parse ports ----
        port_list = parse_ports(ports)
        total = len(port_list)
        scan_results['scan_stats']['total_ports'] = total
        if total == 0:
            scan_results['error'] = "No valid ports to scan"
            scan_results['status'] = 'failed'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
            return scan_results

        # ---- adaptive concurrency & mode timeouts ----
        if not max_workers or max_workers < 1:
            max_workers = min(512, max(128, total // 2))  # higher baseline for speed

        connect_timeout = 2.0 if full_scan else 0.6
        banner_timeout  = 1.0 if full_scan else 0.15
        grab_banner     = bool(full_scan)

        open_ports: List[Dict] = []
        errors: List[str] = []

        if progress_cb:
            try:
                progress_cb(0, total, None, None)
            except Exception:
                pass

        if _is_set(cancel_token):
            scan_results['status'] = 'stopped'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
            return scan_results
        _pause_point()

        # ---- concurrent scanning ----
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exe:
            # Submit in small batches so Pause/Cancel reacts quickly
            # (prevents filling the queue with thousands of tasks)
            BATCH = max(64, max_workers * 2)
            submitted = {}
            idx = 0

            def _submit_batch(start_i: int):
                nonlocal submitted
                end_i = min(start_i + BATCH, total)
                for p in port_list[start_i:end_i]:
                    fut = exe.submit(port_scan, target_ip, p, connect_timeout, grab_banner, banner_timeout)
                    submitted[fut] = p
                return end_i

            next_i = _submit_batch(0)

            while submitted:
                if _is_set(cancel_token):
                    # cancel whatever is not started yet (Python 3.9+ may not cancel running ones)
                    for f in list(submitted.keys()):
                        f.cancel()
                    try:
                        exe.shutdown(wait=False, cancel_futures=True)
                    except Exception:
                        pass
                    scan_results['status'] = 'stopped'
                    scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
                    return scan_results

                _pause_point()

                # Wait for the next completed future with a short timeout to
                # re-check pause/cancel frequently
                done, _pending = concurrent.futures.wait(
                    submitted.keys(), timeout=0.15, return_when=concurrent.futures.FIRST_COMPLETED
                )
                if not done:
                    # no completion yet; loop to re-check pause/cancel
                    continue

                for fut in list(done):
                    p = submitted.pop(fut, None)
                    r = None
                    try:
                        r = fut.result()
                        if r.get("is_open"):
                            logger.info("[port-scan] %d/%d port %s -> open", idx + 1, total, p)
                            scan_results['scan_stats']['open_ports'] += 1
                            svc = r.get("service", {})
                            open_ports.append({
                                'port': r["port"],
                                'state': 'open',
                                'service': svc.get('name', 'unknown'),
                                'protocol': svc.get('protocol', 'tcp'),
                                'details': svc
                            })
                        else:
                            logger.info("[port-scan] %d/%d port %s -> closed", idx + 1, total, p)
                            scan_results['scan_stats']['closed_ports'] += 1
                    except Exception as e:
                        scan_results['scan_stats']['error_ports'] += 1
                        err_msg = f"Error scanning port {p}: {e}"
                        errors.append(err_msg)
                        logger.warning(err_msg)
                    finally:
                        idx += 1
                        scan_results['total_ports_scanned'] = idx
                        scan_results['scan_stats']['total_ports_scanned'] = idx
                        if progress_cb:
                            try:
                                st = 'open' if (r and r.get('is_open')) else ('error' if (r and r.get('error')) else 'closed')
                                progress_cb(idx, total, p, st)
                            except Exception:
                                pass

                # Top up queue if we have more ports remaining
                if next_i < total and len(submitted) < max_workers:
                    _pause_point()
                    if _is_set(cancel_token):
                        continue
                    next_i = _submit_batch(next_i)

        # ---- finalize ----
        open_ports.sort(key=lambda x: x['port'])
        scan_results['open_ports'] = open_ports
        elapsed = round(time.time() - start_wall, 2)
        scan_results['scan_stats']['scan_duration_seconds'] = elapsed
        scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scan_results['duration_seconds'] = elapsed
        scan_results['status'] = 'completed'

        logger.info("Completed %s scan in %.2fs. Open=%d / %d",
                    scan_results['scan_type'], elapsed,
                    scan_results['scan_stats']['open_ports'], total)
        return scan_results

    except Exception as e:
        logger.exception("Scan failed")
        scan_results['status'] = 'failed'
        scan_results['error'] = f"Scan failed: {e}"
        scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scan_results['duration_seconds'] = round(time.time() - start_wall, 2)
        return scan_results