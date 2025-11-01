import socket
import concurrent.futures
import re
import sys
import traceback
import time
import datetime
from datetime import timezone
from typing import Dict, List, Union, Tuple, Optional
import ipaddress
import logging

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

def port_scan(target: str, port: int, timeout: float = 2.0) -> Dict:
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
    
    # Create a new socket for each attempt
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    
    try:
        # Try to connect to the port with a small delay to avoid overwhelming the target
        start_time = time.time()
        is_open = sock.connect_ex((target, port)) == 0
        connect_time = (time.time() - start_time) * 1000  # in milliseconds
        
        if is_open:
            result["is_open"] = True
            result["connect_time_ms"] = round(connect_time, 2)
            
            # If port is open, try to get more info
            try:
                # Set a separate timeout for banner grabbing
                sock.settimeout(1.5)
                banner = get_banner(target, port)
                service_info = get_service_info(port, banner)
                result["service"] = service_info
                
                # If we have a banner, check for known CVEs
                if banner and service_info.get("server"):
                    try:
                        cve_checker = CVEChecker()
                        cve_results = cve_checker.check_cves(service_info["server"])
                        if cve_results.get("cves_found"):
                            result["vulnerabilities"] = cve_results["cves_found"]
                    except Exception as cve_error:
                        result["cve_check_error"] = str(cve_error)
                        
            except Exception as banner_error:
                result["banner_error"] = str(banner_error)
        
        return result
        
    except socket.timeout:
        result["error"] = "Connection timed out"
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except OSError as e:
        if "timed out" in str(e):
            result["error"] = "Connection timed out"
        elif "No route to host" in str(e):
            result["error"] = "No route to host"
        else:
            result["error"] = f"OS error: {str(e)}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        return result
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            sock.close()
        except:
            pass
            pass

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
    return sorted(set(ports))  # Remove duplicates and sort

def scan_ports(target: str, ports: str = '21-23,80,443,8080,8443', max_workers: int = 100) -> Dict:
    """
    Perform a port scan on the target using Python's socket library.
    
    Args:
        target: IP address or domain to scan
        ports: Ports to scan (e.g., '21-100' or '80,443,8080')
        max_workers: Maximum number of concurrent scans
        
    Returns:
        Dict containing scan results
    """
    return _perform_scan(target, ports, max_workers)

def scan_ports_full(target: str, ports: str = '1-1024,3306,3389,5432,5900,6379,8000,8080,8443,27017', max_workers: int = 50) -> Dict:
    """
    Perform a full port scan with additional checks and slower, more thorough scanning.
    
    Args:
        target: IP address or domain to scan
        ports: Ports to scan (default includes common services)
        max_workers: Maximum number of concurrent scans (lower than quick scan)
        
    Returns:
        Dict containing detailed scan results
    """
    return _perform_scan(target, ports, max_workers, full_scan=True)

def _perform_scan(target: str, ports: str, max_workers: int, full_scan: bool = False) -> Dict:
    """
    Internal function to perform the actual port scanning with improved error handling and logging.
    """
    start_time = time.time()
    logger.info(f"Starting {full_scan and 'full' or 'quick'} scan for {target} on ports {ports}")
    
    # Initialize scan results
    scan_results = {
        'target': target,
        'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'end_time': None,
        'duration_seconds': None,
        'scan_type': 'full' if full_scan else 'quick',
        'open_ports': [],
        'total_ports_scanned': 0,
        'error': None,
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
        # Resolve target to IP
        try:
            target_ip = socket.gethostbyname(target)
            scan_results['scan_details']['target_resolution'] = target_ip
            scan_results['scan_details']['host_status'] = 'up'
            logger.info(f"Resolved {target} to {target_ip}")
        except socket.gaierror as e:
            error_msg = f'Could not resolve hostname: {target} - {str(e)}'
            logger.error(error_msg)
            scan_results['error'] = error_msg
            scan_results['scan_details']['host_status'] = 'down'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = time.time() - start_time
            return scan_results
        
        # Parse port ranges
        port_list = parse_ports(ports)
        scan_results['scan_stats']['total_ports'] = len(port_list)
        logger.info(f"Scanning {len(port_list)} ports with {max_workers} workers")
        
        if not port_list:
            scan_results['error'] = 'No valid ports to scan'
            scan_results['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            scan_results['duration_seconds'] = time.time() - start_time
            return scan_results
        
        # Scan ports concurrently
        open_ports = []
        errors = []
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(port_scan, target_ip, port, 5.0 if full_scan else 3.0): port 
                    for port in port_list
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        port_result = future.result()
                        
                        if port_result.get("is_open"):
                            scan_results['scan_stats']['open_ports'] += 1
                            service_info = port_result.get("service", {"name": "unknown"})
                            port_info = {
                                'port': port_result["port"],
                                'state': 'open',
                                'service': service_info.get("name", "unknown"),
                                'protocol': service_info.get("protocol", "tcp"),
                                'details': service_info
                            }
                            
                            # Add additional info if available
                            if 'connect_time_ms' in port_result:
                                port_info['connect_time_ms'] = port_result['connect_time_ms']
                            if full_scan and service_info.get("banner"):
                                port_info['banner'] = service_info["banner"]
                            if 'vulnerabilities' in port_result:
                                port_info['vulnerabilities'] = port_result['vulnerabilities']
                                
                            open_ports.append(port_info)
                            print(f"Found open port: {port} ({service_info.get('name', 'unknown')})")
                        else:
                            scan_results['scan_stats']['closed_ports'] += 1
                            
                    except Exception as e:
                        scan_results['scan_stats']['error_ports'] += 1
                        error_msg = f"Error scanning port {port}: {str(e)}"
                        errors.append(error_msg)
                        print(error_msg, file=sys.stderr)
                        
        except Exception as e:
            error_msg = f"Error during concurrent execution: {str(e)}"
            print(error_msg, file=sys.stderr)
            errors.append(error_msg)
        
        # Calculate scan statistics
        scan_duration = time.time() - start_time
        scan_results['scan_stats']['scan_duration_seconds'] = round(scan_duration, 2)
        if scan_duration > 0:
            scan_results['scan_stats']['ports_per_second'] = round(len(port_list) / scan_duration, 2)
        
        # Sort open ports by port number
        open_ports.sort(key=lambda x: x['port'])
        
        # Prepare result - match frontend expected format
        result = {
            'status': 'completed',
            'target': target,
            'ip_address': target_ip,
            'scan_type': 'tcp_connect_scan',
            'open_ports': [{
                'port': port_info['port'],
                'service': port_info.get('service', 'unknown'),
                'protocol': port_info.get('protocol', 'tcp'),
                'details': {
                    'banner': port_info.get('banner', ''),
                    'service': port_info.get('service_info', {})
                }
            } for port_info in open_ports],
            'scan_stats': {
                'total_ports_scanned': len(port_list),
                'open_ports_count': len(open_ports),
                'closed_ports_count': scan_results['scan_stats']['closed_ports'],
                'scan_type': 'quick' if not full_scan else 'full',
                'scan_duration_seconds': scan_results['scan_stats']['scan_duration_seconds']
            },
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        
        if errors and len(port_list) > 10:  # Only include errors if we scanned many ports
            result['error_count'] = len(errors)
            if len(errors) > 5:
                result['errors_sample'] = errors[:5]  # Include sample of errors
        
        print(f"Scan completed in {scan_results['scan_stats']['scan_duration_seconds']} seconds")
        print(f"Found {len(open_ports)} open ports out of {len(port_list)}")
        
        return result
        
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = f'Scan failed: {str(e)}'
        print(error_msg, file=sys.stderr)
        if '--debug' in sys.argv:
            print(error_trace, file=sys.stderr)
            
        # Format error response to match frontend expectations
        error_response = {
            'status': 'error',
            'error': error_msg,
            'target': target,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'scan_stats': {
                'scan_duration_seconds': round(time.time() - start_time, 2),
                'total_ports_scanned': 0,
                'open_ports_count': 0,
                'closed_ports_count': 0,
                'scan_type': 'quick' if not full_scan else 'full'
            },
            'open_ports': []
        }
        
        if '--debug' in sys.argv:
            error_response['details'] = error_trace
            
        return error_response
