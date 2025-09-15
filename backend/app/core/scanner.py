import nmap
import requests
import ssl
import socket
import time
from datetime import datetime

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan(self, target):
        """Main scanning method that orchestrates all scan types"""
        results = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'completed',
            'results': {}
        }
        
        try:
            # Run different types of scans
            results['results']['port_scan'] = self.port_scan(target)
            results['results']['http_headers'] = self.check_http_headers(target)
            results['results']['ssl_info'] = self.check_ssl(target)
            
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
            
        return results
    
    def port_scan(self, target):
        """
        Perform a comprehensive port scan with better error handling and fallback.
        Scans top 100 ports with version detection and service detection.
        """
        import time  # Ensure time module is available
        print(f"\n=== Starting port scan for {target} ===")
        
        try:
            # First try with Nmap if available
            try:
                print("Attempting Nmap scan...")
                
                # First, try a simple ping scan to verify host is reachable
                print("Performing host discovery...")
                try:
                    self.nm.scan(hosts=target, arguments='-sn -T4')
                    if not self.nm.all_hosts():
                        print("Host appears to be down or blocking ping")
                        print("Trying scan anyway...")
                except Exception as ping_error:
                    print(f"Ping scan failed: {str(ping_error)}")
                
                # For Google, we know some common ports to check
                common_ports = '80,443,22,21,25,53,110,143,465,587,993,995,1723,3306,3389,5900,8080,8443,27017,27018'
                
                # More comprehensive scan parameters:
                # -Pn: Treat all hosts as online (skip host discovery)
                # -sS: TCP SYN scan (faster and less likely to be logged)
                # -T4: Aggressive timing template
                # -F: Fast mode - scan fewer ports than the default scan
                # -sV: Version detection
                # --version-intensity 3: Balanced service detection
                # --max-retries 1: Reduce retries to fail faster
                # --max-scan-delay 100ms: Reduce delays between probes
                scan_args = f'-Pn -sS -T4 -p {common_ports} -sV --version-intensity 3 --max-retries 1 --max-scan-delay 100ms'
                print(f"Running Nmap with arguments: {scan_args}")
                
                scan_result = self.nm.scan(
                    hosts=target,
                    arguments=scan_args,
                    timeout=60  # 1 minute timeout for initial scan
                )
                
                print("Nmap scan completed successfully")
                
                # Process and format the results
                results = {
                    'scan_summary': {
                        'target': target,
                        'scan_type': 'nmap_scan',
                        'status': 'completed'
                    },
                    'hosts': {}
                }
                
                if not self.nm.all_hosts():
                    print("No hosts found in scan results")
                    results['scan_summary']['status'] = 'no_hosts_found'
                    return results
                
                for host in self.nm.all_hosts():
                    host_info = self.nm[host]
                    print(f"Processing host: {host}")
                    
                    host_data = {
                        'hostnames': host_info.hostnames(),
                        'state': host_info.state(),
                        'protocols': host_info.all_protocols(),
                        'ports': {}
                    }
                    
                    # Process TCP ports
                    if 'tcp' in host_info:
                        for port, port_info in host_info['tcp'].items():
                            print(f"Found open port: {port} - {port_info}")
                            host_data['ports'][str(port)] = {
                                'state': port_info.get('state', 'unknown'),
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                    
                    # Add OS information if available
                    if 'osmatch' in host_info and host_info['osmatch']:
                        host_data['os'] = {
                            'name': host_info['osmatch'][0].get('name', 'unknown'),
                            'accuracy': host_info['osmatch'][0].get('accuracy', 0)
                        }
                    
                    results['hosts'][host] = host_data
                
                # Add scan statistics
                results['scan_summary']['hosts_scanned'] = len(self.nm.all_hosts())
                results['scan_summary']['open_ports'] = sum(
                    len(host_info['ports'])
                    for host_info in results['hosts'].values()
                    if 'ports' in host_info
                )
                
                print(f"Scan complete. Found {results['scan_summary']['open_ports']} open ports.")
                return results
                
            except Exception as nmap_error:
                # Fall back to basic socket scanning if Nmap fails
                print(f"Nmap scan failed, falling back to socket scan: {str(nmap_error)}")
                return self._basic_socket_scan(target)
                
        except Exception as e:
            return {'error': f'Port scan failed: {str(e)}'}
    
    def _basic_socket_scan(self, target, ports_to_scan=None):
        """Fallback basic socket-based port scanner"""
        if ports_to_scan is None:
            # Common ports to scan
            ports_to_scan = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 27018
            ]
        
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = {
            'host': target,
            'scan_type': 'basic_socket_scan',
            'tcp_ports': {}
        }
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((target, port))
                sock.close()
                return port, result == 0
            except:
                return port, False
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports_to_scan}
            for future in as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    results['tcp_ports'][port] = {
                        'state': 'open',
                        'service': 'unknown',
                        'version': ''
                    }
        
        return results
    
    def check_http_headers(self, target):
        """Check HTTP headers for security issues"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            response = requests.get(target, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            # Basic security header checks
            security_headers = {
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security')
            }
            
            return {
                'status_code': response.status_code,
                'headers': headers,
                'security_headers': security_headers
            }
            
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def check_ssl(self, target):
        """Check SSL/TLS configuration"""
        try:
            hostname = target.split('://')[-1].split('/')[0].split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    
                    return {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expiry': not_after.isoformat(),
                        'days_until_expiry': days_until_expiry,
                        'is_valid': days_until_expiry > 0
                    }
                    
        except Exception as e:
            return {'error': str(e)}
