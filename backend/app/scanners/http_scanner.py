import requests
import ssl
import socket
import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

class HttpScanner:
    def __init__(self, target: str):
        self.target = target if target.startswith(('http://', 'https://')) else f'https://{target}'
        self.results = {
            'url': self.target,
            'status': 'pending',
            'findings': []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SimpleVulnerabilityScanner/1.0'
        })

    def check_ssl_certificate(self) -> Dict:
        """Check SSL certificate validity and configuration"""
        parsed = urlparse(self.target)
        if parsed.scheme != 'https':
            return {'status': 'skipped', 'message': 'Not an HTTPS URL'}

        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    days_remaining = (not_after - datetime.datetime.utcnow()).days
                    
                    # Check for self-signed certificate
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    is_self_signed = issuer == subject
                    
                    return {
                        'status': 'completed',
                        'valid_until': not_after.isoformat(),
                        'days_remaining': days_remaining,
                        'is_self_signed': is_self_signed,
                        'issuer': issuer.get('organizationName', 'Unknown'),
                    }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def check_http_headers(self) -> Dict:
        """Check for missing or insecure HTTP headers"""
        required_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]
        
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            headers = dict(response.headers)
            
            missing_headers = [h for h in required_headers if h.lower() not in map(str.lower, headers.keys())]
            
            return {
                'status': 'completed',
                'missing_headers': missing_headers,
                'all_headers': headers
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan(self) -> Dict:
        """Run all HTTP-related scans"""
        try:
            # Check if target is reachable
            self.session.get(self.target, timeout=10, verify=False)
            
            # Run security checks
            ssl_results = self.check_ssl_certificate()
            headers_results = self.check_http_headers()
            
            # Compile results
            self.results.update({
                'status': 'completed',
                'ssl': ssl_results,
                'headers': headers_results
            })
            
            return self.results
            
        except Exception as e:
            self.results.update({
                'status': 'error',
                'message': str(e)
            })
            return self.results
