import requests
import ssl
import socket
import datetime
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

class HttpScanner:
    def __init__(self, target: str):
        self.target = target if target.startswith(('http://', 'https://')) else f'https://{target}'
        self.results = {
            'url': self.target,
            'status': 'pending',
            'findings': [],
            'head_scan': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SimpleVulnerabilityScanner/1.0'
        })
        self.session.max_redirects = 5  # Prevent infinite redirects

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

    def perform_head_scan(self) -> Dict[str, Any]:
        """
        Perform an HTTP HEAD request to gather server information and headers
        without downloading the entire content.
        
        Returns:
            Dict containing server information and security headers
        """
        try:
            response = self.session.head(
                self.target,
                allow_redirects=True,
                timeout=10,
                verify=False  # We want to analyze even if SSL is invalid
            )
            
            # Get security-related headers
            security_headers = {
                'server': response.headers.get('server', ''),
                'x-powered-by': response.headers.get('x-powered-by', ''),
                'x-frame-options': response.headers.get('x-frame-options', 'Not set'),
                'x-content-type-options': response.headers.get('x-content-type-options', 'Not set'),
                'content-security-policy': response.headers.get('content-security-policy', 'Not set'),
                'strict-transport-security': response.headers.get('strict-transport-security', 'Not set'),
                'x-xss-protection': response.headers.get('x-xss-protection', 'Not set'),
                'referrer-policy': response.headers.get('referrer-policy', 'Not set'),
                'permissions-policy': response.headers.get('permissions-policy', 'Not set')
            }
            
            # Check for missing security headers
            missing_headers = []
            for header in ['x-frame-options', 'x-content-type-options', 'content-security-policy']:
                if security_headers[header] == 'Not set':
                    missing_headers.append(header)
            
            result = {
                'status': 'completed',
                'http_status': response.status_code,
                'url': response.url,  # Final URL after redirects
                'headers': dict(response.headers),
                'security_headers': security_headers,
                'missing_security_headers': missing_headers,
                'redirect_history': [{
                    'url': r.url,
                    'status_code': r.status_code,
                    'headers': dict(r.headers)
                } for r in response.history]
            }
            
            # Add security findings based on headers
            findings = []
            if 'server' in response.headers:
                findings.append({
                    'severity': 'info',
                    'title': 'Server Information',
                    'description': f'Server: {response.headers["server"]}'
                })
                
            if 'x-powered-by' in response.headers:
                findings.append({
                    'severity': 'low',
                    'title': 'Powered-By Header Disclosure',
                    'description': f'Server technology disclosed: {response.headers["x-powered-by"]}'
                })
                
            if not response.url.startswith('https'):
                findings.append({
                    'severity': 'high',
                    'title': 'No HTTPS',
                    'description': 'The site is not using HTTPS, which could expose sensitive information in transit.'
                })
                
            if missing_headers:
                findings.append({
                    'severity': 'medium',
                    'title': 'Missing Security Headers',
                    'description': f'Recommended security headers not found: {", ".join(missing_headers)}'
                })
                
            result['findings'] = findings
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'status': 'failed',
                'error': str(e)
            }

    def scan(self) -> Dict:
        """Run all HTTP-related scans"""
        try:
            # Check if target is reachable
            self.session.get(self.target, timeout=10, verify=False)
            
            # Run security checks
            self.results['head_scan'] = self.perform_head_scan()
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
