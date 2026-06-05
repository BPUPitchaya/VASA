import requests
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

@dataclass
class HeaderScanResult:
    """Results from HTTP headers security scan"""
    url: str
    status_code: int
    headers: Dict[str, str]
    missing_headers: List[str]
    security_issues: List[Dict[str, str]]
    
    def to_dict(self) -> dict:
        return {
            'url': self.url,
            'status_code': self.status_code,
            'headers': self.headers,
            'missing_headers': self.missing_headers,
            'security_issues': self.security_issues
        }

class HeadersScanner:
    """Scanner for HTTP security headers and common misconfigurations"""
    
    # Required security headers
    REQUIRED_HEADERS = [
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    # Secure header values
    SECURE_VALUES = {
        'X-Content-Type-Options': ['nosniff'],
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-XSS-Protection': ['1; mode=block'],
        'Referrer-Policy': ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin'],
        'Permissions-Policy': ['*' not in v for v in ["geolocation=()", "microphone=()", "camera=()"]]
    }
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        """
        Initialize headers scanner
        
        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    def scan(self, url: str) -> HeaderScanResult:
        """
        Scan a URL for security headers and common misconfigurations
        
        Args:
            url: URL to scan (must include http:// or https://)
            
        Returns:
            HeaderScanResult with scan findings
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = {'User-Agent': self.user_agent}
        
        try:
            response = requests.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            
            # Convert headers to case-insensitive dict
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing headers
            missing_headers = [
                h for h in self.REQUIRED_HEADERS 
                if h.lower() not in response_headers
            ]
            
            # Check header values for security issues
            security_issues = self._check_header_values(response_headers)
            
            # Check for server information disclosure
            self._check_server_info_disclosure(response_headers, security_issues)
            
            return HeaderScanResult(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                missing_headers=missing_headers,
                security_issues=security_issues
            )
            
        except requests.exceptions.RequestException as e:
            return HeaderScanResult(
                url=url,
                status_code=0,
                headers={},
                missing_headers=self.REQUIRED_HEADERS.copy(),
                security_issues=[{
                    'header': 'Connection',
                    'issue': f'Failed to connect: {str(e)}',
                    'severity': 'high',
                    'remediation': 'Check the URL and network connectivity'
                }]
            )
    
    def _check_header_values(self, headers: Dict[str, str]) -> List[Dict]:
        """Check header values for security issues"""
        issues = []
        
        # Check HSTS
        hsts = headers.get('strict-transport-security', '').lower()
        if hsts:
            if 'max-age=0' in hsts:
                issues.append({
                    'header': 'Strict-Transport-Security',
                    'issue': 'HSTS max-age is set to 0, which disables HSTS',
                    'severity': 'high',
                    'remediation': 'Set max-age to at least 31536000 (1 year)'
                })
            elif 'max-age=' not in hsts:
                issues.append({
                    'header': 'Strict-Transport-Security',
                    'issue': 'HSTS max-age directive is missing',
                    'severity': 'high',
                    'remediation': 'Add max-age directive with a value of at least 31536000 (1 year)'
                })
        
        # Check other security headers
        for header, secure_values in self.SECURE_VALUES.items():
            header_lower = header.lower()
            if header_lower in headers:
                value = headers[header_lower]
                if secure_values and not any(sv.lower() in value.lower() for sv in secure_values):
                    issues.append({
                        'header': header,
                        'issue': f'Insecure value: {value}',
                        'severity': 'medium',
                        'remediation': f'Use one of: {", ".join(secure_values)}'
                    })
        
        return issues
    
    def _check_server_info_disclosure(self, headers: Dict[str, str], issues: List[Dict]) -> None:
        """Check for server information disclosure"""
        info_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        
        for header in info_headers:
            if header in headers:
                issues.append({
                    'header': header,
                    'issue': f'Server information disclosure: {headers[header]}',
                    'severity': 'low',
                    'remediation': f'Remove or obfuscate the {header} header'
                })
