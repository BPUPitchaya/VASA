import socket
import ssl
import OpenSSL
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

@dataclass
class SSLScanResult:
    """Results from SSL/TLS scan"""
    host: str
    port: int
    valid: bool = False
    error: Optional[str] = None
    certificate: Optional[dict] = None
    protocols: List[str] = None
    ciphers: List[dict] = None
    vulnerabilities: List[dict] = None
    
    def to_dict(self) -> dict:
        """Convert result to dictionary"""
        return {
            'host': self.host,
            'port': self.port,
            'valid': self.valid,
            'error': self.error,
            'certificate': self.certificate,
            'protocols': self.protocols,
            'ciphers': [{
                'name': c['name'],
                'protocol': c['protocol'],
                'strength': c['strength'],
                'secure': c.get('secure', False)
            } for c in (self.ciphers or [])],
            'vulnerabilities': self.vulnerabilities or []
        }

class SSLScanner:
    """Scanner for SSL/TLS vulnerabilities"""
    
    # Known weak ciphers and protocols
    WEAK_CIPHERS = [
        'DES', 'RC4', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ANON', 'ADH', 'LOW',
        '3DES', 'CBC', 'CBC3', 'IDEA', 'SEED', 'CAMELLIA', 'ARIA', 'CHACHA20',
        'PSK', 'SRP', 'KRB5', 'AES128', 'AES256', 'CAMELLIA128', 'CAMELLIA256'
    ]
    
    # Minimum key sizes in bits
    MIN_RSA_KEY_SIZE = 2048
    MIN_ECC_KEY_SIZE = 256  # ECDSA keys are secure at this size
    
    # Maximum certificate validity in days
    MAX_CERT_DAYS = 365
    
    def __init__(self, host: str, port: int = 443, timeout: int = 10):
        """
        Initialize SSL scanner
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 443)
            timeout: Connection timeout in seconds (default: 10)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        
    def scan(self) -> SSLScanResult:
        """
        Perform SSL/TLS scan
        
        Returns:
            SSLScanResult with scan results
        """
        result = SSLScanResult(host=self.host, port=self.port)
        
        try:
            # Create socket connection
            sock = socket.create_connection((self.host, self.port), self.timeout)
            
            # Wrap socket with SSL
            ssl_sock = self.context.wrap_socket(sock, server_hostname=self.host)
            
            # Get certificate info
            cert = ssl_sock.getpeercert(binary_form=True)
            x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert
            )
            
            # Parse certificate
            result.certificate = self._parse_certificate(x509)
            
            # Check certificate validity
            self._check_certificate(result, x509)
            
            # Check supported protocols
            result.protocols = self._check_protocols()
            
            # Check supported ciphers
            result.ciphers = self._check_ciphers()
            
            # Check for vulnerabilities
            result.vulnerabilities = self._check_vulnerabilities(result)
            
            result.valid = True
            
        except socket.timeout:
            result.error = "Connection timed out"
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except ssl.SSLError as e:
            result.error = f"SSL Error: {str(e)}"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        finally:
            if 'ssl_sock' in locals():
                ssl_sock.close()
            if 'sock' in locals():
                sock.close()
                
        return result
    
    def _parse_certificate(self, x509) -> dict:
        """Parse X509 certificate details"""
        subject = dict(x509.get_subject().get_components())
        issuer = dict(x509.get_issuer().get_components())
        
        # Get key type and size
        pubkey = x509.get_pubkey()
        key_type = 'RSA' if pubkey.type() == OpenSSL.crypto.TYPE_RSA else 'EC' if pubkey.type() == OpenSSL.crypto.TYPE_EC else 'UNKNOWN'
        
        return {
            'subject': {k.decode(): v.decode() for k, v in subject.items()},
            'issuer': {k.decode(): v.decode() for k, v in issuer.items()},
            'version': x509.get_version() + 1,
            'serial_number': x509.get_serial_number(),
            'not_before': x509.get_notBefore().decode(),
            'not_after': x509.get_notAfter().decode(),
            'signature_algorithm': x509.get_signature_algorithm().decode(),
            'key_bits': pubkey.bits(),
            'key_type': key_type
        }
    
    def _check_certificate(self, result: SSLScanResult, x509) -> None:
        """Check certificate validity and security"""
        cert = result.certificate
        if not cert:
            return
            
        # Check expiration
        not_after = datetime.strptime(cert['not_after'], '%Y%m%d%H%M%SZ')
        days_left = (not_after - datetime.utcnow()).days
        
        if days_left < 0:
            result.vulnerabilities = result.vulnerabilities or []
            result.vulnerabilities.append({
                'id': 'cert_expired',
                'severity': 'high',
                'description': 'SSL certificate has expired',
                'remediation': 'Renew the SSL certificate'
            })
        elif days_left < 30:
            result.vulnerabilities = result.vulnerabilities or []
            result.vulnerabilities.append({
                'id': 'cert_expiring_soon',
                'severity': 'medium',
                'description': f'SSL certificate expires in {days_left} days',
                'remediation': 'Renew the SSL certificate'
            })
        
        # Check key size based on key type
        key_type = cert.get('key_type', '').upper()
        key_bits = cert.get('key_bits', 0)
        
        if key_type == 'RSA' and key_bits < self.MIN_RSA_KEY_SIZE:
            result.vulnerabilities = result.vulnerabilities or []
            result.vulnerabilities.append({
                'id': 'weak_rsa_key',
                'severity': 'high',
                'description': f'Weak RSA key size: {key_bits} bits',
                'remediation': f'Use at least {self.MIN_RSA_KEY_SIZE}-bit RSA keys'
            })
        elif key_type == 'EC' and key_bits < self.MIN_ECC_KEY_SIZE:
            result.vulnerabilities = result.vulnerabilities or []
            result.vulnerabilities.append({
                'id': 'weak_ecc_key',
                'severity': 'high',
                'description': f'Weak ECC key size: {key_bits} bits',
                'remediation': f'Use at least {self.MIN_ECC_KEY_SIZE}-bit ECC keys'
            })
    
    def _check_protocols(self) -> List[str]:
        """Check supported SSL/TLS protocols"""
        protocols = []
        
        # Test different protocol versions
        for proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
            try:
                context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{proto}'))
                with socket.create_connection((self.host, self.port), self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host):
                        protocols.append(proto)
            except:
                continue
                
        return protocols
    
    def _check_ciphers(self) -> List[dict]:
        """Check supported ciphers"""
        ciphers = []
        
        # Test common cipher suites
        for cipher in ssl._DEFAULT_CIPHERS.split(':'):
            try:
                context = ssl.create_default_context()
                context.set_ciphers(cipher)
                with socket.create_connection((self.host, self.port), self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cipher_data = ssock.cipher()
                        if cipher_data:
                            is_weak = any(weak in cipher_data[0].upper() for weak in self.WEAK_CIPHERS)
                            ciphers.append({
                                'name': cipher_data[0],
                                'protocol': cipher_data[1],
                                'strength': cipher_data[2],
                                'secure': not is_weak
                            })
            except:
                continue
                
        return ciphers
    
    def _check_vulnerabilities(self, result: SSLScanResult) -> List[dict]:
        """Check for common SSL/TLS vulnerabilities"""
        vulns = result.vulnerabilities or []
        
        # Check for Heartbleed
        if self._check_heartbleed():
            vulns.append({
                'id': 'heartbleed',
                'severity': 'critical',
                'description': 'Vulnerable to Heartbleed (CVE-2014-0160)',
                'remediation': 'Upgrade OpenSSL to version 1.0.1g or later',
                'cve': 'CVE-2014-0160'
            })
            
        # Check for POODLE
        if 'SSLv3' in (result.protocols or []) and any('CBC' in c['name'] for c in result.ciphers or []):
            vulns.append({
                'id': 'poodle',
                'severity': 'high',
                'description': 'Vulnerable to POODLE (CVE-2014-3566)',
                'remediation': 'Disable SSLv3',
                'cve': 'CVE-2014-3566'
            })
            
        return vulns
    
    def _check_heartbleed(self) -> bool:
        """Check for Heartbleed vulnerability"""
        try:
            # Skip Heartbleed check for non-OpenSSL servers
            if not any('openssl' in p.lower() for p in (self.protocols or [])):
                return False
                
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    # Check if server is using OpenSSL
                    if not hasattr(ssock, 'version') or not ssock.version():
                        return False
                        
                    # Only check if server is using a vulnerable OpenSSL version
                    if 'openssl' in ssock.version().lower():
                        version_str = ssock.version().lower()
                        if 'openssl 1.0.1' in version_str:
                            # Check if version is between 1.0.1 and 1.0.1f (vulnerable)
                            version_parts = version_str.split(' ')[1].split('.')
                            if len(version_parts) >= 3:
                                try:
                                    patch = int(version_parts[2][0])  # Get first digit of patch version
                                    if patch <= 1:  # 1.0.1 to 1.0.1f are vulnerable
                                        return True
                                except (ValueError, IndexError):
                                    pass
                    return False
        except Exception:
            return False



def run_ssl_scan(host, port_results=None):
    """
    Run a single SSL scan against the best HTTPS-like port we can find.

    endpoints.py calls: run_ssl_scan(target, open_ports)
    where open_ports is a list of { "port": int, ... }.
    """
    # Default port
    port = 443

    # If we have open port info, prefer 443 / 8443 / 9443 when present
    https_candidates = {443, 8443, 9443}
    if port_results:
        for entry in port_results:
            p = entry.get("port")
            if p in https_candidates:
                port = p
                break

    scanner = SSLScanner(host=host, port=port)
    result = scanner.scan()  # SSLScanResult
    return result.to_dict()