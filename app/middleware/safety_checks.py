import ipaddress
import socket
import re
from typing import Optional, List, Set, Tuple, Dict, Any
from urllib.parse import urlparse
from dataclasses import dataclass

@dataclass
class SafetyCheckResult:
    """Result of a safety check."""
    allowed: bool
    reason: Optional[str] = None

class SafetyChecker:
    """
    Performs safety checks before allowing scans to proceed.
    Prevents scanning of restricted targets and enforces safe scanning practices.
    """
    
    def __init__(self):
        # List of restricted IP ranges (private, localhost, etc.)
        self.restricted_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
            ipaddress.ip_network('224.0.0.0/4'),     # Multicast
            ipaddress.ip_network('240.0.0.0/4'),     # Reserved
            ipaddress.ip_network('::1/128'),         # IPv6 localhost
            ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
            ipaddress.ip_network('fc00::/7'),        # IPv6 ULA
        ]
        
        # List of restricted domains
        self.restricted_domains = [
            'localhost',
            'localhost.localdomain',
            'local',
            'broadcasthost',
            'ip6-localhost',
            'ip6-loopback',
        ]
        
        # Maximum number of ports that can be scanned at once
        self.max_ports_per_scan = 1000
        
        # Maximum number of concurrent scans per IP
        self.max_concurrent_scans = 3
        
        # Track active scans per IP
        self.active_scans: Dict[str, int] = {}
    
    def check_target(self, target: str) -> SafetyCheckResult:
        """
        Check if a target is safe to scan.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            SafetyCheckResult indicating if the target is safe to scan
        """
        # Check if target is empty
        if not target or not target.strip():
            return SafetyCheckResult(False, "No target specified")
        
        # Check if target is a URL
        if target.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(target)
                target = parsed.hostname or target
            except Exception as e:
                return SafetyCheckResult(False, f"Invalid URL: {str(e)}")
        
        # Check if target is an IP address
        try:
            ip = ipaddress.ip_address(target)
            return self._check_ip(ip)
        except ValueError:
            # Not an IP, treat as hostname
            return self._check_domain(target)
    
    def check_ports(self, ports: List[str]) -> SafetyCheckResult:
        """
        Check if the specified ports are safe to scan.
        
        Args:
            ports: List of port ranges (e.g., ["80", "443", "8000-9000"])
            
        Returns:
            SafetyCheckResult indicating if the ports are safe to scan
        """
        if not ports:
            return SafetyCheckResult(False, "No ports specified")
        
        total_ports = 0
        
        for port_range in ports:
            for part in port_range.split(','):
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        total_ports += end - start + 1
                    except ValueError:
                        return SafetyCheckResult(False, f"Invalid port range: {part}")
                else:
                    try:
                        int(part)  # Validate it's a number
                        total_ports += 1
                    except ValueError:
                        return SafetyCheckResult(False, f"Invalid port: {part}")
        
        if total_ports > self.max_ports_per_scan:
            return SafetyCheckResult(
                False, 
                f"Too many ports to scan ({total_ports} > {self.max_ports_per_scan}). "
                "Please reduce the port range or contact an administrator."
            )
        
        return SafetyCheckResult(True)
    
    def check_concurrent_scans(self, ip: str) -> SafetyCheckResult:
        """
        Check if an IP has too many concurrent scans.
        
        Args:
            ip: IP address to check
            
        Returns:
            SafetyCheckResult indicating if the scan can proceed
        """
        if self.active_scans.get(ip, 0) >= self.max_concurrent_scans:
            return SafetyCheckResult(
                False,
                f"Too many concurrent scans ({self.active_scans[ip]}). "
                f"Maximum allowed: {self.max_concurrent_scans}"
            )
        return SafetyCheckResult(True)
    
    def start_scan(self, ip: str) -> None:
        """
        Register that a scan has started for an IP.
        
        Args:
            ip: IP address that started a scan
        """
        self.active_scans[ip] = self.active_scans.get(ip, 0) + 1
    
    def end_scan(self, ip: str) -> None:
        """
        Register that a scan has ended for an IP.
        
        Args:
            ip: IP address that finished a scan
        """
        if ip in self.active_scans:
            self.active_scans[ip] -= 1
            if self.active_scans[ip] <= 0:
                del self.active_scans[ip]
    
    def _check_ip(self, ip: ipaddress._BaseAddress) -> SafetyCheckResult:
        """Check if an IP address is safe to scan."""
        # Check if IP is in a restricted range
        for network in self.restricted_ranges:
            if ip in network:
                return SafetyCheckResult(
                    False,
                    f"Scanning {ip} is not allowed (restricted range: {network})"
                )
        
        # Allow public IPs
        if ip.is_global:
            return SafetyCheckResult(True)
        
        return SafetyCheckResult(
            False,
            f"Scanning {ip} is not allowed (non-global address)"
        )
    
    def _check_domain(self, domain: str) -> SafetyCheckResult:
        """Check if a domain is safe to scan."""
        # Normalize domain
        domain = domain.lower().strip()
        
        # Check for restricted domains
        if domain in self.restricted_domains:
            return SafetyCheckResult(False, f"Scanning {domain} is not allowed")
        
        # Check for local domains
        if domain.endswith(('.local', '.localhost', '.localdomain')):
            return SafetyCheckResult(False, f"Scanning local domain {domain} is not allowed")
        
        # Resolve domain to IP and check
        try:
            ips = socket.getaddrinfo(domain, None)
            for _, _, _, _, (ip, *_) in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip.split('%')[0])  # Handle IPv6 zone indices
                    ip_check = self._check_ip(ip_obj)
                    if not ip_check.allowed:
                        return ip_check
                except ValueError:
                    continue
        except socket.gaierror:
            return SafetyCheckResult(False, f"Could not resolve domain: {domain}")
        
        return SafetyCheckResult(True)

# Global safety checker instance
safety_checker = SafetyChecker()
