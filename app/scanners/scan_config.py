from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

class ScanMode(str, Enum):
    """Enumeration of available scan modes."""
    QUICK = "quick"        # Fast, passive checks only
    STANDARD = "standard"  # Common ports + basic active checks
    FULL = "full"          # Comprehensive scan (all ports, all checks)
    CUSTOM = "custom"      # User-defined configuration

class Protocol(str, Enum):
    """Network protocols supported for scanning."""
    TCP = "tcp"
    UDP = "udp"

class OutputFormat(str, Enum):
    """Available output formats for scan results."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"

@dataclass
class ModuleConfig:
    """Configuration for individual scan modules."""
    port_scan: bool = False
    service_scan: bool = False
    http_headers: bool = False
    ssl_scan: bool = False
    cve_check: bool = False
    dns_whois: bool = False
    save_to_history: bool = True

@dataclass
class AdvancedConfig:
    """Advanced configuration options for scans."""
    port_ranges: List[str] = field(default_factory=lambda: ["1-1024"])
    protocol: Protocol = Protocol.TCP
    timeout: int = 5  # seconds
    retries: int = 2
    max_threads: int = 50
    output_format: OutputFormat = OutputFormat.JSON
    include_raw_logs: bool = False

@dataclass
class ScanConfig:
    """
    Configuration for vulnerability scans.
    
    Attributes:
        target: The target to scan (domain or IP)
        mode: Scan mode (quick/standard/full/custom)
        modules: Module-specific configurations
        advanced: Advanced scan settings
        authorized: Whether the user has authorized potentially intrusive scans
    """
    target: str
    mode: ScanMode = ScanMode.QUICK
    modules: ModuleConfig = field(default_factory=ModuleConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    authorized: bool = False
    
    def __post_init__(self):
        """Set default configurations based on scan mode."""
        if self.mode == ScanMode.QUICK:
            self.modules = ModuleConfig(
                http_headers=True,
                ssl_scan=True,
                dns_whois=True,
                save_to_history=True
            )
            self.advanced.max_threads = 10  # Be gentle
            
        elif self.mode == ScanMode.STANDARD:
            self.modules = ModuleConfig(
                port_scan=True,
                service_scan=True,
                http_headers=True,
                ssl_scan=True,
                dns_whois=True,
                save_to_history=True
            )
            self.advanced.port_ranges = ["21-23,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017,27018"]
            
        elif self.mode == ScanMode.FULL:
            self.modules = ModuleConfig(
                port_scan=True,
                service_scan=True,
                http_headers=True,
                ssl_scan=True,
                cve_check=True,
                dns_whois=True,
                save_to_history=True
            )
            self.advanced.port_ranges = ["1-65535"]
            self.advanced.max_threads = 100  # More aggressive
            
    def validate(self) -> List[str]:
        """
        Validate the configuration.
        
        Returns:
            List of error messages, empty if valid
        """
        errors = []
        
        if not self.target:
            errors.append("Target is required")
            
        if self.mode in [ScanMode.FULL, ScanMode.STANDARD] and not self.authorized:
            errors.append("Authorization required for active scans")
            
        if self.modules.port_scan and not self.advanced.port_ranges:
            errors.append("Port ranges must be specified for port scanning")
            
        # Validate port ranges format
        for port_range in self.advanced.port_ranges:
            for part in port_range.split(','):
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        if not (1 <= start <= 65535 and 1 <= end <= 65535):
                            errors.append(f"Port range {part} is invalid. Ports must be between 1 and 65535")
                    except ValueError:
                        errors.append(f"Invalid port range format: {part}")
                else:
                    try:
                        port = int(part)
                        if not (1 <= port <= 65535):
                            errors.append(f"Port {port} is invalid. Ports must be between 1 and 65535")
                    except ValueError:
                        errors.append(f"Invalid port: {part}")
                        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary for serialization."""
        return {
            'target': self.target,
            'mode': self.mode.value,
            'modules': {
                'port_scan': self.modules.port_scan,
                'service_scan': self.modules.service_scan,
                'http_headers': self.modules.http_headers,
                'ssl_scan': self.modules.ssl_scan,
                'cve_check': self.modules.cve_check,
                'dns_whois': self.modules.dns_whois,
                'save_to_history': self.modules.save_to_history,
            },
            'advanced': {
                'port_ranges': self.advanced.port_ranges,
                'protocol': self.advanced.protocol.value,
                'timeout': self.advanced.timeout,
                'retries': self.advanced.retries,
                'max_threads': self.advanced.max_threads,
                'output_format': self.advanced.output_format.value,
                'include_raw_logs': self.advanced.include_raw_logs,
            },
            'authorized': self.authorized
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanConfig':
        """
        Create a ScanConfig from a dictionary.
        
        Args:
            data: Dictionary containing configuration
            
        Returns:
            Configured ScanConfig instance
        """
        mode = ScanMode(data.get('mode', ScanMode.QUICK))
        config = cls(
            target=data['target'],
            mode=mode,
            authorized=data.get('authorized', False)
        )
        
        # Override module settings if provided
        if 'modules' in data:
            modules = data['modules']
            config.modules = ModuleConfig(
                port_scan=modules.get('port_scan', False),
                service_scan=modules.get('service_scan', False),
                http_headers=modules.get('http_headers', False),
                ssl_scan=modules.get('ssl_scan', False),
                cve_check=modules.get('cve_check', False),
                dns_whois=modules.get('dns_whois', False),
                save_to_history=modules.get('save_to_history', True)
            )
            
        # Override advanced settings if provided
        if 'advanced' in data:
            adv = data['advanced']
            config.advanced = AdvancedConfig(
                port_ranges=adv.get('port_ranges', ["1-1024"]),
                protocol=Protocol(adv.get('protocol', Protocol.TCP)),
                timeout=adv.get('timeout', 5),
                retries=adv.get('retries', 2),
                max_threads=adv.get('max_threads', 50),
                output_format=OutputFormat(adv.get('output_format', OutputFormat.JSON)),
                include_raw_logs=adv.get('include_raw_logs', False)
            )
            
        return config
