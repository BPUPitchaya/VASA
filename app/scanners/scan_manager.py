import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import asdict
import time
import logging

from .scan_config import ScanConfig, ScanMode
from .port_scanner import scan_ports
from .http_scanner import HttpScanner
from .ssl_scanner import SSLScanner
from .headers_scanner import HeadersScanner
from .cve_checker import CVEChecker

logger = logging.getLogger(__name__)

class ScanManager:
    """
    Manages the execution of vulnerability scans based on configuration.
    Handles rate limiting, concurrency, and result aggregation.
    """
    
    def __init__(self, config: ScanConfig):
        """
        Initialize the scan manager with a configuration.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.results: Dict[str, Any] = {
            'target': config.target,
            'mode': config.mode.value,
            'start_time': time.time(),
            'end_time': None,
            'status': 'pending',
            'modules': {}
        }
        self._rate_limit_semaphore = asyncio.Semaphore(config.advanced.max_threads)
        
    async def run_scan(self) -> Dict[str, Any]:
        """
        Execute the scan based on the configuration.
        
        Returns:
            Dictionary containing scan results
        """
        self.results['status'] = 'running'
        
        try:
            # Run enabled modules concurrently
            tasks = []
            
            if self.config.modules.port_scan:
                tasks.append(self._run_port_scan())
                
            if self.config.modules.http_headers:
                tasks.append(self._run_headers_scan())
                
            if self.config.modules.ssl_scan:
                tasks.append(self._run_ssl_scan())
                
            if self.config.modules.cve_check:
                tasks.append(self._run_cve_check())
                
            if self.config.modules.dns_whois:
                tasks.append(self._run_dns_whois())
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self.results['status'] = 'completed'
            
        except Exception as e:
            logger.exception("Scan failed")
            self.results['status'] = 'failed'
            self.results['error'] = str(e)
            
        finally:
            self.results['end_time'] = time.time()
            self.results['duration'] = self.results['end_time'] - self.results['start_time']
            
        return self.results
    
    async def _run_port_scan(self) -> None:
        """Run port scanning if enabled in config."""
        if not self.config.modules.port_scan:
            return
            
        try:
            self.results['modules']['port_scan'] = {
                'status': 'running',
                'start_time': time.time()
            }
            
            # Convert port ranges to flat list of ports
            ports = []
            for port_range in self.config.advanced.port_ranges:
                for part in port_range.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
            
            # Run the scan
            open_ports = await scan_ports(
                self.config.target,
                ports=ports,
                timeout=self.config.advanced.timeout,
                max_concurrent=self.config.advanced.max_threads
            )
            
            self.results['modules']['port_scan'].update({
                'status': 'completed',
                'end_time': time.time(),
                'open_ports': open_ports,
                'protocol': self.config.advanced.protocol.value
            })
            
        except Exception as e:
            logger.exception("Port scan failed")
            self.results['modules']['port_scan'].update({
                'status': 'failed',
                'error': str(e),
                'end_time': time.time()
            })
    
    async def _run_headers_scan(self) -> None:
        """Run HTTP headers scan if enabled in config."""
        if not self.config.modules.http_headers:
            return
            
        try:
            self.results['modules']['http_headers'] = {
                'status': 'running',
                'start_time': time.time()
            }
            
            scanner = HeadersScanner()
            result = await asyncio.to_thread(
                scanner.scan,
                f"https://{self.config.target}"
            )
            
            self.results['modules']['http_headers'].update({
                'status': 'completed',
                'end_time': time.time(),
                'results': result.to_dict()
            })
            
        except Exception as e:
            logger.exception("HTTP headers scan failed")
            self.results['modules']['http_headers'].update({
                'status': 'failed',
                'error': str(e),
                'end_time': time.time()
            })
    
    async def _run_ssl_scan(self) -> None:
        """Run SSL/TLS scan if enabled in config."""
        if not self.config.modules.ssl_scan:
            return
            
        try:
            self.results['modules']['ssl_scan'] = {
                'status': 'running',
                'start_time': time.time()
            }
            
            scanner = SSLScanner(
                host=self.config.target,
                port=443,  # Default HTTPS port
                timeout=self.config.advanced.timeout
            )
            result = scanner.scan()
            
            self.results['modules']['ssl_scan'].update({
                'status': 'completed',
                'end_time': time.time(),
                'results': result.to_dict()
            })
            
        except Exception as e:
            logger.exception("SSL scan failed")
            self.results['modules']['ssl_scan'].update({
                'status': 'failed',
                'error': str(e),
                'end_time': time.time()
            })
    
    async def _run_cve_check(self) -> None:
        """Run CVE check if enabled in config."""
        if not self.config.modules.cve_check:
            return
            
        try:
            self.results['modules']['cve_check'] = {
                'status': 'running',
                'start_time': time.time()
            }
            
            # First get banners from open ports if available
            banners = []
            if 'port_scan' in self.results['modules']:
                for port_info in self.results['modules']['port_scan'].get('open_ports', []):
                    if 'banner' in port_info:
                        banners.append(port_info['banner'])
            
            # Check CVEs for each banner
            cve_results = []
            for banner in banners:
                result = CVEChecker.check_cves(banner)
                if result['status'] == 'completed' and result.get('cves_found'):
                    cve_results.extend(result['cves_found'])
            
            self.results['modules']['cve_check'].update({
                'status': 'completed',
                'end_time': time.time(),
                'cves_found': cve_results,
                'total_cves': len(cve_results)
            })
            
        except Exception as e:
            logger.exception("CVE check failed")
            self.results['modules']['cve_check'].update({
                'status': 'failed',
                'error': str(e),
                'end_time': time.time()
            })
    
    async def _run_dns_whois(self) -> None:
        """Run DNS and WHOIS lookup if enabled in config."""
        if not self.config.modules.dns_whois:
            return
            
        try:
            self.results['modules']['dns_whois'] = {
                'status': 'running',
                'start_time': time.time()
            }
            
            # TODO: Implement DNS and WHOIS lookup
            # This would use a DNS/WOHIS library like python-whois and dnspython
            
            self.results['modules']['dns_whois'].update({
                'status': 'completed',
                'end_time': time.time(),
                'message': 'DNS/WHOIS lookup not yet implemented'
            })
            
        except Exception as e:
            logger.exception("DNS/WHOIS lookup failed")
            self.results['modules']['dns_whois'].update({
                'status': 'failed',
                'error': str(e),
                'end_time': time.time()
            })
