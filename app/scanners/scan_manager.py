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
        self.cancel_event = asyncio.Event()
        self.pause_event = asyncio.Event()
        self.pause_event.set()  # Start in running state (not paused)
        self.pause_requested = False
    
    def request_cancel(self):
        self.cancel_event.set()

    def request_pause(self):
        self.pause_requested = True
        self.pause_event.clear()

    def request_resume(self):
        self.pause_requested = False
        self.pause_event.set()
        
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
            
            if self.config.mode == ScanMode.QUICK:
                self.config.modules.port_scan = False

            if self.config.modules.port_scan and self.config.authorized:
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
        """Run port scanning if enabled in config (quick for STANDARD/CUSTOM, full for FULL)."""
        if not self.config.modules.port_scan:
            return

        # If you also want to hard-gate active scans by authorization:
        if not self.config.authorized and self.config.mode in (ScanMode.STANDARD, ScanMode.FULL):
            logger.info("Active port scan skipped (not authorized).")
            return

        try:
            self.results['modules'].setdefault('port_scan', {})
            self.results['modules']['port_scan'].update({
                'status': 'running',
                'start_time': time.time(),
                'progress': 0
            })

            # ---- Build ports string from advanced.port_ranges (NO hidden 1–65535) ----
            try:
                ranges = getattr(self.config.advanced, "port_ranges", None) or []
                ports_str = ",".join(ranges) if ranges else None
            except Exception:
                ports_str = None
            if not ports_str:
                # conservative, quick default to avoid accidental 65k scans
                ports_str = "21-23,80,443,8080,8443"

            # ---- Concurrency ----
            max_workers = getattr(getattr(self.config, "advanced", None), "max_threads", 256)

            # ---- Progress callback (logs every completion) ----
            def cb(scanned: int, total: int, port: int | None, status: str | None) -> None:
                try:
                    if port is None:
                        logger.info("[port-scan] 0/%s starting …", total)
                    else:
                        logger.info("[port-scan] %s/%s port %s -> %s", scanned, total, port, status)
                    pct = int(scanned * 100 / max(total, 1))
                    self.results['modules']['port_scan']['progress'] = min(99, max(0, pct))
                    # keep a coarse top-level hint; other modules can push it up
                    self.results['progress'] = max(self.results.get('progress', 0), min(99, max(0, pct)))
                except Exception:
                    pass

            # ---- Choose scanner by mode ----
            from .port_scanner import scan_ports, scan_ports_full
            is_full = (self.config.mode == ScanMode.FULL)
            scanner = scan_ports_full if is_full else scan_ports
            
            # Pass the pause token to the scanner
            scan_doc = await asyncio.to_thread(
                scanner,
                self.config.target,
                ports=ports_str,
                max_workers=max_workers,
                progress_cb=cb,
                cancel_token=self.cancel_event,
                pause_token=self.pause_event
            )
            
            # Update results with scan data
            if scan_doc and 'open_ports' in scan_doc:
                self.results['modules']['port_scan'].update({
                    'end_time': time.time(),
                    'status': 'completed' if scan_doc.get('status') != 'stopped' else 'stopped',
                    'open_ports': scan_doc.get('open_ports', []),
                    'total_ports_scanned': scan_doc.get('total_ports_scanned', 0),
                    'scan_details': {
                        'host_status': scan_doc.get('host_status', 'unknown'),
                        'elapsed': scan_doc.get('duration_seconds', 0)
                    }
                })
                
                # Update the main results with open ports
                if 'open_ports' not in self.results:
                    self.results['open_ports'] = []
                self.results['open_ports'].extend(scan_doc.get('open_ports', []))

            # Ensure pause tokens exist if you plan to support Pause/Resume
            # (create these in __init__: self.pause_event = asyncio.Event(); self.pause_event.set())
            pause_token = getattr(self, "pause_event", None)

            # ---- Execute port scan off the loop ----
            scan_doc = await asyncio.to_thread(
                scanner,
                self.config.target,
                ports=ports_str,
                max_workers=max_workers,
                progress_cb=cb,
                cancel_token=self.cancel_event,   # supports Stop
                pause_token=pause_token           # supports Pause/Resume (if wired in _perform_scan)
            )

            # ---- Persist results ----
            self.results['modules']['port_scan'].update({
                'status'    : 'completed',
                'end_time'  : time.time(),
                'open_ports': scan_doc.get('open_ports', []),
                'scan_stats': scan_doc.get('scan_stats', {}),
                'target_ip' : scan_doc.get('ip_address'),
                'scan_type' : scan_doc.get('scan_type', 'tcp_connect_scan'),
                'progress'  : 100,
            })
            # lift overall progress toward done for this module
            self.results['progress'] = max(self.results.get('progress', 0), 100)

        except Exception as e:
            logger.exception("Port scan failed")
            self.results['modules']['port_scan'].update({
                'status': 'failed',
                'error' : str(e),
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

#call back log for port scanned 
def my_callback(port,status,idx,total):
    print(f"[progress] {idx}/{total} port {port} : {status}")