from typing import Dict, List, Optional, Tuple, Union, Any
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from packaging import version

@dataclass
class CVE:
    cve_id: str
    description: str
    affected_versions: str
    severity: str
    published_date: str
    cvss_score: float
    cwe_id: str = ""
    exploit_available: bool = False
    remediation: str = ""
    references: list = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

class CVEChecker:
    # Extended CVE database with more entries and better structure
    MOCK_CVE_DB = {
        'apache': [
            CVE(
                cve_id='CVE-2021-41773',
                description='Path Traversal in Apache HTTP Server',
                affected_versions='2.4.49 to 2.4.50',
                severity='High',
                published_date='2021-10-05',
                cvss_score=7.5,
                cwe_id='CWE-22',
                exploit_available=True,
                remediation='Upgrade to Apache 2.4.51 or later',
                references=['https://httpd.apache.org/security/vulnerabilities_24.html']
            ),
            CVE(
                cve_id='CVE-2020-13956',
                description='Apache HTTP Server HTTP/2 memory corruption',
                affected_versions='2.4.20 to 2.4.44',
                severity='Critical',
                published_date='2020-07-16',
                cvss_score=9.8,
                cwe_id='CWE-787',
                exploit_available=True,
                remediation='Upgrade to Apache 2.4.45 or later',
                references=['https://httpd.apache.org/security/vulnerabilities_24.html']
            )
        ],
        'nginx': [
            CVE(
                cve_id='CVE-2021-23017',
                description='Nginx resolver vulnerability',
                affected_versions='0.6.18 to 1.20.0',
                severity='Medium',
                published_date='2021-05-25',
                cvss_score=5.3,
                cwe_id='CWE-400',
                remediation='Upgrade to Nginx 1.21.0 or later',
                references=['https://nginx.org/en/security_advisories.html']
            ),
            CVE(
                cve_id='CVE-2019-20372',
                description='Nginx DoS vulnerability',
                affected_versions='1.17.7 and earlier',
                severity='High',
                published_date='2019-12-31',
                cvss_score=7.5,
                cwe_id='CWE-400',
                exploit_available=True,
                remediation='Upgrade to Nginx 1.17.8 or later',
                references=['https://nginx.org/en/security_advisories.html']
            )
        ],
        'iis': [
            CVE(
                cve_id='CVE-2021-31166',
                description='HTTP Protocol Stack Remote Code Execution',
                affected_versions='10.0.19042.0 to 10.0.19042.1288',
                severity='Critical',
                published_date='2021-05-11',
                cvss_score=9.8,
                cwe_id='CWE-787',
                exploit_available=True,
                remediation='Apply Windows update KB5003173 or later',
                references=['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31166']
            )
        ],
        'openssh': [
            CVE(
                cve_id='CVE-2021-41617',
                description='Privilege escalation in OpenSSH',
                affected_versions='8.5',
                severity='High',
                published_date='2021-10-19',
                cvss_score=7.8,
                cwe_id='CWE-269',
                exploit_available=True,
                remediation='Upgrade to OpenSSH 8.6 or later',
                references=['https://www.openssh.com/security.html']
            )
        ],
        'mysql': [
            CVE(
                cve_id='CVE-2021-46659',
                description='MySQL Server vulnerability',
                affected_versions='5.7.0 to 5.7.36, 8.0.0 to 8.0.27',
                severity='High',
                published_date='2022-01-18',
                cvss_score=8.8,
                cwe_id='CWE-89',
                remediation='Upgrade to MySQL 5.7.37 or 8.0.28 or later',
                references=['https://www.oracle.com/security-alerts/cpujan2022.html']
            )
        ],
        'postgresql': [
            CVE(
                cve_id='CVE-2023-2454',
                description='PostgreSQL memory disclosure',
                affected_versions='12.0 to 14.7, 15.0 to 15.2',
                severity='Medium',
                published_date='2023-05-11',
                cvss_score=5.3,
                cwe_id='CWE-200',
                remediation='Upgrade to PostgreSQL 14.8, 15.3, or later',
                references=['https://www.postgresql.org/support/security/']
            )
        ],
        'wordpress': [
            CVE(
                cve_id='CVE-2022-21661',
                description='SQL Injection in WP_Query',
                affected_versions='5.8.0 to 5.8.2',
                severity='High',
                published_date='2022-01-06',
                cvss_score=8.8,
                cwe_id='CWE-89',
                exploit_available=True,
                remediation='Update to WordPress 5.8.3 or later',
                references=['https://wordpress.org/support/wordpress-version/version-5-8-3/']
            )
        ],
        'tomcat': [
            CVE(
                cve_id='CVE-2020-1938',
                description='Ghostcat - AJP File Read/Inclusion',
                affected_versions='6.0.0 to 6.0.44, 7.0.0 to 7.0.99, 8.5.0 to 8.5.50, 9.0.0 to 9.0.30',
                severity='Critical',
                published_date='2020-02-24',
                cvss_score=9.8,
                cwe_id='CWE-20',
                exploit_available=True,
                remediation='Upgrade to Tomcat 7.0.100, 8.5.51, 9.0.31 or later',
                references=['https://tomcat.apache.org/security-9.html']
            )
        ],
        'redis': [
            CVE(
                cve_id='CVE-2021-32762',
                description='Integer Overflow in Redis',
                affected_versions='2.6 to 6.2.5',
                severity='High',
                published_date='2021-07-20',
                cvss_score=7.5,
                cwe_id='CWE-190',
                remediation='Upgrade to Redis 6.2.6 or later',
                references=['https://github.com/redis/redis/releases/tag/6.2.6']
            )
        ],
        'drupal': [
            CVE(
                cve_id='CVE-2019-6340',
                description='Drupal Core - Remote Code Execution',
                affected_versions='8.7.0 to 8.7.6',
                severity='Critical',
                published_date='2019-02-20',
                cvss_score=9.8,
                cwe_id='CWE-434',
                exploit_available=True,
                remediation='Update to Drupal 8.7.7 or later',
                references=['https://www.drupal.org/sa-core-2019-003']
            )
        ]
    }

    @staticmethod
    def extract_version(banner: str) -> Optional[str]:
        """
        Extract version number from banner using common patterns
        Returns version string if found, None otherwise
        """
        # Common version patterns for different services
        version_patterns = [
            r'([Aa]pache[/\s]?[Hh]ttpd[/\s]?)?(\d+\.\d+(\.\d+)?)',
            r'[Nn]ginx/(\d+\.\d+(\.\d+)?)',
            r'[Ss][Ss][Hh]-(\d+\.\d+(\.\d+)?)',
            r'[Mm]y[Ss][Qq][Ll][Dd]?[-_ ](\d+\.\d+(\.\d+)?)',
            r'[Pp]ostgre[Ss][Qq][Ll]?[-_ ](\d+\.\d+(\.\d+)?)',
            r'[Vv]ersion[-_ ]?(\d+\.\d+(\.\d+)?)',
            r'(\d+\.\d+(\.\d+)?(?:-\w+)?)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1) if len(match.groups()) > 1 else match.group(0)
        return None

    @classmethod
    def is_version_affected(cls, version_str: str, affected_range: str) -> bool:
        """
        Check if a version is within an affected range
        Supports formats like: '1.2.3', '1.2.3 to 1.2.5', '1.2.3, 1.2.4, 1.2.5'
        """
        try:
            current = version.parse(version_str)
            
            # Handle multiple versions separated by commas
            if ',' in affected_range:
                versions = [v.strip() for v in affected_range.split(',')]
                return any(cls._compare_versions(current, v) for v in versions)
            
            # Handle version ranges with 'to' or '-'
            if ' to ' in affected_range:
                low, high = affected_range.split(' to ', 1)
                low_ver = version.parse(low.strip())
                high_ver = version.parse(high.strip())
                return low_ver <= current <= high_ver
                
            # Handle single version
            return cls._compare_versions(current, affected_range)
            
        except Exception:
            return False

    @staticmethod
    def _compare_versions(v1: version.Version, v2_str: str) -> bool:
        """Helper method to compare versions"""
        try:
            v2 = version.parse(v2_str.strip())
            return v1 == v2
        except version.InvalidVersion:
            return False

    @classmethod
    def check_cve(cls, service_name: str, version_str: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Check for CVEs affecting a specific service and version
        
        Args:
            service_name: Name of the service (e.g., 'apache', 'nginx')
            version_str: Optional version string to check against
            
        Returns:
            List of matching CVEs with details
        """
        service_name = service_name.lower()
        if service_name not in cls.MOCK_CVE_DB:
            return []
            
        matching_cves = []
        for cve in cls.MOCK_CVE_DB[service_name]:
            cve_dict = asdict(cve)
            
            # If no version specified, return all CVEs for the service
            if not version_str:
                matching_cves.append(cve_dict)
                continue
                
            # Check if version is affected
            if cls.is_version_affected(version_str, cve.affected_versions):
                matching_cves.append(cve_dict)
                
        return matching_cves

    @classmethod
    def check_banner(cls, banner: str) -> List[Dict[str, Any]]:
        """
        Check for CVEs based on a service banner
        
        Args:
            banner: Service banner string
            
        Returns:
            List of matching CVEs with details
        """
        banner_lower = banner.lower()
        service_name = None
        version_str = cls.extract_version(banner)
        
        # Try to identify service from banner
        if 'apache' in banner_lower or 'httpd' in banner_lower:
            service_name = 'apache'
        elif 'nginx' in banner_lower:
            service_name = 'nginx'
        elif 'ssh' in banner_lower:
            service_name = 'openssh'
        elif 'mysql' in banner_lower:
            service_name = 'mysql'
        elif 'postgres' in banner_lower:
            service_name = 'postgresql'
            
        if not service_name:
            return []
            
        return cls.check_cve(service_name, version_str)
    @staticmethod
    def get_software_name(banner: str) -> str:
        """Identify software from banner"""
        banners = banner.lower()
        if 'apache' in banners:
            return 'apache'
        elif 'nginx' in banners:
            return 'nginx'
        elif 'openssh' in banners or 'ssh-2.0-openssh' in banners:
            return 'openssh'
        return 'unknown'

    @classmethod
    def check_cves(cls, banner: str) -> Dict:
        """Check for known CVEs based on banner information"""
        if not banner:
            return {'status': 'error', 'message': 'No banner provided'}

        try:
            software = cls.get_software_name(banner)
            version = cls.extract_version(banner)
            
            if software == 'unknown' or not version:
                return {
                    'status': 'completed',
                    'message': 'No matching software/version found',
                    'banner': banner
                }
            
            # Check against our mock database
            matching_cves = []
            for cve in self.MOCK_CVE_DB.get(software, []):
                # Simple version check - in a real app, you'd want more sophisticated version comparison
                if version in cve['affected_versions']:
                    matching_cves.append({
                        'cve_id': cve['cve_id'],
                        'description': cve['description'],
                        'severity': cve['severity']
                    })
            
            return {
                'status': 'completed',
                'software': software,
                'version': version,
                'cves_found': matching_cves,
                'banner': banner
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
