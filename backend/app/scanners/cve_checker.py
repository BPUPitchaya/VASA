from typing import Dict, List, Optional
import re

class CVEChecker:
    # Mock CVE database - in a real application, this would be a proper database
    MOCK_CVE_DB = {
        'apache': [
            {
                'cve_id': 'CVE-2021-41773',
                'description': 'Path Traversal in Apache HTTP Server',
                'affected_versions': '2.4.49, 2.4.50',
                'severity': 'High'
            },
            {
                'cve_id': 'CVE-2020-13956',
                'description': 'Apache HTTP Server HTTP/2 memory corruption',
                'affected_versions': '2.4.20 to 2.4.44',
                'severity': 'Critical'
            }
        ],
        'nginx': [
            {
                'cve_id': 'CVE-2021-23017',
                'description': 'Nginx resolver vulnerability',
                'affected_versions': '0.6.18-1.20.0',
                'severity': 'Medium'
            }
        ],
        'openssh': [
            {
                'cve_id': 'CVE-2021-41617',
                'description': 'Privilege escalation in OpenSSH',
                'affected_versions': '8.5',
                'severity': 'High'
            }
        ]
    }

    @staticmethod
    def extract_version(banner: str) -> Optional[str]:
        """Extract version number from banner"""
        # Simple version extraction - looks for common version patterns
        version_patterns = [
            r'(?:Apache|nginx|OpenSSH)[/\s](\d+\.\d+(?:\.\d+)?)',
            r'Server:\s.*?(\d+\.\d+(?:\.\d+)?)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

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

    def check_cves(self, banner: str) -> Dict:
        """Check for known CVEs based on banner information"""
        if not banner:
            return {'status': 'error', 'message': 'No banner provided'}

        try:
            software = self.get_software_name(banner)
            version = self.extract_version(banner)
            
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
