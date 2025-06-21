from typing import Dict,Any,List,Optional
import requests

class CVEChecker:
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1/query"
        self.detect_ecosystem_map = {
            'python': 'PyPI',
            'javascript': 'npm',
            'java': 'Maven',
            'golang': 'Go',
            'ruby': 'RubyGems',
            'rust': 'crates.io',
            'php': 'Packagist',
            'dotnet': 'NuGet',
            'docker': 'Linux',
            'debian': 'Debian',
            'rpm': 'Linux'  
        }


    def detect_ecosystem(self, package: Dict) -> Optional[str]:
        """
        Detect the ecosystem based on package metadata or file structure
        """
        # If ecosystem explicitly provided
        if 'ecosystem' in package:
            return package['ecosystem']
        
        # Auto-detect based on project files
        if 'package.json' in package.get('context', {}).get('files', []):
            return 'npm'
        elif 'requirements.txt' in package.get('context', {}).get('files', []):
            return 'PyPI'
        elif 'pom.xml' in package.get('context', {}).get('files', []):
            return 'Maven'
        elif 'go.mod' in package.get('context', {}).get('files', []):
            return 'Go'
        
        # Fallback to language field
        return self.detect_ecosystem_map.get(package.get('language', '').lower(), package.get('ecosystem',''))
    

    def normalize_version(self, version: str, ecosystem: str) -> str:
        """
        Normalize version numbers across ecosystems
        """
        if ecosystem == 'PyPI':
            return version.split('+')[0]  # Remove build suffixes
        elif ecosystem == 'npm':
            return version.lstrip('^~=>')  # Remove npm version prefixes
        return version

    def _enhance_vulnerabilities(self, vulns: List[Dict], package: Dict) -> List[Dict]:
        """
        Enhance raw vulnerability data with additional context
        """
        enhanced = []
        for vuln in vulns:
            enhanced.append({
                'id': vuln.get('id', ''),
                'summary': vuln.get('summary', ''),
                'details': vuln.get('details', ''),
                'severity': self._get_severity(vuln),
                'affected_versions': self._get_affected_versions(vuln),
                'fixed_versions': self._get_fixed_versions(vuln),
                'references': vuln.get('references', []),
                'package': package['name'],
                'current_version': package['version'],
                'ecosystem': self.detect_ecosystem(package)
            })
        return enhanced  
    
    def _get_severity(self, vuln: Dict) -> str:
        """Extract the highest severity rating"""
        severities = []
        for rating in vuln.get('severity', []):
            if rating['type'] == 'CVSS_V3':
                severities.append(f"CVSS v3: {rating['score']}")
            elif rating['type'] == 'CVSS_V2':
                severities.append(f"CVSS v2: {rating['score']}")
        return ", ".join(severities) if severities else "UNKNOWN"

    def _get_affected_versions(self, vuln: Dict) -> str:
        """Format affected version ranges"""
        ranges = []
        for affected in vuln.get('affected', []):
            for version_range in affected.get('ranges', []):
                if version_range['type'] == 'ECOSYSTEM':
                    for event in version_range['events']:
                        if 'introduced' in event:
                            ranges.append(f">= {event['introduced']}")
                        elif 'fixed' in event:
                            ranges.append(f"< {event['fixed']}")
        return ", ".join(ranges) if ranges else "All versions"
    
    def _get_fixed_versions(self, vuln: Dict) -> List[str]:
        """Extract all fixed versions"""
        fixed_versions = set()
        for affected in vuln.get('affected', []):
            for version_range in affected.get('ranges', []):
                if version_range['type'] == 'ECOSYSTEM':
                    for event in version_range['events']:
                        if 'fixed' in event:
                            fixed_versions.add(event['fixed'])
        return sorted(fixed_versions)

    def check_package(self, package: Dict) -> List[Dict]:
        """
        Check for CVEs in any package across multiple ecosystems
        
        Args:
            package: Dictionary containing:
                - name: Package name
                - version: Package version
                - language/ecosystem: Optional ecosystem hint
                - context: Additional context (files, paths, etc.)
        
        Returns:
            List of vulnerability dictionaries
        """
        ecosystem = self.detect_ecosystem(package)
        if not ecosystem:
            return []
        
        normalized_version = self.normalize_version(package['version'], ecosystem)
        
        query = {
            "version": normalized_version,
            "package": {
                "name": package['name'],
                "ecosystem": ecosystem
            }
        }
        
        try:
            response = requests.post(
                self.base_url,
                json=query,
                timeout=10,
                headers={'Accept': 'application/json'}
            )
            response.raise_for_status()
            
            vulns = response.json().get('vulns', [])
            return self._enhance_vulnerabilities(vulns, package)
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking {package['name']}: {str(e)}")
            return []
        
    def generate_report(self, vulnerabilities):
        if not vulnerabilities:
            return "## ✅ No vulnerabilities found"
    
        report = ["## 🚨 Security Vulnerabilities Found", ""]
        
        for vuln in vulnerabilities:
            package_name = vuln.get("package", "unknown")
            current_version = vuln.get("current_version", "unknown")
            vuln_id = vuln.get("id", "N/A")
            severity = vuln.get("severity", "UNKNOWN")
            details = vuln.get("details", "No details available")
            affected_versions = vuln.get("affected_versions", "Not specified")
            fixed_versions = ", ".join(vuln.get("fixed_versions", []))
            references = vuln.get("references", [])
    
            report.append(f"### `{package_name}`@`{current_version}`")
            report.append(f"**ID**: {vuln_id}")
            report.append(f"**Severity**: {severity}")
            report.append(f"**Affected Versions**: {affected_versions}")
            report.append(f"**Fixed Versions**: {fixed_versions if fixed_versions else 'Not available'}")
            report.append("")
            report.append(f"**Details**:\n{details.strip()}")
            
            if references:
                report.append("\n**References:**")
                for ref in references:
                    ref_type = ref.get("type", "LINK")
                    url = ref.get("url", "")
                    report.append(f"- [{ref_type}]({url})")
    
            report.append("\n---\n")
    
        return "\n".join(report)


checker = CVEChecker()
result = checker.check_package({
    'name': 'requests',
    'version': '2.25.1',
    'language': 'python'
})

print(checker.generate_report(result))