from typing import Dict,Any,List
import requests

class CVEChecker:
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1/query"
        self.ecosystem_map = {
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
    
    def check_package(self,package:Dict)-> Any:
        if 'ecosystem' in package:
            return package['ecosystem']
        
        if 'package.json' in package.get('context', {}).get('files', []):
            return 'npm'
        elif 'requirements.txt' in package.get('context', {}).get('files', []):
            return 'PyPI'
        elif 'pom.xml' in package.get('context', {}).get('files', []):
            return 'Maven'
        elif 'go.mod' in package.get('context', {}).get('files', []):
            return 'Go'
        
        return self.ecosystem_map.get(package.get('language', '').lower(), 'npm')

    def normalize_version(self, version: str, ecosystem: str) -> str:
        """
        Normalize version numbers across ecosystems
        """
        if ecosystem == 'PyPI':
            return version.split('+')[0]  # Remove build suffixes
        elif ecosystem == 'npm':
            return version.lstrip('^~=>')  # Remove npm version prefixes
        return version  
     
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
