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
            # return self._enhance_vulnerabilities(vulns, package)
            return vulns
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking {package['name']}: {str(e)}")
            return []


checker = CVEChecker()
# result = checker.check_package({
#     'name': 'requests',
#     'version': '2.25.1',
#     'language': 'python'
# })
result = checker.check_package({
   'name': 'ubuntu',
    'version': '18.04',
    'ecosystem': 'Debian'
})
print(f"result, {result}")