# scanner/scanner.py
import argparse
from pathlib import Path
from cve_checker import CVEChecker
# Change this import
# OR if you want to keep it simple:
# from cve_checker import CVEChecker  # If files are in same directory

class ProjectScanner:
    def scan(self, project_path):
        pass

def main():
    parser = argparse.ArgumentParser(description="CVE Scanner for CI/CD pipelines")
    parser.add_argument('--path', default='.', help='Project directory to scan')
    parser.add_argument('--format', default='markdown', 
                       choices=['markdown', 'json', 'sarif'],
                       help='Output format')
    parser.add_argument('--output', default='cve-report.md',
                       help='Output file path')
    
    args = parser.parse_args()
    
    checker = CVEChecker()
    
    # Mock results for testing
    results = [{
        'project': 'test-project',
        'dependencies': [{
            'name': 'python-a2a',
            'version': '0.5.5',
            'ecosystem': 'python'
        }]
    }]
    
    vulnerabilities = []

    for project in results:
        for dep in project['dependencies']:
            vulns = checker.check_package(dep)
            for vuln in vulns:
                vulnerabilities.append({
                    'package': dep,
                    'vulnerability': vuln,
                    'project': project['project']
                })
    
    report = generate_report(vulnerabilities, args.format)
    print(f"report : {report}")
    # Ensure output directory exists
    """
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    if vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)
    """
def generate_report(vulnerabilities, format='markdown'):
    if format == 'markdown':
        if not vulnerabilities:
            return "# No vulnerabilities found"
        report = ["# Vulnerability Report", ""]
        for vuln in vulnerabilities:
            report.append(f"## {vuln['package']['name']}@{vuln['package']['version']}")
            report.append(f"- ID: {vuln['vulnerability'].get('id', 'Unknown')}")
            report.append(f"- Severity: {vuln['vulnerability'].get('severity', 'Unknown')}")
            report.append("")
        return "\n".join(report)
    return str(vulnerabilities)

if __name__ == '__main__':
    main()