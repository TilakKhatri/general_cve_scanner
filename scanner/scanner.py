# scanner/scanner.py
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from .cve_checker import CVEChecker
from .report_generator import generate_report

class ProjectScanner:
    def scan(self, project_path):
        # Implementation from previous example
        pass

def main():
    parser = argparse.ArgumentParser(description="CVE Scanner for CI/CD pipelines")
    parser.add_argument('--path', default='.', help='Project directory to scan')
    parser.add_argument('--format', default='markdown', 
                       choices=['markdown', 'json', 'sarif'],
                       help='Output format')
    parser.add_argument('--output', default='/output/cve-report.md',
                       help='Output file path')
    
    args = parser.parse_args()
    
    scanner = ProjectScanner()
    checker = CVEChecker()
    
    results = scanner.scan(args.path)
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
    
    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    if vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()