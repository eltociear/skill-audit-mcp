#!/usr/bin/env python3
"""
mcp-security-audit CLI — Scan files for malicious patterns.

Usage:
  python3 cli.py --path ./server.py                    # Scan single file
  python3 cli.py --path ./mcp-servers/                 # Scan directory
  python3 cli.py --path . --severity medium            # Filter by severity
  python3 cli.py --path . --fail-on HIGH               # Exit 1 if HIGH+
  python3 cli.py --path . --sarif results.sarif        # SARIF output
  python3 cli.py --path . --json                       # JSON output
"""

import argparse
import json
import os
import sys
import glob as globmod

# Import scanner engine (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import scan, PATTERNS, SEVERITY_SCORE

SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
    '.sh', '.bash', '.zsh',
    '.md', '.txt', '.yaml', '.yml', '.json', '.toml',
    '.rb', '.go', '.rs', '.java', '.kt', '.swift',
    '.skill', '.prompt',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'SAFE': 4}


def scan_file(filepath):
    """Scan a single file. Returns (filepath, result) or None."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read(1_000_000)  # 1MB limit
    except (IOError, OSError):
        return None

    result = scan(content)
    result['file'] = filepath
    return result


def scan_directory(dirpath, min_severity='low'):
    """Scan all eligible files in a directory. Returns list of results."""
    results = []
    min_sev_idx = SEVERITY_ORDER.get(min_severity.upper(), 3)

    for root, dirs, files in os.walk(dirpath):
        # Skip hidden dirs and common non-code dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
            'node_modules', '__pycache__', '.git', 'venv', '.venv', 'dist', 'build'
        }]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            filepath = os.path.join(root, fname)
            result = scan_file(filepath)
            if result and result['total_findings'] > 0:
                # Filter findings by severity
                filtered = [f for f in result['findings']
                           if SEVERITY_ORDER.get(f['severity'], 3) <= min_sev_idx]
                if filtered:
                    result['findings'] = filtered
                    result['total_findings'] = len(filtered)
                    results.append(result)

    return results


def to_sarif(results):
    """Convert results to SARIF format for GitHub Code Scanning."""
    rules = []
    rule_ids = set()
    sarif_results = []

    for result in results:
        for finding in result.get('findings', []):
            rule_id = finding.get('id', 'unknown')
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    'id': rule_id,
                    'name': finding.get('name', ''),
                    'shortDescription': {'text': finding.get('name', '')},
                    'fullDescription': {'text': finding.get('description', '')},
                    'defaultConfiguration': {
                        'level': 'error' if finding['severity'] in ('CRITICAL', 'HIGH') else 'warning'
                    },
                })

            sarif_results.append({
                'ruleId': rule_id,
                'level': 'error' if finding['severity'] in ('CRITICAL', 'HIGH') else 'warning',
                'message': {'text': f"{finding['name']}: {finding.get('matched', '')[:80]}"},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': result.get('file', 'unknown')},
                        'region': {'startLine': finding.get('line', 1)},
                    }
                }],
            })

    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'mcp-security-audit',
                    'version': '1.0.0',
                    'informationUri': 'https://github.com/eltociear/mcp-security-audit',
                    'rules': rules,
                }
            },
            'results': sarif_results,
        }],
    }


def main():
    parser = argparse.ArgumentParser(description='MCP Security Audit — scan for malicious patterns')
    parser.add_argument('--path', default='.', help='File or directory to scan')
    parser.add_argument('--severity', default='low', help='Minimum severity (critical/high/medium/low)')
    parser.add_argument('--fail-on', default='HIGH', help='Exit 1 if risk meets/exceeds (SAFE/LOW/MEDIUM/HIGH/CRITICAL)')
    parser.add_argument('--sarif', default='', help='Write SARIF output to file')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--github-output', action='store_true', help='Write GitHub Actions outputs')
    args = parser.parse_args()

    target = args.path

    if os.path.isfile(target):
        results = [scan_file(target)]
        results = [r for r in results if r and r['total_findings'] > 0]
    elif os.path.isdir(target):
        results = scan_directory(target, args.severity)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(1)

    # Aggregate
    total_findings = sum(r['total_findings'] for r in results)
    max_score = max((r['risk_score'] for r in results), default=0)
    max_level = 'SAFE'
    for r in results:
        if SEVERITY_ORDER.get(r['risk_level'], 4) < SEVERITY_ORDER.get(max_level, 4):
            max_level = r['risk_level']

    # Output
    if args.json:
        print(json.dumps({
            'risk_score': max_score,
            'risk_level': max_level,
            'total_findings': total_findings,
            'files_scanned': len(results),
            'results': results,
        }, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  MCP Security Audit")
        print(f"{'='*60}")
        print(f"  Target: {target}")
        print(f"  Risk Score: {max_score}/100 ({max_level})")
        print(f"  Findings: {total_findings} across {len(results)} files")
        print(f"{'='*60}\n")

        for result in sorted(results, key=lambda r: -r['risk_score']):
            if result['total_findings'] == 0:
                continue
            print(f"  {result['file']} — {result['risk_level']} ({result['risk_score']}/100)")
            for f in result['findings'][:10]:
                print(f"    [{f['severity']}] {f['name']}: {f.get('matched', '')[:60]}")
                print(f"      Line {f['line']}: {f.get('context', '')[:80]}")
            print()

    # SARIF
    if args.sarif:
        sarif = to_sarif(results)
        with open(args.sarif, 'w') as f:
            json.dump(sarif, f, indent=2)
        print(f"SARIF written to {args.sarif}")

    # GitHub Actions outputs
    if args.github_output:
        output_file = os.environ.get('GITHUB_OUTPUT', '')
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"risk-score={max_score}\n")
                f.write(f"risk-level={max_level}\n")
                f.write(f"findings={total_findings}\n")

    # Fail check
    fail_level = args.fail_on.upper()
    if SEVERITY_ORDER.get(max_level, 4) <= SEVERITY_ORDER.get(fail_level, 1):
        sys.exit(1)


if __name__ == '__main__':
    main()
