# LLM Install Instructions — skill-audit-mcp

This file gives LLM-driven coding agents (Cline, Goose, Cursor, Claude Code) explicit instructions for installing `skill-audit-mcp` as an MCP server.

## What this server does

Static security scanner. Scans MCP server code, AI agent skill files, and plugins for **68 attack patterns** across 4 severity levels:

- **CRITICAL** — credential exfiltration, seed-phrase harvest, download-and-execute
- **HIGH** — arbitrary code execution, auth bypass, identity impersonation
- **MEDIUM** — prompt injection, obfuscation, privilege escalation
- **LOW** — external URL references, broad filesystem access

Output: structured JSON findings (severity, line numbers, CWE references) or SARIF 2.1.0 for GitHub Code Scanning.

## Quick install (preferred path)

The server is a single Python file with zero dependencies. The fastest install:

```bash
# 1. Clone or curl the scanner
curl -sL https://raw.githubusercontent.com/eltociear/skill-audit-mcp/main/scanner.py -o /tmp/skill-audit-scanner.py

# 2. Register as MCP server in your client config
```

### Client configuration

#### Claude Desktop / Cline (`mcp_settings.json` or `claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "skill-audit": {
      "command": "python3",
      "args": ["/tmp/skill-audit-scanner.py", "--mcp"],
      "env": {}
    }
  }
}
```

#### Goose (`~/.config/goose/config.yaml`)

```yaml
extensions:
  skill-audit:
    enabled: true
    type: stdio
    cmd: python3
    args:
      - /tmp/skill-audit-scanner.py
      - --mcp
    timeout: 120
```

#### Cursor / Windsurf

Add the same JSON config under `mcp.servers` in the editor settings.

## Tools exposed

| Tool | Purpose | Input |
|------|---------|-------|
| `audit` | Scan a code snippet / text content | `{ content: string, language?: string }` |
| `audit_file` | Scan a local file by path | `{ path: string }` |
| `audit_directory` | Recursively scan a directory | `{ path: string, max_files?: number }` |

Each tool returns a structured report including:
- `findings[]` — array of matches with severity, line numbers, pattern ID, CWE reference
- `summary` — counts by severity
- `risk_score` — 0–100 composite

## System requirements

- Python 3.6+ (no other dependencies)
- macOS / Linux / Windows
- Approximate memory: <50 MB
- No network access required for scanning (offline-safe)

## Verification

After install, ask your agent:

> "Use skill-audit to scan the file at /path/to/some-mcp-server.py for security issues."

You should see a JSON report with `findings` and `summary` keys.

## Also available as

- **GitHub Action**: `uses: eltociear/skill-audit-mcp@v1` — drop-in CI/CD scanner
- **Hosted x402 API**: `https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit` — pay-per-scan via USDC micropayments
- **Glama listing**: https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp

## License

MIT. See `LICENSE`.
