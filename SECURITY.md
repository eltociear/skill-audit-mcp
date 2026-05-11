# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `skill-audit-mcp` itself (the scanner, the GitHub Action, or the MCP server transport), please report it privately rather than opening a public issue.

### Preferred channel

**GitHub private security advisory:**
https://github.com/eltociear/skill-audit-mcp/security/advisories/new

### Alternate channel

Email: `eltociear@gmail.com` with subject `[skill-audit-mcp security]`. PGP available on request.

### What to include

- A clear description of the vulnerability
- Steps to reproduce (a minimal proof-of-concept is ideal)
- Affected version(s) and platform(s)
- Suggested mitigation if you have one

## Response timeline

| Step | Target |
|------|--------|
| Initial acknowledgement | 48 hours |
| Triage & severity assignment | 7 days |
| Fix in `main` | 14 days for HIGH/CRITICAL, 30 days for MEDIUM/LOW |
| Coordinated disclosure | Mutually agreed, default 90 days |

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | ✅ |
| < 1.0 | ❌ |

## Out of scope

- Findings produced *by* skill-audit-mcp in third-party code — those should be reported to the affected project, not here.
- DoS via deliberately crafted huge inputs (the scanner has bounded memory; if you find an unbounded path, that's in scope).
- Issues in transitive dependencies — skill-audit-mcp has zero runtime dependencies, so this should not apply.

## Public bug bounty

We do not currently run a paid bug bounty program. We do credit reporters in release notes for accepted findings.

## Related

- **Found vulnerabilities in OTHER MCP servers using skill-audit-mcp?** Report them via [huntr.com](https://huntr.com) (MCP servers are in scope) or directly to the affected repo's security policy.
- **Need an audit of your own MCP server / skill files?** Use the hosted x402 API: `POST https://x402.bankr.bot/0x130c617c8f636cad965ed57ca2164ee4e39ac6dd/security-audit` with `{content}` or `{url}` body. $0.01 USDC per scan, free tier 1,000 scans/month.
