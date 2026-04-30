#!/usr/bin/env python3
"""
skill-audit MCP Server v1.0.0
Detects malicious patterns in agent skill files.

Zero dependencies. Single file. Python 3.6+.
MCP protocol (JSON-RPC 2.0 over stdio).

Usage:
  Add to .mcp.json:
  {
    "skill-audit": {
      "type": "stdio",
      "command": "python3",
      "args": ["mcp_servers/skill-audit/server.py"]
    }
  }
"""

import sys
import json
import re
import os

VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "skill-audit"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Detection Patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PATTERNS = {
    "critical": [
        {
            "id": "download_execute",
            "name": "Download & Execute",
            "desc": "Downloads external file and executes/installs it",
            "regexes": [
                r"curl\s+[^\s]+\s*\|\s*(?:sh|bash|python|node)",
                r"curl\s+-[a-zA-Z]*o\s+",
                r"wget\s+-[a-zA-Z]*O\s+",
                r"wget\s+[^\s]+\s*&&\s*(?:chmod|bash|sh|python)",
                r"eval\s*\(\s*(?:fetch|require|import)",
                r"(?:sh|bash|python|node)\s*<\s*\(",
                r"curl\b.*\binstall\b",
            ],
        },
        {
            "id": "credential_exfil",
            "name": "Credential Exfiltration",
            "desc": "Sends credentials/keys to external service",
            "regexes": [
                r"(?:send|post|upload|transmit|forward)\b.*\b(?:api[_-]?key|token|password|secret|credential|private[_-]?key)\b.*\b(?:to|via|through|at)\b",
                r"(?:api[_-]?key|token|password|secret|private[_-]?key)\b.*\b(?:send|post|upload|transmit|forward)\b",
                r"exfiltrat",
            ],
        },
        {
            "id": "key_generation",
            "name": "Cryptographic Key Generation",
            "desc": "Requests generation of cryptographic keys (identity hijack vector)",
            "regexes": [
                r"generate\s+(?:a\s+)?(?:PGP|GPG|SSH|RSA|ECDSA|ed25519)\b.*\bkey\b",
                r"(?:PGP|GPG|SSH)\s+key\b.*\bgenerat",
                r"create\s+.*\b(?:private|signing)\s+key\b",
                r"gpg\s+--(?:gen-key|generate-key|full-generate-key)",
                r"ssh-keygen\b",
            ],
        },
        {
            "id": "sensitive_dir_write",
            "name": "Sensitive Directory Write",
            "desc": "Writes files to sensitive system directories",
            "regexes": [
                r"(?:mv|cp|write|save|install|tee|cat\s*>)\s+.*~/\.(?:ssh|gnupg|gpg|aws|kube|docker|npmrc)",
                r"(?:mv|cp|write|save|install|tee|cat\s*>)\s+.*/\.(?:ssh|gnupg|aws)/",
                r"(?:mv|cp)\s+\S+\s+~/\.",
            ],
        },
        {
            "id": "seed_phrase_harvest",
            "name": "Seed Phrase / Private Key Harvest",
            "desc": "Extracts wallet seed phrases, mnemonics, or private keys",
            "regexes": [
                r"(?:send|share|provide|enter|input|paste|type|give)\b.*\b(?:seed\s+phrase|mnemonic|recovery\s+phrase|private\s+key|secret\s+key)",
                r"(?:seed\s+phrase|mnemonic|recovery\s+phrase|private\s+key)\b.*\b(?:send|share|provide|post|upload)",
            ],
        },
    ],
    "high": [
        {
            "id": "external_download",
            "name": "External File Download",
            "desc": "Downloads files from unknown external URLs",
            "regexes": [
                r"curl\s+(?:-[a-zA-Z]+\s+)*https?://",
                r"wget\s+(?:-[a-zA-Z]+\s+)*https?://",
                r"fetch\s*\(\s*[\"']https?://",
                r"download\b.*\bfrom\s+https?://",
            ],
        },
        {
            "id": "skill_install",
            "name": "Skill/Plugin Installation",
            "desc": "Installs downloaded content as agent skill or plugin",
            "regexes": [
                r"(?:mv|cp|install|add|save|write)\b.*\b(?:skill|plugin|extension)s?(?:/|\s+dir|\s+fold)",
                r"\.openclaw/workspace/skills",
                r"skills?\s+(?:directory|folder|path)",
                r"(?:add|install)\s+(?:to|into)\s+.*\bskills?\b",
            ],
        },
        {
            "id": "code_execution",
            "name": "Arbitrary Code Execution",
            "desc": "Executes arbitrary or dynamically-loaded code",
            "regexes": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"subprocess\.\w+\(",
                r"os\.system\s*\(",
                r"npm\s+install\s+-g\s+",
                r"pip3?\s+install\s+(?!-r\b)\S",
                r"npx\s+\S+",
            ],
        },
        {
            "id": "auth_bypass",
            "name": "Security Bypass",
            "desc": "Bypasses authentication or security mechanisms",
            "regexes": [
                r"(?:bypass|skip|ignore|disable|override)\s+(?:auth|security|verification|validation|check|hook)",
                r"--no-verify\b",
                r"--insecure\b",
                r"verify\s*=\s*False",
            ],
        },
        {
            "id": "identity_impersonation",
            "name": "Identity Impersonation",
            "desc": "Sets up identity claiming to be the agent or user",
            "regexes": [
                r"your\s+(?:PGP|GPG)\s+key\s+is\s+your\s+identity",
                r"(?:set|change|update)\s+.*\b(?:display\s+name|username|identity)\b",
                r"register\s+(?:as|with)\s+(?:your|this)\s+(?:name|identity)",
            ],
        },
    ],
    "medium": [
        {
            "id": "unknown_api",
            "name": "Unknown API Endpoint",
            "desc": "Calls to unrecognized external APIs",
            "regexes": [
                r"(?:POST|PUT|PATCH|DELETE)\s+https?://(?!(?:api\.github\.com|localhost|127\.0\.0\.1))\S+",
            ],
        },
        {
            "id": "data_collection",
            "name": "Data Collection",
            "desc": "Collects or aggregates agent/user data",
            "regexes": [
                r"collect\s+(?:user|agent|personal)\s+(?:data|info|information)",
                r"(?:log|record|track|monitor)\s+(?:all\s+)?(?:user|agent)\s+(?:activity|actions|behavior|requests)",
            ],
        },
        {
            "id": "privilege_escalation",
            "name": "Privilege Escalation",
            "desc": "Requests elevated system permissions",
            "regexes": [
                r"\bsudo\b",
                r"chmod\s+[0-7]*7[0-7]*\s",
                r"(?:request|need|require|grant)\s+(?:full|complete|admin|root|elevated)\s+(?:access|permission|privilege)",
            ],
        },
        {
            "id": "obfuscation",
            "name": "Content Obfuscation",
            "desc": "Contains obfuscated or encoded payloads",
            "regexes": [
                r"base64\s+(?:decode|encode|--decode|-d)\b",
                r"\batob\s*\(",
                r"\bbtoa\s*\(",
                r"(?:\\x[0-9a-fA-F]{2}){4,}",
                r"(?:\\u[0-9a-fA-F]{4}){4,}",
                r"String\.fromCharCode\s*\(",
            ],
        },
        {
            "id": "prompt_injection",
            "name": "Prompt Injection Markers",
            "desc": "Contains patterns commonly used in prompt injection",
            "regexes": [
                r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)",
                r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|my)",
                r"system\s*:\s*you\s+(?:are|must|should|will)",
                r"<\s*(?:system|admin|root)\s*>",
            ],
        },
    ],
    "low": [
        {
            "id": "external_urls",
            "name": "External URL Reference",
            "desc": "References external URLs (review for legitimacy)",
            "regexes": [
                r"https?://(?!(?:github\.com|docs\.|developer\.|localhost|127\.0\.0\.1|.*\.md))\S{10,}",
            ],
        },
        {
            "id": "filesystem_broad",
            "name": "Broad File System Access",
            "desc": "References file paths outside working directory",
            "regexes": [
                r"(?:read|write|access|modify|delete)\b.*\b(?:/etc/|/usr/|/var/|/tmp/)",
                r"~/.(?!config\b|local\b)",
            ],
        },
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scanner Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan(content):
    """Scan content for malicious patterns. Returns audit result dict."""
    findings = []
    lines = content.split("\n")
    seen = set()

    for severity, pattern_groups in PATTERNS.items():
        for pg in pattern_groups:
            for regex in pg["regexes"]:
                try:
                    compiled = re.compile(regex, re.IGNORECASE)
                except re.error:
                    continue
                for line_num, line in enumerate(lines, 1):
                    for match in compiled.finditer(line):
                        key = (pg["id"], line_num)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "severity": severity.upper(),
                            "id": pg["id"],
                            "name": pg["name"],
                            "description": pg["desc"],
                            "line": line_num,
                            "matched": match.group(0)[:120],
                            "context": line.strip()[:200],
                        })

    # Score
    total = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f["severity"].lower()
        total += SEVERITY_SCORE.get(s, 0)
        counts[f["severity"]] += 1
    total = min(total, 100)

    if total >= 76:
        level = "CRITICAL"
    elif total >= 51:
        level = "HIGH"
    elif total >= 26:
        level = "MEDIUM"
    elif total >= 11:
        level = "LOW"
    else:
        level = "SAFE"

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 99), f["line"]))

    parts = []
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[s]:
            parts.append("%d %s" % (counts[s], s))

    return {
        "risk_score": total,
        "risk_level": level,
        "findings": findings,
        "summary": ", ".join(parts) if parts else "No issues found",
        "total_findings": len(findings),
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MCP Tool Definitions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOOLS = [
    {
        "name": "audit",
        "description": (
            "Audit text content for malicious patterns. "
            "Paste skill/plugin content to get a risk score and detailed findings. "
            "Detects: download-and-execute, credential exfiltration, key generation, "
            "prompt injection, privilege escalation, and more."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "The text content to audit (skill file, prompt, instruction, etc.)",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "audit_file",
        "description": (
            "Audit a local file for malicious patterns. "
            "Provide an absolute file path to scan."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to audit",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "audit_directory",
        "description": (
            "Scan a directory for skill/markdown files and audit each one. "
            "Returns per-file risk scores and an aggregate summary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the directory to scan",
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated file extensions to scan (default: md,txt,yaml,yml,json)",
                    "default": "md,txt,yaml,yml,json",
                },
            },
            "required": ["path"],
        },
    },
]


def format_report(result):
    """Format scan result as human-readable text."""
    lines = []
    risk = result["risk_level"]
    score = result["risk_score"]

    icons = {"CRITICAL": "☠", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "SAFE": "✅"}
    icon = icons.get(risk, "?")

    lines.append("%s RISK: %s (score %d/100)" % (icon, risk, score))
    lines.append("  %s" % result["summary"])
    lines.append("")

    if result["findings"]:
        lines.append("FINDINGS:")
        for f in result["findings"]:
            sev_icon = {"CRITICAL": "☠", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], " ")
            lines.append("  %s [%s] %s (line %d)" % (sev_icon, f["severity"], f["name"], f["line"]))
            lines.append("    %s" % f["description"])
            lines.append("    match: %s" % f["matched"])
            lines.append("    > %s" % f["context"])
            lines.append("")
    else:
        lines.append("No malicious patterns detected.")

    return "\n".join(lines)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool Handlers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def handle_audit(args):
    content = args.get("content", "")
    if not content.strip():
        return {"isError": True, "content": [{"type": "text", "text": "Error: empty content"}]}
    result = scan(content)
    report = format_report(result)
    return {"content": [{"type": "text", "text": report}]}


def handle_audit_file(args):
    path = args.get("path", "")
    if not path:
        return {"isError": True, "content": [{"type": "text", "text": "Error: path required"}]}
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        return {"isError": True, "content": [{"type": "text", "text": "Error: file not found: %s" % path}]}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": "Error reading file: %s" % e}]}

    result = scan(content)
    report = "FILE: %s\n\n%s" % (path, format_report(result))
    return {"content": [{"type": "text", "text": report}]}


def handle_audit_directory(args):
    path = args.get("path", "")
    exts = args.get("extensions", "md,txt,yaml,yml,json")
    if not path:
        return {"isError": True, "content": [{"type": "text", "text": "Error: path required"}]}
    path = os.path.expanduser(path)
    if not os.path.isdir(path):
        return {"isError": True, "content": [{"type": "text", "text": "Error: directory not found: %s" % path}]}

    ext_set = set("." + e.strip().lstrip(".") for e in exts.split(","))
    results = []
    max_risk = 0
    total_findings = 0

    for root, dirs, files in os.walk(path):
        # Skip hidden dirs and node_modules
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in sorted(files):
            _, ext = os.path.splitext(fname)
            if ext.lower() not in ext_set:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            result = scan(content)
            if result["total_findings"] > 0:
                results.append((fpath, result))
                max_risk = max(max_risk, result["risk_score"])
                total_findings += result["total_findings"]

    if not results:
        report = "✅ CLEAN: No issues found in %s" % path
    else:
        lines = ["DIRECTORY SCAN: %s" % path]
        lines.append("Files with findings: %d | Total findings: %d | Max risk score: %d" % (
            len(results), total_findings, max_risk))
        lines.append("")
        for fpath, result in sorted(results, key=lambda x: -x[1]["risk_score"]):
            rel = os.path.relpath(fpath, path)
            icons = {"CRITICAL": "☠", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "SAFE": "✅"}
            icon = icons.get(result["risk_level"], " ")
            lines.append("  %s %s — %s (score %d)" % (icon, rel, result["risk_level"], result["risk_score"]))
            for f in result["findings"][:3]:
                lines.append("    [%s] %s (line %d)" % (f["severity"], f["name"], f["line"]))
            if len(result["findings"]) > 3:
                lines.append("    ... +%d more" % (len(result["findings"]) - 3))
        report = "\n".join(lines)

    return {"content": [{"type": "text", "text": report}]}


TOOL_HANDLERS = {
    "audit": handle_audit,
    "audit_file": handle_audit_file,
    "audit_directory": handle_audit_directory,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MCP Protocol (JSON-RPC 2.0 over stdio)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def make_response(id, result):
    return {"jsonrpc": "2.0", "id": id, "result": result}


def make_error(id, code, message):
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def handle_message(msg):
    method = msg.get("method", "")
    id = msg.get("id")
    params = msg.get("params", {})

    # Notifications (no id) — no response needed
    if id is None:
        return None

    if method == "initialize":
        return make_response(id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": VERSION},
        })

    elif method == "ping":
        return make_response(id, {})

    elif method == "tools/list":
        return make_response(id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return make_response(id, {
                "isError": True,
                "content": [{"type": "text", "text": "Unknown tool: %s" % tool_name}],
            })
        try:
            result = handler(arguments)
        except Exception as e:
            result = {"isError": True, "content": [{"type": "text", "text": "Error: %s" % e}]}
        return make_response(id, result)

    else:
        return make_error(id, -32601, "Method not found: %s" % method)


def main():
    """Main loop: read JSON-RPC messages from stdin, write responses to stdout."""
    buf = ""
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break
        if not line:
            break
        buf += line
        # Try to parse complete JSON objects
        buf = buf.strip()
        if not buf:
            continue
        try:
            msg = json.loads(buf)
            buf = ""
        except json.JSONDecodeError:
            # Incomplete message, keep reading
            continue

        response = handle_message(msg)
        if response is not None:
            out = json.dumps(response)
            sys.stdout.write(out + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
