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
      "args": ["server.py"]
    }
  }
"""

import sys
import json
import re
import os

VERSION = "1.1.0"
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
            # Precision: bare `curl -o`/`wget -O` (download only, no execution) removed —
            # ubiquitous in install docs. Kept: forms that actually EXECUTE what they fetch.
            "regexes": [
                # Flags between the command and the pipe are the norm, not the exception:
                # `curl -fsSL https://get.docker.com | sudo sh` is the canonical form. The
                # earlier pattern allowed exactly ONE token between curl and the pipe and so
                # missed 6 of 8 real installer shapes, that one included. Measured, not guessed.
                r"curl\b[^|;\r\n]{0,300}\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:sh|bash|zsh|dash|ksh|python3?|node|perl|ruby)\b(?!\s+-[mc]\b)",
                r"wget\b[^|;\r\n]{0,300}\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:sh|bash|zsh|dash|ksh|python3?|node|perl|ruby)\b(?!\s+-[mc]\b)",
                r"wget\s+[^\s]+\s*&&\s*(?:chmod|bash|sh|python)",
                r"eval\s*\(\s*(?:fetch|require|import|atob)",
                r"(?:sh|bash|python|node)\s*<\s*\(\s*curl",
            ],
        },
        {
            "id": "credential_exfil",
            "name": "Credential Exfiltration",
            "desc": "Sends credentials/keys to external service",
            # Precision: require BOTH a credential noun AND an explicit external
            # destination (URL / webhook / email / bare domain) near a send verb, so a
            # benign sentence like "send the XSRF header" no longer trips it.
            "regexes": [
                r"(?:send|post|upload|transmit|forward|leak|exfiltrat)\w*\b.{0,60}?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|credential|private[_-]?key|seed|mnemonic)\b.{0,60}?(?:https?://|wss?://|@[\w.-]+|webhook|discord\.com/api|t\.me/|[a-z0-9-]+\.(?:com|net|io|xyz|ru|cn|sh|dev)\b)",
                r"\b(?:api[_-]?key|access[_-]?token|password|secret|private[_-]?key|mnemonic|seed\s+phrase)\b.{0,60}?\b(?:send|post|upload|transmit|forward|leak|exfiltrat)\w*\b.{0,60}?https?://",
                r"exfiltrat\w*\b.{0,40}(?:key|token|secret|credential|password)",
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
            # Precision: require an ownership word (your / the user's) so benign code like
            # `inputSchema: { properties … "private"… }` no longer trips it. Wallet seed/
            # mnemonic terms are specific enough to keep without ownership.
            "regexes": [
                r"(?:send|share|provide|enter|paste|type|give|reveal)\b.{0,40}\b(?:your|the\s+user'?s?)\b.{0,25}(?:seed\s+phrase|mnemonic|recovery\s+phrase|private\s+key|secret\s+key)",
                r"(?:seed\s+phrase|mnemonic|recovery\s+phrase)\b.{0,40}\b(?:send|share|provide|post|upload|paste|reveal)\b",
                r"\b(?:your|user'?s?)\s+(?:wallet\s+)?(?:seed\s+phrase|mnemonic|private\s+key)\b.{0,30}(?:https?://|@|paste|enter|share)",
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
            # Precision: these exec primitives are normal in ordinary source. They are
            # only scored HIGH when the SAME line also carries a dynamic-input signal
            # (see DYNAMIC_INPUT + scan()); otherwise they are reported as info context.
            # npx/pip/npm-install removed entirely — packaging, not code execution.
            "regexes": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"subprocess\.\w+\(",
                r"os\.system\s*\(",
                r"child_process",
                r"pickle\.loads?\s*\(",
                r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
            ],
        },
        {
            "id": "auth_bypass",
            "name": "Security Bypass",
            "desc": "Bypasses authentication or security mechanisms",
            # Precision: dropped bare "disable auth" — it matched documented dev config
            # toggles (e.g. `SOMA_MCP_NO_AUTH … Disable auth for loopback development`),
            # which are features, not attacks. Kept imperative bypass + code-level flags.
            "regexes": [
                r"(?:bypass|circumvent|defeat|turn\s+off)\s+(?:the\s+)?(?:auth\w*|security|verification|validation)",
                r"--no-verify\b",
                r"--insecure\b",
                r"verify\s*=\s*False\b",
                r"ssl[_-]?verify\s*[:=]\s*(?:false|0|none)",
                r"rejectUnauthorized\s*:\s*false",
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
        {
            "id": "prompt_injection",
            "name": "Prompt Injection Markers",
            "desc": "Contains patterns commonly used in prompt injection",
            # High-precision, definitive injection phrasing → scored HIGH.
            "regexes": [
                r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)",
                r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|my)",
                r"system\s*:\s*you\s+(?:are|must|should|will)",
                r"<\s*(?:system|admin|root)\s*>\s*you",
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
            # bare `sudo` removed — ubiquitous in install docs, not a signal by itself.
            "regexes": [
                r"chmod\s+[0-7]*7[0-7]*\s",
                r"(?:request|need|require|grant)\s+(?:full|complete|admin|root|elevated)\s+(?:access|permission|privilege)",
            ],
        },
        {
            "id": "obfuscation",
            "name": "Content Obfuscation",
            "desc": "Contains obfuscated or encoded payloads",
            # base64/atob/btoa words removed — common in legit encoding code. Kept: long
            # hex/unicode escape blobs and String.fromCharCode, which are real obfuscation.
            "regexes": [
                r"(?:\\x[0-9a-fA-F]{2}){6,}",
                r"(?:\\u[0-9a-fA-F]{4}){6,}",
                r"String\.fromCharCode\s*\((?:\s*\d+\s*,){4,}",
                r"eval\s*\(\s*(?:atob|Buffer\.from|base64)",
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

# ── Precision layer (added 2026-07-26) ────────────────────────────────────────
# The pattern set was tuned for natural-language skill manifests; run against real
# source it over-flagged (a benign file could hit 200+ external-URL "findings" and
# score CRITICAL). These pattern ids are context, not risk: they are still reported,
# but under `info` (score 0) so they never inflate the risk score or the CRIT/HIGH/
# MED/LOW counts. Measured on 10 reputable repos: external_urls alone was 249/260
# false positives.
INFO_IDS = {
    "external_urls", "filesystem_broad", "unknown_api",
    "external_download", "data_collection",
    # skill/plugin install is the NORMAL use case for MCP servers/agent skills — legit
    # "claude plugin install", "installs to your skills directory" docs tripped it on
    # every real plugin repo. The genuinely-malicious surreptitious self-install is caught
    # by download_execute + sensitive_dir_write instead. Context, not risk.
    "skill_install",
}
# code_execution primitives (eval/exec/subprocess/os.system/…) are only a real HIGH
# finding when the same line also carries a dynamic-input source; a literal call is
# ordinary code and demoted to info.
DYNAMIC_INPUT = re.compile(
    r"input\s*\(|\bargv\b|\bstdin\b|request\.|req\.|params|os\.environ|getenv|"
    r"\bfetch\b|urlopen|requests\.(?:get|post)|\.read\(\)|user[_-]?input|"
    r"\bf[\"']|\.format\s*\(|%\s*[\(\w]|\+\s*\w",
    re.IGNORECASE,
)
CODE_EXEC_ID = "code_execution"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scanner Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan(content):
    """Scan content for malicious patterns. Returns audit result dict."""
    findings = []
    info = []
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
                        item = {
                            "severity": severity.upper(),
                            "id": pg["id"],
                            "name": pg["name"],
                            "description": pg["desc"],
                            "line": line_num,
                            "matched": match.group(0)[:120],
                            "context": line.strip()[:200],
                        }
                        # Precision routing: informational patterns, and code-exec
                        # primitives without a dynamic-input signal on the line, are
                        # context (score 0) not scored findings.
                        is_info = pg["id"] in INFO_IDS
                        if pg["id"] == CODE_EXEC_ID and not DYNAMIC_INPUT.search(line):
                            is_info = True
                        if is_info:
                            item["severity"] = "INFO"
                            info.append(item)
                        else:
                            findings.append(item)

    # Score (info items contribute 0 and are reported separately)
    total = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f["severity"].lower()
        total += SEVERITY_SCORE.get(s, 0)
        counts[f["severity"]] += 1
    total = min(total, 100)

    # Level is driven by the HIGHEST-severity real finding present (one credential-exfil
    # or pipe-to-shell is CRITICAL regardless of count), with risk_score as magnitude.
    # This replaces the additive-threshold scheme that only worked because benign noise
    # used to inflate every score.
    if counts["CRITICAL"]:
        level = "CRITICAL"
    elif counts["HIGH"]:
        level = "HIGH"
    elif counts["MEDIUM"]:
        level = "MEDIUM"
    elif counts["LOW"]:
        level = "LOW"
    else:
        level = "SAFE"

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 99), f["line"]))

    parts = []
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[s]:
            parts.append("%d %s" % (counts[s], s))

    info.sort(key=lambda f: f["line"])
    return {
        "risk_score": total,
        "risk_level": level,
        "findings": findings,
        "info": info,
        "summary": ", ".join(parts) if parts else "No issues found",
        "total_findings": len(findings),
        "info_count": len(info),
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


# ── File context ──────────────────────────────────────────────────────────────
# Added 2026-08-18. This is the PAID surface — buyers call it over MCP and x402 — and it was
# reporting a `curl | sh` in an install doc and a `subprocess.run(` in a test harness at the
# same weight as production code. Re-scanning 18 repositories that an earlier database of ours
# had named as critically vulnerable, EVERY surviving finding was one of those two things.
# That is how a healthy repository comes back reading like "RCE".
#
# apify-actor/src/scanner.py already skipped test and example paths and the behaviour never
# propagated here. This labels rather than skips: a `curl | sh` in an install doc is a real
# supply-chain concern for whoever follows it, it is simply not a flaw in the server.
_CTX_TEST_MARKERS = ("/test/", "/tests/", "/spec/", "/__tests__/", "/fixtures/", "/e2e/",
                     "/testdata/", "/examples/")
_CTX_DOC_EXTS = {".md", ".txt", ".rst"}


def file_context(path):
    """production | test | documentation — from the path alone."""
    low = "/" + path.replace(chr(92), "/").lstrip("/").lower()
    base = low.rsplit("/", 1)[-1]
    ext = os.path.splitext(base)[1]
    if ext in _CTX_DOC_EXTS:
        return "documentation"
    if any(m in low for m in _CTX_TEST_MARKERS):
        return "test"
    if base.startswith("test_") or base.endswith(("_test.py", ".test.js", ".test.ts",
                                                  ".spec.js", ".spec.ts")):
        return "test"
    return "production"


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
    # 2026-08-18: the default was md,txt,yaml,yml,json — no code extension at all. Pointed at a
    # repository containing os.system("mv ~/.ssh/keys.json /tmp/x") this returned "CLEAN", because
    # it never opened a .py file. Aligned with scripts/scan_cli.py _DEFAULT_EXTS. Broadening the
    # net is only safe because findings now carry file_context(), so the READMEs and test harnesses
    # it now reaches are labelled instead of counted as server flaws.
    exts = args.get("extensions", "md,txt,yaml,yml,json,py,js,ts,sh")
    if not path:
        return {"isError": True, "content": [{"type": "text", "text": "Error: path required"}]}
    path = os.path.expanduser(path)
    if not os.path.isdir(path):
        return {"isError": True, "content": [{"type": "text", "text": "Error: directory not found: %s" % path}]}

    ext_set = set("." + e.strip().lstrip(".") for e in exts.split(","))
    results = []
    max_risk = 0
    total_findings = 0
    nonprod_findings = 0
    files_seen = 0
    files_read = 0

    for root, dirs, files in os.walk(path):
        # Skip hidden dirs and node_modules
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in sorted(files):
            files_seen += 1
            _, ext = os.path.splitext(fname)
            if ext.lower() not in ext_set:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            files_read += 1
            result = scan(content)
            if result["total_findings"] > 0:
                ctx = file_context(os.path.relpath(fpath, path))
                result["file_context"] = ctx
                results.append((fpath, result))
                if ctx == "production":
                    max_risk = max(max_risk, result["risk_score"])
                    total_findings += result["total_findings"]
                else:
                    nonprod_findings += result["total_findings"]

    if not results:
        # A clean verdict has to say what it read. "CLEAN" over zero opened files is not a result,
        # it is a failed scan wearing a result's clothes.
        if files_read == 0:
            report = ("⚠ NOT SCANNED: %s contains no files matching %s (%d file(s) present, all "
                      "skipped). This is not a clean bill of health — widen `extensions` and re-run."
                      % (path, exts, files_seen))
        else:
            report = ("✅ CLEAN: no findings in %d file(s) read from %s (extensions: %s; %d other "
                      "file(s) skipped as out of scope)" % (files_read, path, exts,
                                                            files_seen - files_read))
    else:
        lines = ["DIRECTORY SCAN: %s" % path,
                 "Read %d of %d file(s) (extensions: %s)" % (files_read, files_seen, exts)]
        prod = [r for r in results if r[1].get("file_context", "production") == "production"]
        lines.append("Files with findings: %d | Findings IN THE SERVER: %d | Max risk score: %d" % (
            len(prod), total_findings, max_risk))
        if nonprod_findings:
            lines.append("Plus %d finding(s) in documentation or test files, listed below and "
                         "tagged. Those are not flaws in the server." % nonprod_findings)
        lines.append("")
        for fpath, result in sorted(results, key=lambda x: -x[1]["risk_score"]):
            rel = os.path.relpath(fpath, path)
            icons = {"CRITICAL": "☠", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "SAFE": "✅"}
            icon = icons.get(result["risk_level"], " ")
            ctx = result.get("file_context", "production")
            tag = "" if ctx == "production" else "  <%s>" % ctx
            lines.append("  %s %s — %s (score %d)%s" % (icon, rel, result["risk_level"],
                                                        result["risk_score"], tag))
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
