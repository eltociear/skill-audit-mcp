"""Cog Predictor for skill-audit-mcp on Replicate.

Wraps the existing scanner.py (zero-dependency Python static security scanner
for MCP server code) so it runs as a paid HTTP API on Replicate.

Build & push:
  cd replicate/
  cog login
  cog push r8.im/eltociear/skill-audit-mcp
"""

from cog import BasePredictor, Input
from typing import Any
import importlib.util
import os
import urllib.request


class Predictor(BasePredictor):
    def setup(self) -> None:
        scanner_path = os.path.join(os.path.dirname(__file__), "..", "scanner.py")
        scanner_path = os.path.abspath(scanner_path)
        spec = importlib.util.spec_from_file_location("scanner", scanner_path)
        self.scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.scanner)

    def predict(
        self,
        content: str = Input(
            description="MCP server / agent skill source code to scan. Leave empty if using `url` instead.",
            default="",
        ),
        url: str = Input(
            description="URL to fetch and scan. Used only if `content` is empty.",
            default="",
        ),
        max_bytes: int = Input(
            description="Maximum bytes to read from `url` (truncated, default 200000).",
            default=200000,
            ge=1024,
            le=2_000_000,
        ),
    ) -> Any:
        if not content and not url:
            return {"error": "Provide either `content` or `url`."}
        if not content and url:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "skill-audit-mcp/1.0 (+https://github.com/eltociear/skill-audit-mcp)"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                content = r.read(max_bytes).decode("utf-8", errors="replace")
        return self.scanner.scan(content)
