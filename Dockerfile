FROM python:3.12-alpine

LABEL org.opencontainers.image.title="skill-audit-mcp"
LABEL org.opencontainers.image.description="Static security scanner for MCP servers, AI agent skills, and plugins. 68 attack patterns across 4 severity levels."
LABEL org.opencontainers.image.source="https://github.com/eltociear/skill-audit-mcp"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY scanner.py cli.py ./

# Default entry: pass arguments through to the CLI.
# Example: docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 --path /work --min-severity MEDIUM
ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["--help"]
