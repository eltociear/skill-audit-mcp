#!/usr/bin/env bash
# Keep replicate/scanner.py in sync with the canonical ../scanner.py.
# Cog's build context is the cog.yaml directory, so we cannot reference
# files in the parent. Run this whenever scanner.py changes upstream.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$DIR/../scanner.py" "$DIR/scanner.py"
echo "synced: $DIR/scanner.py <- ../scanner.py"
