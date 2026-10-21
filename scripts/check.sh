#!/bin/sh
# Single test entry point: ruff check, ruff format --check, pyright, pytest "$@".
set -eu
cd "$(dirname "$0")/.."

echo "=== check.sh: ruff check ==="
uv run --locked ruff check
echo "=== check.sh: ruff format ==="
uv run --locked ruff format --check
echo "=== check.sh: pyright ==="
uv run --locked pyright
echo "=== check.sh: pytest ==="
uv run --locked pytest "$@"
