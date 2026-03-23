#!/usr/bin/env bash
# Install repository git hooks into .git/hooks (local only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOKS_DIR="$ROOT/.git/hooks"
if [ ! -d "$HOOKS_DIR" ]; then
  echo "No .git/hooks directory found. Are you in a git repo?" >&2
  exit 1
fi
cp "$ROOT/scripts/pre-commit" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"
echo "Installed pre-commit hook to .git/hooks/pre-commit"
