#!/bin/bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
if [[ ${FROSTKEEP_STRICT_CHECKS:-0} == 1 ]]; then
  for tool in rclone shellcheck gitleaks; do
    command -v "$tool" >/dev/null || { echo "Required check tool missing: $tool" >&2; exit 1; }
  done
fi
python3 -m unittest discover -s tests -v
python3 scripts/release.py --check --workspace
for file in scripts/*.sh scripts/frostkeep scripts/glacier-status; do
  bash -n "$file"
done
if command -v shellcheck >/dev/null; then
  shellcheck scripts/*.sh scripts/frostkeep scripts/glacier-status
else
  echo "shellcheck not installed; syntax checks only" >&2
fi
if command -v gitleaks >/dev/null; then
  gitleaks dir . --redact --no-banner --max-archive-depth 0 --max-decode-depth 5
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    gitleaks git . --redact --no-banner --max-archive-depth 0 --max-decode-depth 5 --log-opts=--all
  fi
fi
