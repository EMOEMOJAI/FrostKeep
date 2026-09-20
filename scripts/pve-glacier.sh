#!/bin/bash
# Compatibility entrypoint; configuration now lives in /etc/frostkeep/config.json.
set -euo pipefail
exec "$(dirname -- "$0")/frostkeep" backup "$@"
