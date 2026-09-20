#!/bin/bash
# Optional local hook. Receives a bounded JSON summary on stdin.
# Replace this with your notification integration outside the source repository.
set -euo pipefail
exec logger --tag frostkeep
