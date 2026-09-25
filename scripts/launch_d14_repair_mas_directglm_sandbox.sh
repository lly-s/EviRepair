#!/usr/bin/env bash
set -Eeuo pipefail

# D14 uses the same sandbox launcher entrypoint as D13/D4.
# Point the bundle/prompt root at this D14-verified directory when invoking.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/launch_d4_analysismas_directglm_sandbox.sh" "$@"
