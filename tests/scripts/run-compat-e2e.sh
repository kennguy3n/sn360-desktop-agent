#!/bin/bash
# E2E compatibility test against Wazuh 4.7.x.
#
# This is a thin wrapper around `run-e2e.sh` that points the standard
# 14-assertion harness at an older Wazuh manager image
# (`tests/docker-compose-v4.7.yml`) instead of the canonical 4.9.2
# deployment. The agent's claim of "Wazuh 4.x compatible" is only
# meaningful if we exercise at least one manager release outside the
# current baseline, and the oldest supported 4.x minor is what the
# proposal (§ 13) flags as the most likely regression surface when
# the server protocol changes.
#
# Nothing in this script touches docker state that run-e2e.sh wouldn't —
# the compat compose file uses its own named volumes so it can run
# alongside the 4.9.2 suite without interference.
#
# Usage:
#   bash tests/scripts/run-compat-e2e.sh
#
# Override the compose file (e.g. to pin a different 4.x minor):
#   E2E_COMPOSE_FILE=tests/docker-compose-v4.7.yml bash tests/scripts/run-e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

export E2E_COMPOSE_FILE="${E2E_COMPOSE_FILE:-tests/docker-compose-v4.7.yml}"

echo "==> Running E2E compatibility suite against $E2E_COMPOSE_FILE"
exec bash "$REPO_ROOT/tests/scripts/run-e2e.sh"
