#!/bin/bash
# Focused FIM burst benchmark.
#
# Runs the FimModule in isolation via the `burst_watcher` example, then
# creates 1000 files in its watched directory from an unrelated shell
# while `pidstat` samples %CPU on the watcher process. This isolates
# the agent's CPU cost from the file-creation loop itself.
#
# Prereqs: cargo, sysstat (pidstat).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

FILE_COUNT=${FILE_COUNT:-1000}
WATCH_DIR=${WATCH_DIR:-/tmp/sda-bench-fim}

if ! command -v pidstat &>/dev/null; then
  echo "ERROR: pidstat is required (apt install sysstat)" >&2
  exit 1
fi

echo "==> Building burst_watcher example (release)..."
cargo build --release --example burst_watcher -p sda-fim 2>&1 | tail -3

BIN="$REPO_ROOT/target/release/examples/burst_watcher"
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: missing $BIN" >&2
  exit 1
fi

rm -rf "$WATCH_DIR"
mkdir -p "$WATCH_DIR"

echo "==> Starting burst_watcher on $WATCH_DIR..."
"$BIN" "$WATCH_DIR" &>/tmp/sda-burst-watcher.log &
BENCH_PID=$!

cleanup() {
  kill "$BENCH_PID" 2>/dev/null || true
  wait "$BENCH_PID" 2>/dev/null || true
  rm -rf "$WATCH_DIR"
}
trap cleanup EXIT

sleep 2

if ! kill -0 "$BENCH_PID" 2>/dev/null; then
  echo "ERROR: burst_watcher exited early" >&2
  cat /tmp/sda-burst-watcher.log
  exit 1
fi

echo "==> Sampling %CPU on PID $BENCH_PID while creating $FILE_COUNT files..."

PIDSTAT_OUT=$(mktemp)
pidstat -p "$BENCH_PID" 1 15 >"$PIDSTAT_OUT" 2>&1 &
PIDSTAT_PID=$!

sleep 0.5

START_NS=$(date +%s%N)
for i in $(seq 1 "$FILE_COUNT"); do
  printf 'benchmark file %s content\n' "$i" >"$WATCH_DIR/file_$(printf '%04d' "$i").txt"
done
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "    created $FILE_COUNT files in ${ELAPSED_MS} ms"

wait "$PIDSTAT_PID" 2>/dev/null || true

echo ""
echo "==> pidstat output:"
cat "$PIDSTAT_OUT"

PEAK=$(awk '!/^#/ && !/Average/ && $8 ~ /[0-9]/ { if ($8+0 > max) max=$8+0 } END { printf "%.2f", max+0 }' "$PIDSTAT_OUT")
AVG=$(awk '/Average:/ { print $8 }' "$PIDSTAT_OUT")

echo ""
echo "==> Summary:"
echo "    files created         : $FILE_COUNT"
echo "    burst duration        : ${ELAPSED_MS} ms"
echo "    peak %CPU (1 s samp.) : ${PEAK}"
echo "    avg  %CPU             : ${AVG}"

rm -f "$PIDSTAT_OUT"
