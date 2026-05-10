#!/bin/bash
# Performance regression gate for CI (Phase 6 task 6.3).
#
# Enforces the hard budgets documented in device-agent-proposal.md § 11
# and benchmark-results.md:
#
#   idle RSS      < 15 MB
#   idle CPU      <  0.1 %
#   binary size   <  7 MB
#   FIM burst CPU <  3.0 %  (1000-file burst, peak)
#
# The script is designed to run non-interactively on a GitHub-hosted
# ubuntu runner: it builds a release binary, starts the agent with
# `tests/sda-test-config.yaml` pointing at loopback (no manager
# required — enrollment will retry forever but the idle metrics are
# still meaningful), takes measurements, and exits non-zero if any
# budget is exceeded. Results are written to
# `$REGRESSION_OUTPUT_DIR/benchmark-regression.txt` for upload as a
# CI artifact.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Thresholds ────────────────────────────────────────────────────────
MAX_IDLE_RSS_KB=$((15 * 1024))      # 15 MB
MAX_IDLE_CPU_PCT="0.1"              # 0.1 %
# Raised from 5 MB to 7 MB once YARA (via sda-local-detection),
# rustls + ring (enhanced protocol), and the reqwest-based updater
# landed. cargo bloat confirms those three subsystems account for
# the delta; see benchmark-results.md § "Binary Size" for the
# per-crate attribution.
MAX_BINARY_SIZE_BYTES=$((7 * 1024 * 1024))  # 7 MB
MAX_FIM_PEAK_CPU_PCT="3.0"          # 3 %

IDLE_MEASURE_SECS="${IDLE_MEASURE_SECS:-30}"
FIM_FILE_COUNT="${FIM_FILE_COUNT:-1000}"
# MUST match an FIM-monitored directory in $SDA_CONFIG, otherwise the
# FIM module never sees the burst and the peak-CPU gate silently
# measures idle CPU. tests/sda-test-config.yaml monitors
# /tmp/sda-e2e-fim.
FIM_DIR="${FIM_DIR:-/tmp/sda-e2e-fim}"
OUTPUT_DIR="${REGRESSION_OUTPUT_DIR:-$REPO_ROOT/target/benchmark-regression}"
# Cargo profile to build/measure. Defaults to `release` for the
# canonical regression run; CI may set `SDA_PROFILE=ci` to use the
# `[profile.ci]` profile (release + thin LTO + 4 codegen units) for a
# dramatically faster compile while keeping the size/CPU budgets
# meaningful enough for a smoke gate.
SDA_PROFILE="${SDA_PROFILE:-release}"
SDA_BIN="${SDA_BIN:-$REPO_ROOT/target/$SDA_PROFILE/sda-agent}"
SDA_CONFIG="${SDA_CONFIG:-$REPO_ROOT/tests/sda-test-config.yaml}"

mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/benchmark-regression.txt"
: > "$REPORT"

FAILED=0

fail() { echo "FAIL: $*" | tee -a "$REPORT"; FAILED=1; }
pass() { echo "PASS: $*" | tee -a "$REPORT"; }
info() { echo "info: $*" | tee -a "$REPORT"; }

# Float comparisons are handled entirely by awk below, so no external
# dependency is needed. (An earlier draft guarded on `bc` being
# installed, but nothing in this script ever calls bc.)
float_gt() {
  # float_gt <a> <b> — returns 0 if a > b, non-zero otherwise.
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a+0 > b+0) }'
}

# Portable "is this PID alive?" that works when the target is owned
# by another user. `kill -0 $pid` returns failure with errno EPERM
# (not ESRCH) for root-owned children of a sudo-spawned wrapper when
# called from the unprivileged parent shell — the kernel refuses the
# signal probe and the shell cannot distinguish that from the
# process being gone. `ps -p` just reads the procfs entry, which any
# user can do.
pid_alive() {
  [ -n "${1:-}" ] && ps -p "$1" >/dev/null 2>&1
}

cleanup() {
  # SDA_PID is the real agent child; SUDO_PID is the sudo wrapper
  # that forked it. We kill the agent first (it drives the shutdown
  # path cleanly) and then fall back to the sudo wrapper in case the
  # child somehow survived or never materialised.
  if pid_alive "${SDA_PID:-}"; then
    sudo kill -TERM "$SDA_PID" 2>/dev/null || true
    sleep 1
    sudo kill -KILL "$SDA_PID" 2>/dev/null || true
  fi
  if pid_alive "${SUDO_PID:-}"; then
    sudo kill -TERM "$SUDO_PID" 2>/dev/null || true
    sleep 1
    sudo kill -KILL "$SUDO_PID" 2>/dev/null || true
  fi
  rm -rf "$FIM_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Build release binary ───────────────────────────────────────────
info "Building $SDA_PROFILE binary..."
cargo build --profile "$SDA_PROFILE" -p sda-agent

# ── 2. Binary size ────────────────────────────────────────────────────
if [ ! -x "$SDA_BIN" ]; then
  fail "Release binary not found at $SDA_BIN"
  exit 1
fi
BIN_SIZE=$(stat --format='%s' "$SDA_BIN" 2>/dev/null || stat -f '%z' "$SDA_BIN")
info "Binary size: $BIN_SIZE bytes (budget: $MAX_BINARY_SIZE_BYTES)"
if [ "$BIN_SIZE" -gt "$MAX_BINARY_SIZE_BYTES" ]; then
  fail "binary size $BIN_SIZE > $MAX_BINARY_SIZE_BYTES"
else
  pass "binary size within budget"
fi

# ── 3. Start agent & measure idle ─────────────────────────────────────
info "Starting agent for idle measurement (${IDLE_MEASURE_SECS}s)..."
sudo mkdir -p /etc/sn360-desktop-agent
# `sudo ... &` puts the sudo wrapper in the background; `$!` is the
# wrapper's PID, NOT the sda-agent child it execs. If we use that PID
# for ps/pidstat we silently measure an idle sudo process (~3 MB RSS,
# 0 % CPU) and the regression gate passes regardless of the agent's
# real resource use. Resolve the actual agent child via pgrep after
# giving the wrapper enough time to exec.
sudo "$SDA_BIN" "$SDA_CONFIG" >"$OUTPUT_DIR/agent.log" 2>&1 &
SUDO_PID=$!
# Give tokio time to spin up all modules and for enrollment backoff to
# reach steady state.
sleep 15

# Find the real agent PID. Match the absolute binary path to avoid
# matching any other sda-agent instance on the runner, and explicitly
# drop the sudo wrapper PID from the results.
SDA_PID=$(pgrep -f "^${SDA_BIN}( |$)" 2>/dev/null | grep -v "^${SUDO_PID}$" | head -1 || true)
if [ -z "$SDA_PID" ]; then
  fail "could not resolve sda-agent child PID (sudo wrapper was $SUDO_PID)"
  tail -40 "$OUTPUT_DIR/agent.log" | tee -a "$REPORT" || true
  exit 1
fi
info "sudo wrapper PID: $SUDO_PID, sda-agent PID: $SDA_PID"

if ! pid_alive "$SDA_PID"; then
  fail "agent exited before idle measurement could start"
  tail -40 "$OUTPUT_DIR/agent.log" | tee -a "$REPORT" || true
  exit 1
fi

IDLE_RSS_KB=$(ps -o rss= -p "$SDA_PID" 2>/dev/null | tr -d ' ')
info "Idle RSS: ${IDLE_RSS_KB} KB (budget: ${MAX_IDLE_RSS_KB} KB)"
if [ "${IDLE_RSS_KB:-0}" -gt "$MAX_IDLE_RSS_KB" ]; then
  fail "idle RSS ${IDLE_RSS_KB} KB > ${MAX_IDLE_RSS_KB} KB"
else
  pass "idle RSS within budget"
fi

if command -v pidstat >/dev/null; then
  IDLE_CPU=$(pidstat -p "$SDA_PID" 1 "$IDLE_MEASURE_SECS" 2>/dev/null \
    | awk '/Average:/ && !/^#/ { print $8 }' | tail -1)
  IDLE_CPU="${IDLE_CPU:-N/A}"
else
  IDLE_CPU="N/A (pidstat not installed)"
fi
info "Idle CPU avg: ${IDLE_CPU} % (budget: ${MAX_IDLE_CPU_PCT} %)"
if [ "$IDLE_CPU" != "N/A" ] && [ "$IDLE_CPU" != "N/A (pidstat not installed)" ]; then
  if float_gt "$IDLE_CPU" "$MAX_IDLE_CPU_PCT"; then
    fail "idle CPU ${IDLE_CPU} % > ${MAX_IDLE_CPU_PCT} %"
  else
    pass "idle CPU within budget"
  fi
else
  info "skipping idle CPU gate (no pidstat available)"
fi

# ── 4. FIM burst ──────────────────────────────────────────────────────
info "Running FIM burst (${FIM_FILE_COUNT} files)..."
mkdir -p "$FIM_DIR"
for i in $(seq 1 "$FIM_FILE_COUNT"); do
  echo "regression-$i" > "$FIM_DIR/file_${i}.txt"
done

if command -v pidstat >/dev/null; then
  PEAK_CPU=$(pidstat -p "$SDA_PID" 1 30 2>/dev/null \
    | awk '!/^#/ && !/Average/ && $8 ~ /[0-9]/ { if ($8+0 > max) max=$8+0 } END { print max+0 }')
  PEAK_CPU="${PEAK_CPU:-N/A}"
else
  PEAK_CPU="N/A (pidstat not installed)"
fi
info "FIM peak CPU: ${PEAK_CPU} % (budget: ${MAX_FIM_PEAK_CPU_PCT} %)"
if [ "$PEAK_CPU" != "N/A" ] && [ "$PEAK_CPU" != "N/A (pidstat not installed)" ]; then
  if float_gt "$PEAK_CPU" "$MAX_FIM_PEAK_CPU_PCT"; then
    fail "FIM peak CPU ${PEAK_CPU} % > ${MAX_FIM_PEAK_CPU_PCT} %"
  else
    pass "FIM peak CPU within budget"
  fi
else
  info "skipping FIM peak gate (no pidstat available)"
fi

# ── 5. Summary ────────────────────────────────────────────────────────
{
  echo ""
  echo "=== benchmark-regression summary ==="
  echo "binary size    : $BIN_SIZE bytes"
  echo "idle RSS       : ${IDLE_RSS_KB} KB"
  echo "idle CPU avg   : ${IDLE_CPU} %"
  echo "FIM peak CPU   : ${PEAK_CPU} %"
  echo ""
  if [ "$FAILED" -eq 0 ]; then
    echo "RESULT: PASS — all budgets met"
  else
    echo "RESULT: FAIL — one or more budgets exceeded"
  fi
} | tee -a "$REPORT"

exit "$FAILED"
