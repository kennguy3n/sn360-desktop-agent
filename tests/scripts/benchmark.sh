#!/bin/bash
# Benchmark harness: compares SDA vs original Wazuh agent resource usage.
# Measures idle RSS, CPU, binary size, startup time, and FIM scan impact.
# Outputs a comparison table.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

# ── Configuration ─────────────────────────────────────────────────────
MEASURE_DURATION=60          # seconds to measure idle metrics
FIM_FILE_COUNT=1000          # files to create for FIM scan benchmark
FIM_DIR="/tmp/sda-benchmark-fim"
WAZUH_AGENT_BIN="/var/ossec/bin/wazuh-agentd"
SDA_BIN="./target/release/sda-agent"
SDA_CONFIG="tests/sda-test-config.yaml"

# ── Helper functions ──────────────────────────────────────────────────

measure_rss() {
  # measure_rss <PID> — returns RSS in KB
  local pid="$1"
  ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0"
}

measure_cpu_avg() {
  # measure_cpu_avg <PID> <seconds> — returns average CPU% over interval
  local pid="$1"
  local secs="$2"
  if command -v pidstat &>/dev/null; then
    pidstat -p "$pid" 1 "$secs" 2>/dev/null \
      | awk '/Average:/ && !/^#/ { print $8 }' | tail -1 || echo "N/A"
  else
    # Fallback: sample /proc/stat
    local start_ticks end_ticks
    start_ticks=$(cat /proc/"$pid"/stat 2>/dev/null | awk '{print $14+$15}' || echo 0)
    sleep "$secs"
    end_ticks=$(cat /proc/"$pid"/stat 2>/dev/null | awk '{print $14+$15}' || echo 0)
    local hz
    hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
    echo "scale=2; ($end_ticks - $start_ticks) / $hz / $secs * 100" | bc 2>/dev/null || echo "N/A"
  fi
}

measure_binary_size() {
  # measure_binary_size <path> — returns size in bytes
  if [ -f "$1" ]; then
    stat --format='%s' "$1" 2>/dev/null || stat -f '%z' "$1" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

measure_startup_time() {
  # measure_startup_time <command...> — returns time to first output in ms
  local start_ns end_ns
  start_ns=$(date +%s%N)
  "$@" &>/dev/null &
  local pid=$!
  # Wait for process to be running (up to 10s)
  local attempts=0
  while [ $attempts -lt 100 ]; do
    if kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  end_ns=$(date +%s%N)
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  echo $(( (end_ns - start_ns) / 1000000 ))
}

bytes_to_mb() {
  echo "scale=2; $1 / 1048576" | bc 2>/dev/null || echo "N/A"
}

kb_to_mb() {
  echo "scale=2; $1 / 1024" | bc 2>/dev/null || echo "N/A"
}

# ── Results storage ───────────────────────────────────────────────────
declare -A WAZUH_METRICS
declare -A SDA_METRICS

# ── Step 1: Build SDA ────────────────────────────────────────────────
echo "==> Step 1: Building SDA..."
cargo build --release
echo "    Build complete."

# ── Step 2: Measure original Wazuh agent (if available) ──────────────
echo "==> Step 2: Measuring original Wazuh agent..."

if [ -x "$WAZUH_AGENT_BIN" ]; then
  echo "    Found Wazuh agent at $WAZUH_AGENT_BIN"

  WAZUH_METRICS[binary_size]=$(measure_binary_size "$WAZUH_AGENT_BIN")

  # Start the agent
  sudo /var/ossec/bin/wazuh-control start 2>/dev/null || true
  sleep 5

  WAZUH_PID=$(pgrep -f wazuh-agentd | head -1 || true)
  if [ -n "$WAZUH_PID" ]; then
    echo "    Wazuh agent PID: $WAZUH_PID"

    # Wait for idle stabilization
    sleep 10

    WAZUH_METRICS[idle_rss]=$(measure_rss "$WAZUH_PID")
    echo "    Measuring CPU for ${MEASURE_DURATION}s..."
    WAZUH_METRICS[idle_cpu]=$(measure_cpu_avg "$WAZUH_PID" "$MEASURE_DURATION")

    # FIM scan benchmark
    echo "    Creating $FIM_FILE_COUNT files for FIM scan test..."
    mkdir -p "$FIM_DIR"
    for i in $(seq 1 "$FIM_FILE_COUNT"); do
      echo "benchmark content $i" > "$FIM_DIR/file_${i}.txt"
    done
    sleep 5
    # Measure peak CPU during FIM scan
    WAZUH_METRICS[fim_peak_cpu]="N/A"
    if command -v pidstat &>/dev/null; then
      PEAK_CPU=$(pidstat -p "$WAZUH_PID" 1 30 2>/dev/null \
        | awk '!/^#/ && !/Average/ && $8 ~ /[0-9]/ { if ($8+0 > max) max=$8+0 } END { print max+0 }' || echo "N/A")
      WAZUH_METRICS[fim_peak_cpu]="$PEAK_CPU"
    fi

    sudo /var/ossec/bin/wazuh-control stop 2>/dev/null || true
  else
    echo "    WARNING: Could not find Wazuh agent PID"
    WAZUH_METRICS[idle_rss]="N/A"
    WAZUH_METRICS[idle_cpu]="N/A"
    WAZUH_METRICS[fim_peak_cpu]="N/A"
  fi
else
  echo "    Original Wazuh agent not installed. Skipping baseline."
  echo "    Install wazuh-agent v4.9.x to get baseline comparison."
  WAZUH_METRICS[binary_size]="N/A"
  WAZUH_METRICS[idle_rss]="N/A"
  WAZUH_METRICS[idle_cpu]="N/A"
  WAZUH_METRICS[fim_peak_cpu]="N/A"
fi

# ── Step 3: Measure SDA ──────────────────────────────────────────────
echo "==> Step 3: Measuring SDA..."

SDA_METRICS[binary_size]=$(measure_binary_size "$SDA_BIN")

echo "    Starting SDA..."
sudo mkdir -p /etc/sn360-desktop-agent
sudo "$SDA_BIN" "$SDA_CONFIG" &>/dev/null &
SDA_PID=$!
sleep 10

if kill -0 "$SDA_PID" 2>/dev/null; then
  SDA_METRICS[idle_rss]=$(measure_rss "$SDA_PID")
  echo "    SDA PID: $SDA_PID, RSS: ${SDA_METRICS[idle_rss]} KB"
  echo "    Measuring CPU for ${MEASURE_DURATION}s..."
  SDA_METRICS[idle_cpu]=$(measure_cpu_avg "$SDA_PID" "$MEASURE_DURATION")

  # FIM scan benchmark
  echo "    Creating $FIM_FILE_COUNT files for FIM scan test..."
  rm -rf "$FIM_DIR"
  mkdir -p "$FIM_DIR"
  for i in $(seq 1 "$FIM_FILE_COUNT"); do
    echo "benchmark content $i" > "$FIM_DIR/file_${i}.txt"
  done
  sleep 5
  SDA_METRICS[fim_peak_cpu]="N/A"
  if command -v pidstat &>/dev/null; then
    PEAK_CPU=$(pidstat -p "$SDA_PID" 1 30 2>/dev/null \
      | awk '!/^#/ && !/Average/ && $8 ~ /[0-9]/ { if ($8+0 > max) max=$8+0 } END { print max+0 }' || echo "N/A")
    SDA_METRICS[fim_peak_cpu]="$PEAK_CPU"
  fi

  sudo kill "$SDA_PID" 2>/dev/null || true
  wait "$SDA_PID" 2>/dev/null || true
else
  echo "    WARNING: SDA did not start properly"
  SDA_METRICS[idle_rss]="N/A"
  SDA_METRICS[idle_cpu]="N/A"
  SDA_METRICS[fim_peak_cpu]="N/A"
fi

# ── Step 4: Startup time comparison ──────────────────────────────────
echo "==> Step 4: Measuring startup times..."

SDA_METRICS[startup_ms]=$(measure_startup_time sudo "$SDA_BIN" "$SDA_CONFIG")
echo "    SDA startup: ${SDA_METRICS[startup_ms]} ms"

if [ -x "$WAZUH_AGENT_BIN" ]; then
  WAZUH_METRICS[startup_ms]=$(measure_startup_time sudo "$WAZUH_AGENT_BIN")
  echo "    Wazuh startup: ${WAZUH_METRICS[startup_ms]} ms"
else
  WAZUH_METRICS[startup_ms]="N/A"
fi

# ── Step 5: Output comparison table ──────────────────────────────────
echo ""
echo "======================================================================"
echo "                  Benchmark Comparison Results"
echo "======================================================================"
echo ""

# Calculate improvements where possible
calc_improvement() {
  local wazuh="$1"
  local sda="$2"
  if [ "$wazuh" = "N/A" ] || [ "$sda" = "N/A" ] || [ "$sda" = "0" ]; then
    echo "N/A"
  else
    echo "scale=1; $wazuh / $sda" | bc 2>/dev/null || echo "N/A"
  fi
}

SDA_RSS_MB=$(kb_to_mb "${SDA_METRICS[idle_rss]:-0}")
WAZUH_RSS_MB=$(kb_to_mb "${WAZUH_METRICS[idle_rss]:-0}")
SDA_BIN_MB=$(bytes_to_mb "${SDA_METRICS[binary_size]:-0}")
WAZUH_BIN_MB=$(bytes_to_mb "${WAZUH_METRICS[binary_size]:-0}")

RSS_IMP=$(calc_improvement "${WAZUH_METRICS[idle_rss]:-N/A}" "${SDA_METRICS[idle_rss]:-N/A}")
CPU_IMP=$(calc_improvement "${WAZUH_METRICS[idle_cpu]:-N/A}" "${SDA_METRICS[idle_cpu]:-N/A}")
BIN_IMP=$(calc_improvement "${WAZUH_METRICS[binary_size]:-N/A}" "${SDA_METRICS[binary_size]:-N/A}")
STARTUP_IMP=$(calc_improvement "${WAZUH_METRICS[startup_ms]:-N/A}" "${SDA_METRICS[startup_ms]:-N/A}")

printf "| %-20s | %-15s | %-15s | %-12s |\n" "Metric" "Wazuh Original" "SDA" "Improvement"
printf "|%-22s|%-17s|%-17s|%-14s|\n" "----------------------" "-----------------" "-----------------" "--------------"
printf "| %-20s | %-15s | %-15s | %-12s |\n" \
  "Idle RSS (MB)" "${WAZUH_RSS_MB}" "${SDA_RSS_MB}" "${RSS_IMP}x"
printf "| %-20s | %-15s | %-15s | %-12s |\n" \
  "Idle CPU (%)" "${WAZUH_METRICS[idle_cpu]:-N/A}" "${SDA_METRICS[idle_cpu]:-N/A}" "${CPU_IMP}x"
printf "| %-20s | %-15s | %-15s | %-12s |\n" \
  "Binary Size (MB)" "${WAZUH_BIN_MB}" "${SDA_BIN_MB}" "${BIN_IMP}x"
printf "| %-20s | %-15s | %-15s | %-12s |\n" \
  "Startup (ms)" "${WAZUH_METRICS[startup_ms]:-N/A}" "${SDA_METRICS[startup_ms]:-N/A}" "${STARTUP_IMP}x"
printf "| %-20s | %-15s | %-15s | %-12s |\n" \
  "FIM Peak CPU (%)" "${WAZUH_METRICS[fim_peak_cpu]:-N/A}" "${SDA_METRICS[fim_peak_cpu]:-N/A}" "—"

echo ""
echo "======================================================================"

# ── Cleanup ───────────────────────────────────────────────────────────
rm -rf "$FIM_DIR"
echo "Benchmark complete."
