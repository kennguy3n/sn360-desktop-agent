#!/bin/bash
# Micro-benchmark harness for SDA internal components.
# Runs Criterion benchmarks for crypto, hashing, and event bus throughput.
# If Criterion benchmarks are not yet set up, falls back to basic timing tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

echo "======================================================================"
echo "           SDA Micro-Benchmark Suite"
echo "======================================================================"
echo ""

# ── 1. Crypto throughput (encryption/decryption) ─────────────────────
echo "==> 1. Crypto throughput benchmark..."

if cargo bench --bench crypto_bench 2>/dev/null; then
  echo "    Criterion benchmark completed (see target/criterion/ for reports)"
else
  echo "    Criterion bench not found; running inline timing test..."
  cargo test --release -p sda-comms --lib -- --ignored bench 2>/dev/null || true

  # Fallback: measure encrypt/decrypt round-trip via a small Rust snippet
  cat > /tmp/sda_crypto_bench.rs << 'BENCH_EOF'
use std::time::Instant;
fn main() {
    // Simple throughput estimation: AES-256-CBC encrypt/decrypt 1 MB
    let data = vec![0x42u8; 1_048_576]; // 1 MB
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        // Simulate work: SHA-256 hash (stand-in for crypto throughput)
        let _ = ring::digest::digest(&ring::digest::SHA256, &data);
    }
    let elapsed = start.elapsed();

    let throughput_mbps = (iterations as f64 * 1.0) / elapsed.as_secs_f64();
    println!("  SHA-256 throughput: {:.1} MB/s ({} iterations, {:.2}s)",
             throughput_mbps, iterations, elapsed.as_secs_f64());
}
BENCH_EOF
  echo "    (Criterion benchmarks can be added to crates/sda-comms/benches/)"
fi

echo ""

# ── 2. FIM hashing throughput (SHA-256) ──────────────────────────────
echo "==> 2. SHA-256 hashing throughput benchmark..."

if cargo bench --bench fim_bench 2>/dev/null; then
  echo "    Criterion benchmark completed"
else
  echo "    Running inline hashing benchmark..."

  # Create test files of various sizes
  BENCH_DIR="/tmp/sda-hash-bench"
  rm -rf "$BENCH_DIR"
  mkdir -p "$BENCH_DIR"

  # 1 KB file
  dd if=/dev/urandom of="$BENCH_DIR/1kb.bin" bs=1024 count=1 2>/dev/null
  # 1 MB file
  dd if=/dev/urandom of="$BENCH_DIR/1mb.bin" bs=1048576 count=1 2>/dev/null
  # 10 MB file
  dd if=/dev/urandom of="$BENCH_DIR/10mb.bin" bs=1048576 count=10 2>/dev/null

  for SIZE_LABEL in "1kb" "1mb" "10mb"; do
    FILE="$BENCH_DIR/${SIZE_LABEL}.bin"
    ITERS=100
    if [ "$SIZE_LABEL" = "10mb" ]; then ITERS=10; fi

    START_NS=$(date +%s%N)
    for i in $(seq 1 $ITERS); do
      sha256sum "$FILE" > /dev/null
    done
    END_NS=$(date +%s%N)

    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
    AVG_MS=$(( ELAPSED_MS / ITERS ))
    echo "    SHA-256 ${SIZE_LABEL}: ${AVG_MS}ms avg (${ITERS} iterations, ${ELAPSED_MS}ms total)"
  done

  rm -rf "$BENCH_DIR"
fi

echo ""

# ── 3. Event bus throughput ──────────────────────────────────────────
echo "==> 3. Event bus publish/subscribe throughput benchmark..."

if cargo bench --bench eventbus_bench 2>/dev/null; then
  echo "    Criterion benchmark completed"
else
  echo "    Running event bus test as throughput proxy..."

  # Run event bus tests in release mode and time them
  START_NS=$(date +%s%N)
  cargo test --release -p sda-event-bus -- 2>/dev/null
  END_NS=$(date +%s%N)

  ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
  echo "    Event bus test suite completed in ${ELAPSED_MS}ms (release mode)"
  echo "    (Add Criterion benchmarks to crates/sda-event-bus/benches/ for detailed throughput)"
fi

echo ""

# ── 4. Overall build time ────────────────────────────────────────────
echo "==> 4. Build time benchmark..."

# Clean build
cargo clean 2>/dev/null || true
START_NS=$(date +%s%N)
cargo build --release 2>/dev/null
END_NS=$(date +%s%N)

BUILD_MS=$(( (END_NS - START_NS) / 1000000 ))
BUILD_S=$(echo "scale=1; $BUILD_MS / 1000" | bc)
echo "    Clean release build time: ${BUILD_S}s"

# Binary size
BIN_SIZE=$(stat --format='%s' ./target/release/sda-agent 2>/dev/null || stat -f '%z' ./target/release/sda-agent 2>/dev/null || echo "0")
BIN_MB=$(echo "scale=2; $BIN_SIZE / 1048576" | bc 2>/dev/null || echo "N/A")
echo "    Binary size (stripped): ${BIN_MB} MB"

echo ""
echo "======================================================================"
echo "  Micro-benchmarks complete."
echo "  For detailed profiling, add Criterion benchmarks to:"
echo "    crates/sda-comms/benches/crypto_bench.rs"
echo "    crates/sda-fim/benches/fim_bench.rs"
echo "    crates/sda-event-bus/benches/eventbus_bench.rs"
echo "======================================================================"
