#!/bin/bash
set -e

# Temporary benchmark file
BENCH_FILE="bench_data.img"
BIN="./target/release/vdiskhash"

# Cleanup function to run on exit
cleanup() {
    if [ -f "$BENCH_FILE" ]; then
        echo "Cleaning up temporary benchmark file..."
        rm -f "$BENCH_FILE"
    fi
}
trap cleanup EXIT

echo "=== vdiskhash Benchmark ==="

# 1. Build the utility
echo "Building vdiskhash in release mode..."
cargo build --release

if [ ! -f "$BIN" ]; then
    echo "Error: release binary not found at $BIN"
    exit 1
fi

# 2. Create a dummy file (1 GiB)
echo "Creating 1 GiB dummy file ($BENCH_FILE) for benchmarking..."
dd if=/dev/zero of="$BENCH_FILE" bs=1M count=1024 status=none

echo "Starting benchmark scenarios..."
echo "--------------------------------------------------"

run_bench() {
    local name="$1"
    shift
    echo "Scenario: $name"
    echo "Command: $BIN $* $BENCH_FILE"
    time "$BIN" "$@" "$BENCH_FILE" > /dev/null
    echo "--------------------------------------------------"
}

# --- IO Threads Comparison ---
echo "=== 1. IO Threads Comparison (using xxHash (XXH3), 1MiB chunk) ==="
run_bench "IO Threads: 1" --io-threads 1
run_bench "IO Threads: 2" --io-threads 2
run_bench "IO Threads: 4 (Default)"
echo ""

# --- HASH Threads Comparison ---
echo "=== 2. HASH Threads Comparison (using xxHash (XXH3), 1MiB chunk) ==="
run_bench "HASH Threads: 1" -j 1
run_bench "HASH Threads: 2" -j 2
run_bench "HASH Threads: 4" -j 4
# Run with default (half of logical CPUs, max 4)
run_bench "HASH Threads: Default (Half of CPUs, Max 4)"
echo ""

# --- Hash Algorithms Comparison ---
echo "=== 3. Hash Algorithms Comparison (using 1MiB chunk, Default threads) ==="
run_bench "Algorithm: SHA-224" -a sha224
run_bench "Algorithm: SHA-256" -a sha256
run_bench "Algorithm: SHA-384" -a sha384
run_bench "Algorithm: SHA-512" -a sha512
run_bench "Algorithm: xxHash (XXH64)" -a xxh64
run_bench "Algorithm: xxHash (XXH3)" -a xxh3
echo ""

# --- Chunk Size Comparison ---
echo "=== 4. Chunk Size Comparison (using xxHash (XXH3), Default threads) ==="
run_bench "Chunk Size: 512 KiB" -c 512KiB
run_bench "Chunk Size: 1 MiB" -c 1MiB
run_bench "Chunk Size: 4 MiB" -c 4MiB
run_bench "Chunk Size: 16 MiB" -c 16MiB
echo ""

echo "Benchmark completed successfully!"
