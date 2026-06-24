#!/bin/bash
set -e

echo "=== vdiskhash Integration Test ==="

# Define temporary filenames
ORIG_RAW="test_orig.raw"
QCOW2_IMG="test_image.qcow2"
VHDX_DYN_IMG="test_image_dyn.vhdx"
VHDX_FIX_IMG="test_image_fix.vhdx"
VMDK_IMG="test_image.vmdk"

# Test output logs
EXPECTED_OUT="expected.out"
QCOW2_OUT="qcow2.out"
VHDX_DYN_OUT="vhdx_dyn.out"
VHDX_FIX_OUT="vhdx_fix.out"
VMDK_OUT="vmdk.out"
QCOW2_EXPLICIT_OUT="qcow2_explicit.out"
VHDX_DYN_EXPLICIT_OUT="vhdx_dyn_explicit.out"
VHDX_FIX_EXPLICIT_OUT="vhdx_fix_explicit.out"
VMDK_EXPLICIT_OUT="vmdk_explicit.out"

BIN="./target/release/vdiskhash"

# Cleanup function to ensure no temporary files are left behind
cleanup() {
    echo "Cleaning up temporary files..."
    rm -f "$ORIG_RAW" "$QCOW2_IMG" "$VHDX_DYN_IMG" "$VHDX_FIX_IMG" "$VMDK_IMG" "temp_compressible.raw"
    rm -f "$EXPECTED_OUT" "$QCOW2_OUT" "$VHDX_DYN_OUT" "$VHDX_FIX_OUT" "$VMDK_OUT"
    rm -f "$QCOW2_EXPLICIT_OUT" "$VHDX_DYN_EXPLICIT_OUT" "$VHDX_FIX_EXPLICIT_OUT" "$VMDK_EXPLICIT_OUT"
}
trap cleanup EXIT

# 1. Verify requirements
if ! command -v qemu-img &> /dev/null; then
    echo "Error: 'qemu-img' command is required to convert test images but was not found."
    echo "Please install qemu-utils (Ubuntu/Debian) or qemu-img (CentOS/RHEL/Fedora)."
    exit 1
fi

# 2. Build in release mode if not already built
echo "Building vdiskhash in release mode..."
cargo build --release

if [ ! -f "$BIN" ]; then
    echo "Error: Release binary not found at $BIN"
    exit 1
fi

# 3. Create dummy raw image with compressible text patterns (aligned to 512 bytes)
echo "Generating dummy raw image with compressible text pattern..."
temp_raw="temp_compressible.raw"
# We generate a repetitive sequence of words and numbers that qemu-img can compress effectively.
seq 1 400000 | sed 's/^/virtual disk hash chunk /' > "$temp_raw"

# Align size to 512 bytes sector boundary
SIZE=$(wc -c < "$temp_raw")
ALIGNED_SIZE=$(( (SIZE / 512) * 512 ))
echo "Aligning test data size from $SIZE to $ALIGNED_SIZE bytes..."
dd if="$temp_raw" of="$ORIG_RAW" bs=512 count=$((ALIGNED_SIZE / 512)) status=none
rm -f "$temp_raw"

# 4. Generate expected hash values from the source RAW image
echo "Generating reference hashes from RAW file..."
"$BIN" "$ORIG_RAW" > "$EXPECTED_OUT"

# 5. Convert RAW image into various virtual disk formats using qemu-img
echo "Converting RAW to QCOW2 (with compression)..."
qemu-img convert -c -f raw -O qcow2 "$ORIG_RAW" "$QCOW2_IMG"

echo "Converting RAW to VHDX (Dynamic)..."
qemu-img convert -f raw -O vhdx -o subformat=dynamic "$ORIG_RAW" "$VHDX_DYN_IMG"

echo "Converting RAW to VHDX (Fixed)..."
qemu-img convert -f raw -O vhdx -o subformat=fixed "$ORIG_RAW" "$VHDX_FIX_IMG"

echo "Converting RAW to VMDK..."
qemu-img convert -f raw -O vmdk "$ORIG_RAW" "$VMDK_IMG"

# 6. Run vdiskhash on converted virtual disks (Auto-detection mode)
echo "Hashing QCOW2 image (Auto-detect)..."
"$BIN" "$QCOW2_IMG" > "$QCOW2_OUT"

echo "Hashing VHDX Dynamic image (Auto-detect)..."
"$BIN" "$VHDX_DYN_IMG" > "$VHDX_DYN_OUT"

echo "Hashing VHDX Fixed image (Auto-detect)..."
"$BIN" "$VHDX_FIX_IMG" > "$VHDX_FIX_OUT"

echo "Hashing VMDK image (Auto-detect)..."
"$BIN" "$VMDK_IMG" > "$VMDK_OUT"

# 7. Run vdiskhash with explicit format options
echo "Hashing QCOW2 image (Explicit)..."
"$BIN" -f qcow2 "$QCOW2_IMG" > "$QCOW2_EXPLICIT_OUT"

echo "Hashing VHDX Dynamic image (Explicit)..."
"$BIN" -f vhdx "$VHDX_DYN_IMG" > "$VHDX_DYN_EXPLICIT_OUT"

echo "Hashing VHDX Fixed image (Explicit)..."
"$BIN" -f vhdx "$VHDX_FIX_IMG" > "$VHDX_FIX_EXPLICIT_OUT"

echo "Hashing VMDK image (Explicit)..."
"$BIN" -f vmdk "$VMDK_IMG" > "$VMDK_EXPLICIT_OUT"

# 8. Verify outputs by comparing with expected RAW hashes
echo "Verifying QCOW2 (Auto-detect) output..."
diff -u "$EXPECTED_OUT" "$QCOW2_OUT"

echo "Verifying VHDX Dynamic (Auto-detect) output..."
diff -u "$EXPECTED_OUT" "$VHDX_DYN_OUT"

echo "Verifying VHDX Fixed (Auto-detect) output..."
diff -u "$EXPECTED_OUT" "$VHDX_FIX_OUT"

echo "Verifying VMDK (Auto-detect) output..."
diff -u "$EXPECTED_OUT" "$VMDK_OUT"

echo "Verifying QCOW2 (Explicit) output..."
diff -u "$EXPECTED_OUT" "$QCOW2_EXPLICIT_OUT"

echo "Verifying VHDX Dynamic (Explicit) output..."
diff -u "$EXPECTED_OUT" "$VHDX_DYN_EXPLICIT_OUT"

echo "Verifying VHDX Fixed (Explicit) output..."
diff -u "$EXPECTED_OUT" "$VHDX_FIX_EXPLICIT_OUT"

echo "Verifying VMDK (Explicit) output..."
diff -u "$EXPECTED_OUT" "$VMDK_EXPLICIT_OUT"

echo "=== All integration tests PASSED successfully! ==="
