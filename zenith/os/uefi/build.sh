#!/bin/bash
# Build the Zenith UEFI image: os/uefi/zenos.z -> build/uefi/zenos.{efi,iso}
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${ZENITH_OUT:-$ROOT/build/uefi}"
Z="$ROOT/build/linux/zenith"
if [ ! -x "$Z" ]; then
  echo "building the compiler first..."
  make -C "$ROOT" -f Makefile.linux -j"$(nproc)" >/dev/null
fi
mkdir -p "$OUT"
SRC="$HERE/zenos.z"
[ -n "$1" ] && SRC="$1"
"$Z" "$SRC" -o "$OUT/zenos.efi" --iso
echo " -> $OUT/zenos.efi"
echo " -> $OUT/zenos.iso"
