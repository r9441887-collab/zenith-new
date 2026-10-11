#!/bin/bash
# Boot zenos.efi/ISO under QEMU+OVMF and keep it running for inspection.
#   ./run_qemu.sh [image.iso] [--hold]
# Serial goes to build/serial.log, monitor to build/mon.sock.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${ZENITH_OUT:-$ROOT/build/uefi}"
ISO="${1:-$OUT/zenos.iso}"
[ -f "$ISO" ] || { echo "no image: $ISO (run build.sh first)"; exit 1; }
mkdir -p "$OUT"
OVMF=""
for c in /usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF.fd \
         /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/ovmf/OVMF_CODE.fd \
         /usr/share/edk2/x64/OVMF_CODE.fd; do
  [ -f "$c" ] && OVMF="$c" && break
done
[ -n "$OVMF" ] || { echo "OVMF firmware not found"; exit 1; }
rm -f "$OUT/serial.log" "$OUT/mon.sock"
exec qemu-system-x86_64 \
  -machine q35 -m 512 -cpu qemu64 \
  -bios "$OVMF" \
  -drive if=ide,media=cdrom,file="$ISO",format=raw,readonly=on \
  -display none -vga std \
  -serial file:"$OUT/serial.log" \
  -monitor unix:"$OUT/mon.sock",server,nowait \
  -no-reboot -no-shutdown
