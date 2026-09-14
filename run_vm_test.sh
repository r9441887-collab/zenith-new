#!/bin/bash
# Run all Zenith .ko drivers inside a disposable QEMU VM (host kernel).
# Safe for hlt/cli/port-I/O driver tests that can hang the host kernel.
#
# Requirements: qemu-system-x86_64, busybox-static, /boot/vmlinuz-<kernel>.
# Usage:  ./run_vm_test.sh [--kernel 6.12.95+deb12-amd64] [--mods "a b"]
# Output: full dmesg to stdout, plus a copy in ./vm_test.log

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
KV="${1:-$(uname -r)}"
KERNEL="/boot/vmlinuz-$KV"
VENV="/tmp/zenith-vmtest"
MODLIST="${MODLIST:-driver_test driver_test2 drv_imports asm_driver}"

if [[ ! -f "$KERNEL" ]]; then
    echo "error: $KERNEL not found" >&2
    exit 1
fi
command -v qemu-system-x86_64 >/dev/null || { echo "need qemu-system-x86_64" >&2; exit 1; }
command -v busybox >/dev/null || { echo "need busybox-static" >&2; exit 1; }

rm -rf "$VENV"
mkdir -p "$VENV/root/bin" "$VENV/root/lib/modules"

cp /bin/busybox "$VENV/root/bin/"
for m in $MODLIST; do
    if [[ -f "$DIR/$m.ko" ]]; then
        cp "$DIR/$m.ko" "$VENV/root/lib/modules/"
    else
        echo "warning: $DIR/$m.ko not found, skipped" >&2
    fi
done

cat > "$VENV/root/init" <<EOF
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
echo "=== init: zenith ko test ==="
for m in $MODLIST; do
    echo "----- insmod \$m -----"
    insmod "/lib/modules/\$m.ko" 2>&1
    echo "insmod exit: \$?"
done
echo "===== kernel log ====="
dmesg | tail -80
echo "=== done, powering off ==="
sync
poweroff -f
EOF
chmod 755 "$VENV/root/init"

( cd "$VENV/root" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$VENV/initrd.gz" )
echo "[*] booting qemu: kernel=$KV mods=[$MODLIST]"
timeout 120 qemu-system-x86_64 \
    -m 512 -nographic -no-reboot \
    -kernel "$KERNEL" -initrd "$VENV/initrd.gz" \
    -append "console=ttyS0 rdinit=/init" > "$DIR/vm_test.log" 2>&1 || true
tr -d '\r' < "$DIR/vm_test.log"
echo "[*] log saved to $DIR/vm_test.log"