#!/bin/bash
# Install asm_driver.ko to be loaded very early at boot (initramfs, the black
# console screen where kernel drivers come up) and show its output on the
# console by removing "quiet" from the kernel cmdline.
#
# Run as root:   sudo /path/install_boot_driver.sh
# To uninstall:  sudo /path/install_boot_driver.sh --uninstall

set -euo pipefail

KO="/media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith/asm_driver.ko"
MODNAME="asm_driver"
MODULES_FILE="/etc/initramfs-tools/modules"
GRUB_CONF="/etc/default/grub"

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "[*] uninstalling boot-time driver"
    if [[ -f "$MODULES_FILE" ]] && grep -q "^$MODNAME" "$MODULES_FILE"; then
        sed -i "/^$MODNAME/d" "$MODULES_FILE"
        echo "[+] removed from $MODULES_FILE"
    fi
    if [[ -n "$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT="quiet"' "$GRUB_CONF" 2>/dev/null)" ]]; then
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT=""/' "$GRUB_CONF"
        echo "[+] re-added 'quiet'"
    fi
    update-initramfs -u
    update-grub
    echo "[*] done. Reboot to apply."
    exit 0
fi

if [[ ! -f "$KO" ]]; then
    echo "error: $KO not found" >&2
    exit 1
fi

KV=$(uname -r)
UPDATES="/lib/modules/$KV/updates"
echo "[*] kernel: $KV"

echo "[*] installing module to $UPDATES"
mkdir -p "$UPDATES"
cp "$KO" "$UPDATES/"
depmod -a "$KV"
echo "[+] depmod ok"

echo "[*] adding '$MODNAME' to $MODULES_FILE"
if grep -q "^$MODNAME" "$MODULES_FILE" 2>/dev/null; then
    echo "[+] already listed"
else
    printf '%s\n' "$MODNAME" >> "$MODULES_FILE"
    echo "[+] added"
fi

echo "[*] rebuilding initramfs"
update-initramfs -u
echo "[+] initramfs ok"

echo "[*] removing 'quiet' from $GRUB_CONF so boot console shows messages"
if [[ -n "$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT="quiet"' "$GRUB_CONF" 2>/dev/null)" ]]; then
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT=""/' "$GRUB_CONF"
    echo "[+] removed 'quiet'"
else
    echo "[+] 'quiet' absent, nothing to do"
fi

echo "[*] updating grub"
update-grub
echo "[+] done. Reboot and watch the boot console for zenith-bench output."