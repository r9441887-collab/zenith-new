#!/bin/bash
# Zenith regression runner.
# Modes:
#   native  — compile .z with build/linux/zenith -> ELF -> run on host
#   wine    — compile .z with build/zenith.exe (mingw) -> run under wine
#   qemu    — compile each app-linux-driver .z to a FRESH .ko and insmod them
#             inside a disposable QEMU VM (never touches the host kernel)
#   compile — compile-only gate (Windows GUI/DX11 apps; need wine to run)
#
# Exit code: 0 = all green (XFAILs allowed), 1 = any real FAIL.
# Usage:  ./run_tests.sh [--qemu] [--verbose]

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

VERBOSE=0; DO_QEMU=0
for a in "$@"; do
    [ "$a" = "--verbose" ] && VERBOSE=1
    [ "$a" = "--qemu" ]    && DO_QEMU=1
done

PASS=0; FAIL=0; XFAIL=0; SKIP=0
declare -a FAILED=()

out() { [ "$VERBOSE" = 1 ] && printf '%s\n' "$*"; }

run_native() {  # $1 = .z path, expects exit 0
    local z="$1" name out rc
    name="$(basename "${z%.z}")"
    if ! ./build/linux/zenith "$z" -o "/tmp/zt_${name}.elf" >/tmp/zt_out 2>&1; then
        return 66
    fi
    chmod +x "/tmp/zt_${name}.elf"
    timeout 30 "/tmp/zt_${name}.elf" >/tmp/zt_run 2>&1
    return $?
}

run_wine() {  # $1 = .z path, expects exit 0
    local z="$1" name
    name="$(basename "${z%.z}")"
    if ! wine ./build/zenith.exe "$z" >/tmp/zt_out 2>&1; then
        return 66
    fi
    cp -f a.exe "/tmp/zt_${name}.exe"
    timeout 30 wine "/tmp/zt_${name}.exe" >/tmp/zt_run 2>&1
    return $?
}

record() { # $1=label $2=rc $3=expected $4=xfail?  $5=path
    local label="$1" rc="$2" exp="$3" xf="$4" path="$5"
    if [ "$rc" = "$exp" ]; then
        PASS=$((PASS+1)); out "  ok    $label"
    elif [ "$xf" = 1 ]; then
        XFAIL=$((XFAIL+1)); out "  XFAIL $label (rc=$rc — known-broken, tracked)"
    else
        FAIL=$((FAIL+1)); FAILED+=("$label (rc=$rc, want=$exp)")
        out "  FAIL  $label"
        if [ "$VERBOSE" = 1 ]; then tail -n 5 /tmp/zt_run | sed 's/^/        /'; tail -n 3 /tmp/zt_out | sed 's/^/        [compile] /'; fi
    fi
}

echo "[*] building linux compiler"
make -f Makefile.linux -q 2>/dev/null || make -f Makefile.linux -j"$(nproc)" >/dev/null 2>&1 || { echo "compiler build failed"; exit 1; }

# ============================ native (Linux ELF) ============================
echo "== native ELF =="
for z in test_linux.z; do
    run_native "$z"; rc=$?; record "native.$z" "$rc" 0 0 "$z"
done
for z in ../zenith-engine/tests/core_colortest.z ../zenith-engine/tests/t_probe_glob.z; do
    run_native "$z"; rc=$?; record "native.$z" "$rc" 0 0 "$z"
done
# Known-broken on the ELF backend (SEGV) — pass under wine, tracked as XFAIL.
for z in ../zenith-engine/tests/core_recttest.z ../zenith-engine/tests/core_trftest.z \
         ../zenith-engine/tests/eng_test.z; do
    run_native "$z"; rc=$?; record "native.$z" "$rc" 0 1 "$z"
done

# ============================ wine (Windows PE) =============================
echo "== wine PE =="
if command -v wine >/dev/null 2>&1; then
    for z in ../zenith-engine/tests/core_colortest.z ../zenith-engine/tests/core_recttest.z \
             ../zenith-engine/tests/core_trftest.z ../zenith-engine/tests/eng_test.z \
             https_test.z; do
        run_wine "$z"; rc=$?; record "wine.$z" "$rc" 0 0 "$z"
    done
    # JS-engine regression (tracked; flip to green when fixed).
    for z in js_test.z js_tern_test.z js_require_test.z js_require_stress.z \
             feat.z zoop.z zstd.z zasync.z; do
        run_wine "$z"; rc=$?; record "wine.$z" "$rc" 0 1 "$z"
    done
    echo "== compile-only (need real Windows to run) =="
    for z in test_win.z cube3d.z chip8_gui.z; do
        if wine ./build/zenith.exe "$z" >/tmp/zt_out 2>&1; then
            PASS=$((PASS+1)); out "  ok    compile-only.$z"
        else
            FAIL=$((FAIL+1)); FAILED+=("compile-only.$z"); out "  FAIL  compile-only.$z"
        fi
    done
else
    SKIP=$((SKIP+1)); echo "  (wine not found — wine suite skipped)"
fi

# ============================ qemu driver tests =============================
if [ "$DO_QEMU" = 1 ]; then
    echo "== qemu driver (.ko) =="
    if command -v qemu-system-x86_64 >/dev/null 2>&1; then
        ok=1
        for z in driver_test.z driver_test2.z drv_imports.z asm_driver.z; do
            if ! ./build/linux/zenith "$z" -o "$z.ko" >/tmp/zt_out 2>&1; then
                echo "    FAIL build driver $z"; FAILED+=("qemu.build.$z"); ok=0
            fi
        done
        if [ "$ok" = 1 ] && ./run_vm_test.sh >/tmp/zt_vm 2>&1; then
            if grep -q "insmod exit: 0" /tmp/zt_vm && ! grep -qiE "oops|panic|BUG:" /tmp/zt_vm; then
                PASS=$((PASS+1)); out "  ok    qemu.drivers"
            else
                FAIL=$((FAIL+1)); FAILED+=("qemu.drivers (oops/panic)"); out "  FAIL  qemu.drivers"
            fi
        else
            FAIL=$((FAIL+1)); FAILED+=("qemu.drivers"); out "  FAIL  qemu.drivers"
        fi
    else
        echo "  (qemu not found — driver suite skipped)"
    fi
else
    out "(run with --qemu to include driver tests)"
fi

# ================================ summary ===================================
echo
echo "PASS=$PASS  FAIL=$FAIL  XFAIL=$XFAIL  SKIP=$SKIP"
if [ "${#FAILED[@]}" -gt 0 ]; then
    printf 'FAILED:\n'; printf '  - %s\n' "${FAILED[@]}"
    echo "RESULT: RED"
    exit 1
fi
echo "RESULT: GREEN"
exit 0