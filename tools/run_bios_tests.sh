#!/bin/sh
# run_bios_tests.sh — прогон BIOS-тестов (app bios) под QEMU.
#
#   tools/run_bios_tests.sh <file.z> [драйвер...]
#
# Драйверы по умолчанию: build/linux/zenith (C++) и build/linux/zenith-z
# (Z-драйвер). Для каждого:
#   1) собираем ISO-образ:  <драйвер> <file.z> --iso -o <out>
#   2) запускаем QEMU:      qemu-system-i386 -cdrom <out>.iso -boot d
#                           -m 128 -display none -debugcon stdio
#                           -device isa-debug-exit,iobase=0xf4,iosize=0x04
#      порт 0xE9 (QEMU debug console) уходит в stdout; запись в 0xF4
#      завершает QEMU (isa-debug-exit) — тест сам себя останавливает;
#   3) разбираем поток: каждый байт = проверка (0x41+idx = OK,
#      0x61+idx = FAIL), 0x0A = конец.
#
# Код возврата: 0 — все проверки прошли, 1 — есть провалы, 2 — ошибка
# сборки/запуска.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="${TMPDIR:-/tmp}/zenith-bios-tests"
QEMU="${QEMU:-qemu-system-i386}"

if [ $# -lt 1 ]; then
    echo "usage: $(basename "$0") <file.z> [driver...]" >&2
    exit 2
fi

SRC="$1"
shift
DRIVERS="$*"
if [ -z "$DRIVERS" ]; then
    DRIVERS="$ROOT/build/linux/zenith $ROOT/build/linux/zenith-z"
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "run_bios_tests: $QEMU не найден — тесты пропущены" >&2
    exit 2
fi

mkdir -p "$OUTDIR"
STEM="$OUTDIR/$(basename "$SRC" .z)"
rc_all=0

for DRV in $DRIVERS; do
    if [ ! -x "$DRV" ]; then
        echo "run_bios_tests: драйвер $DRV не найден/не исполняемый — пропуск" >&2
        rc_all=2
        continue
    fi
    NAME="$(basename "$DRV")"
    rm -f "$STEM.iso" "$STEM.bin" "$STEM.log" "$STEM.out"

    # ---- сборка образа ----
    # --no-run: QEMU запускаем сами (нужен -debugcon stdio для отчёта).
    if ! "$DRV" "$SRC" --iso --no-run -o "$STEM" > "$STEM.log" 2>&1; then
        echo "run_bios_tests: $NAME: сборка не удалась:" >&2
        tail -20 "$STEM.log" >&2
        rc_all=2
        continue
    fi
    if [ ! -f "$STEM.iso" ]; then
        echo "run_bios_tests: $NAME: не создан $STEM.iso" >&2
        tail -20 "$STEM.log" >&2
        rc_all=2
        continue
    fi

    # ---- диск Level 1: 64 МиБ, sparse; при каждом запуске — с нуля ----
    # (внутренняя FAT32 форматируется сама, если образ пустой: проверка
    #  disk_is_zero в selfhost/lvl1/main.z — «чужой MBR» не трогаем).
    DISK="$STEM.disk"
    rm -f "$DISK"
    if ! truncate -s 64M "$DISK" 2>/dev/null; then
        dd if=/dev/zero of="$DISK" bs=1M count=64 >/dev/null 2>&1
    fi

    # ---- запуск под QEMU ----
    # Тест сам завершает QEMU записью в 0xF4 (isa-debug-exit); timeout —
    # страховка, если образ завис. Level-1 (встроенная FAT32 + ATA) на
    # старте занимает ~40-60с, поэтому таймаут для них больше.
    if command -v timeout >/dev/null 2>&1; then
        timeout 180 "$QEMU" -cdrom "$STEM.iso" -boot d -m 128 -display none \
            -debugcon stdio -no-reboot \
            -drive file="$DISK",format=raw,if=ide,index=0 \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            > "$STEM.out" 2>/dev/null
    else
        "$QEMU" -cdrom "$STEM.iso" -boot d -m 128 -display none \
            -debugcon stdio -no-reboot \
            -drive file="$DISK",format=raw,if=ide,index=0 \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            > "$STEM.out" 2>/dev/null &
        QPID=$!
        sleep 5
        kill $QPID 2>/dev/null
        wait $QPID 2>/dev/null
    fi

    # ---- разбор потока 0xE9 ----
    od -An -tu1 -v "$STEM.out" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' > "$STEM.bytes"
    pass=0
    fail=0
    failed=""
    while read -r b; do
        [ "$b" = "10" ] && break          # перевод строки — конец прогона
        if [ "$b" -ge 66 ] && [ "$b" -le 96 ]; then
            pass=$((pass + 1))
        elif [ "$b" -ge 98 ] && [ "$b" -le 128 ]; then
            fail=$((fail + 1))
            failed="$failed $((b - 97))"
        fi
    done < "$STEM.bytes"

    if [ "$pass" = "0" ] && [ "$fail" = "0" ]; then
        echo "run_bios_tests: $NAME: нет ни одной проверки (образ не отработал?)" >&2
        rc_all=2
        continue
    fi
    if [ "$fail" -ne 0 ]; then
        echo "run_bios_tests: $NAME: FAIL на проверках:$failed"
        rc_all=1
    else
        echo "run_bios_tests: $NAME: ALL PASS ($pass проверок)"
    fi
done

exit $rc_all
