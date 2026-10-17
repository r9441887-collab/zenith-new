#!/usr/bin/env python3
"""Проверка склейки целого контейнера (cgGenerateWide -> cgBuildELF/Lib/KO).

src/_cgimg.z держит четырнадцать исходников (.z-литалы), гоняет их через selfhost
codegen и печатает длину + FNV-64 получившегося cgImg. Здесь те же исходники
вынимаются из литалов, компилируются РЕФЕРЕНСОМ (build/linux/zenith ... --no-opt)
и по ним считается та же пара (len, FNV-64) от байтов контейнера.

Четырнадцать контейнеров (семь веток generateWide + net_* + http_download* +
wl_* + shader_* + wl-окно + sound-детект + disasm + tls + js):

  img1/img2  ET_EXEC .elf   --no-opt                 -> rN.elf
  img3       ET_DYN  .so    --no-opt --lib           -> rN.so
  img4       ET_REL  .o     --no-opt --obj           -> rN.o (сам ET_REL)
  img5       ET_REL  .ko    --no-opt (src 'app linux driver')
                                                      -> ET_REL в $TMP/zenith_ko_1/rN.o
  img6       ET_EXEC .elf   --no-opt (src c net_*)    -> rN.elf; единственный
             источник с cgNetSocksUsed=1, т.е. с четырьмя слотами .data
             (sockaddr_in/addrlen/errno/ipbuf) и disp32 в lea-фикстурах
  img7       ET_EXEC .elf   --no-opt (src c http_*)   -> rN.elf; единственный
             источник с cgHttpDlUsed=1, т.е. с 477784-байтовым блобом в конце
             .text (после NOP-выравнивания), p_flags RWX и rel32-вызовами,
             указывающими на точку входа блоба
  img8       ET_EXEC .elf   --no-opt (src c wl_*)     -> rN.elf; единственный
             источник с cgWlUsed=1, т.е. со слотами .data (envp/fd/path/
             inbuf/tmp), строками .rdata и сырым протоколом display-сокета
             в .text
  img9       ET_EXEC .elf   --no-opt (src c shader()) -> rN.elf; единственный
             источник с шейдерами: .rdata получает 4 SPIR-V модуля
             (ассемблирует src/spvasm.cpp), .text — `lea reg,[rip+moduleRVA]`
             на каждый вызов. Покрывает dedup по (text, kind): одна и та же
             пара text+kind собирается одинаково, та же text с другим kind —
             второй раз, но lea всегда целят в ПЕРВУЮ запись (так в C++).
  img10      ET_EXEC .elf   --no-opt (src c wl-окном) -> rN.elf; единственный
             источник с tryLinuxWLWindowCall: все шесть оконных билтинов
             (wl_create_window/wl_present/wl_process/wl_close_window/wl_fb/
             wl_pixel), т.е. весь wire-протокол рукописного хендшейка,
             sendmsg+SCM_RIGHTS, memfd/ftruncate/mmap и shm-фреймбуфер.
  img11      ET_EXEC .elf   --no-opt (src c sound_*) -> rN.elf; единственный
             источник с cgSoundUsed=1, т.е. с семью слотами .data
             (opened/hwo/fmt/bpf/hdr/seed + 1024-байтовый sin-LUT). Билтин
             sound_* в диспетчере PE-only, но detect*Usage бежит до
             buildImportData и на Linux: это и есть проверка пятёрки
             detect-обходчиков, добавленных в cg_expr.z.

img4 сравнивается по выходному файлу: при --obj buildKO пишет ET_REL прямо
туда и возвращается до modpost/gcc/ld. img5 сравнивается по ЭТАЛОННОМУ ET_REL,
который buildKO пишет в свой рабочий каталог ПЕРЕД запуском shell-команд (файл
появляется раньше любого вызова gcc, поэтому рабочий кодоген даёт валидную
эталонную пару даже если финальная сборка .ko упадёт).

--no-opt обязателен: эталонный optimizer.cpp в selfhost-драйвере ещё не
перенесён, поэтому сравниваем «как есть», без прохода оптимизатора.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "build", "linux", "zenith")
DRIVER = os.path.join(ROOT, "src", "_cgimg.z")

# buildKO кладёт объект в $TMPDIR/zenith_ko_<seq>/; seq — static-счётчик,
# у свежего процесса он 1.
TMP = "/tmp"
KO_DIR = os.path.join(TMP, "zenith_ko_1")

# img5: рабочий кодоген доспускает buildKO до конца и удаляет свой рабочий
# каталог (codegen_ko.cpp:824). Стенд-ин gcc'а останавливает ссылку на шаге
# .mod.c — ET_REL уже записан (строка 745), remove_all не выполняется.
FAKE_GCC_DIR = "/tmp/zenith_fake_gcc"

FNV_OFF = 0x4BF29CE484222325
FNV_PRIME = 0x100000001B3

SRC_NAMES = ("srcA", "srcB", "srcC", "srcD", "srcE", "srcF", "srcG", "srcH",
             "srcI", "srcJ", "srcK", "srcL",
             "srcM", "srcN")


def fnv64(data: bytes) -> int:
    h = FNV_OFF
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return struct.unpack("<q", struct.pack("<Q", h))[0]


def extract_sources() -> list:
    src = open(DRIVER, encoding="utf-8").read()
    out = []
    for name in SRC_NAMES:
        m = re.search(r'var %s: int = "((?:[^"\\]|\\.)*)"' % name, src)
        if not m:
            raise SystemExit("cgimg_check: не нашёл литерал %s в %s" % (name, DRIVER))
        out.append(bytes(m.group(1), "utf-8").decode("unicode_escape"))
    return out


def ref_env(fake_gcc=False):
    env = dict(os.environ)
    env["TMPDIR"] = TMP
    if fake_gcc:
        ensure_fake_gcc()
        env["PATH"] = FAKE_GCC_DIR + os.pathsep + env.get("PATH", "")
    return env


def ensure_fake_gcc():
    os.makedirs(FAKE_GCC_DIR, exist_ok=True)
    p = os.path.join(FAKE_GCC_DIR, "gcc")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    os.chmod(p, 0o755)


def run(cmd, fake_gcc=False, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          env=ref_env(fake_gcc), **kw)


def ref_container(i: int, path: str, out_base: str) -> tuple:
    """Запускает эталон для кейса i (1..14) и возвращает (len, FNV-64)."""
    if i == 1 or i == 2 or i == 6 or i == 7 or i == 8 or i == 9 or i == 10 or i == 11 or i == 12 or i == 13 or i == 14:
        r = run([REF, path, "--no-opt", "-o", out_base])
        obj = out_base + ".elf"
        rc_ok = r.returncode == 0
    elif i == 3:
        r = run([REF, path, "--no-opt", "--lib", "-o", out_base])
        obj = out_base + ".so"
        rc_ok = r.returncode == 0
    elif i == 4:
        # --obj: buildKO пишет ET_REL прямо в выходной файл и возвращается
        # ДО modpost/gcc/ld (codegen_ko.cpp:669..682) — дерева ядра не нужно.
        r = run([REF, path, "--no-opt", "--obj", "-o", out_base])
        obj = out_base + ".o"
        rc_ok = r.returncode == 0
    else:
        # driver-режим: modpost -> gcc -> ld -r. Стенд-ин gcc держит рабочий
        # каталог нетронутым, чтобы ET_REL можно было прочитать.
        shutil.rmtree(KO_DIR, ignore_errors=True)
        r = run([REF, path, "--no-opt", "-o", out_base], fake_gcc=True)
        obj = os.path.join(KO_DIR, os.path.basename(out_base) + ".o")
        rc_ok = True
    if not rc_ok:
        print(r.stdout + r.stderr)
        raise SystemExit("cgimg_check: эталон не собрал img%d" % i)
    if not os.path.exists(obj):
        print(r.stdout + r.stderr)
        raise SystemExit("cgimg_check: у эталона img%d нет контейнера %s" % (i, obj))
    data = open(obj, "rb").read()
    check_static_exec(i, data)
    return (len(data), fnv64(data))


def check_static_exec(i: int, data: bytes):
    """Часть 21 «только syscall»: каждый ET_EXEC-контейнер обязан быть
    статическим — ровно 2 program headers (два PT_LOAD), ни одного
    PT_INTERP(3)/PT_DYNAMIC(2): печать через write(1), выход через
    exit_group, память — bump-хип в .bss, ни одного libc-импорта.
    Проверяется байтовое равенство selfhost ↔ эталон, а статичность —
    здесь; .so/.o/.ko и PE-контейнеры (img3/4/5 и MZ) не трогаем: это
    не исполняемые программы."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return
    e_type = int.from_bytes(data[16:18], "little")
    if e_type != 2:
        return
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    types = [int.from_bytes(data[phoff + k * phentsize:phoff + k * phentsize + 4], "little")
             for k in range(phnum)]
    if phnum != 2 or 3 in types or 2 in types:
        raise SystemExit(
            "cgimg_check: img%d — не статический ELF: phnum=%d types=%s "
            "(директива «только syscall»: PT_INTERP/PT_DYNAMIC запрещены)"
            % (i, phnum, types))


def main() -> int:
    if not os.path.exists(REF):
        print("cgimg_check: нет эталона %s" % REF)
        return 1

    sources = extract_sources()
    with tempfile.TemporaryDirectory(prefix="cgimg") as td:
        ref_hash = {}
        for i, code in enumerate(sources, start=1):
            path = os.path.join(td, "img%d.z" % i)
            open(path, "w", encoding="utf-8").write(code)
            ref_hash[i] = ref_container(i, path, os.path.join(td, "r%d" % i))

        out_path = os.path.join(td, "cgimg")
        r = run([REF, DRIVER, "-o", out_path])
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            print("cgimg_check: не собрался драйвер src/_cgimg.z")
            return 1
        exe = out_path + ".elf"
        os.chmod(exe, 0o755)
        r = run([exe])
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            print("cgimg_check: драйвер упал")
            return 1

        lines = r.stdout.split("\n")

        def val(key):
            i = lines.index(key)
            return int(lines[i + 1])

        bad = 0
        for i in range(1, 15):
            got = (val("img%d len=" % i), val("img%d h=" % i))
            want = ref_hash[i]
            if got == want:
                print("cgimg img%d: len=%d h=%d OK" % (i, got[0], got[1]))
            else:
                print("cgimg img%d MISMATCH: selfhost=%r ref=%r" % (i, got, want))
                bad = 1
        if bad:
            return 1
    print("codegen-image src/_cgimg.z: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
