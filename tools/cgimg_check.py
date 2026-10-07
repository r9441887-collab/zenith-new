#!/usr/bin/env python3
"""Проверка склейки целого ELF-образа (cgGenerateWide -> cgBuildELF).

src/_cgimg.z держит два исходника (.z-литалы), гоняет их через selfhost
codegen и печатает длину + FNV-64 получившегося cgImg. Здесь те же исходники
вынимаются из литалов, компилируются РЕФЕРЕНСОМ (build/linux/zenith ... --no-opt)
и по ним считается та же пара (len, FNV-64) от байтов .elf.

--no-opt обязателен: эталонный optimizer.cpp в selfhost-драйвере ещё не
перенесён, поэтому сравниваем «как есть», без прохода оптимизатора.
"""
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "build", "linux", "zenith")
DRIVER = os.path.join(ROOT, "src", "_cgimg.z")

FNV_OFF = 0x4BF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv64(data: bytes) -> int:
    h = FNV_OFF
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return struct.unpack("<q", struct.pack("<Q", h))[0]


def extract_sources() -> list:
    src = open(DRIVER, encoding="utf-8").read()
    out = []
    for name in ("srcA", "srcB"):
        m = re.search(r'var %s: int = "((?:[^"\\]|\\.)*)"' % name, src)
        if not m:
            raise SystemExit("cgimg_check: не нашёл литерал %s в %s" % (name, DRIVER))
        out.append(bytes(m.group(1), "utf-8").decode("unicode_escape"))
    return out


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


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
            r = run([REF, path, "--no-opt", "-o", os.path.join(td, "r%d" % i)])
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                print("cgimg_check: эталон не собрал img%d" % i)
                return 1
            elf = os.path.join(td, "r%d.elf" % i)
            data = open(elf, "rb").read()
            ref_hash[i] = (len(data), fnv64(data))

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
        for i in (1, 2):
            tag = "img" + "AB"[i - 1]
            got = (val("%s len=" % tag), val("%s h=" % tag))
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
