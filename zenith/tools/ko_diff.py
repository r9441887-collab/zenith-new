#!/usr/bin/env python3
"""Ищет ПЕРВЫЙ отличающийся байт между selfhost cgImg и эталоном для
контейнеров img4 (--obj -> ET_REL .o) и img5 (driver -> ET_REL .ko).

Запускает src/_cgdbg.z (печатает префиксный FNV-64 для каждого смещения) и
считает те же префиксы от эталонных байтов build/linux/zenith. Первое
расхождение префиксов = индекс первого различающегося байта.

  python3 tools/ko_diff.py
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
DBG = os.path.join(ROOT, "src", "_cgdbg.z")
TMP = "/tmp"
KO_DIR = os.path.join(TMP, "zenith_ko_1")
FAKE = "/tmp/zenith_fake_gcc"

FNV_OFF = 0x4BF29CE484222325
FNV_PRIME = 0x100000001B3
MASK = (1 << 64) - 1
PRIME_INV = pow(FNV_PRIME, -1, 1 << 64)


def fnv64(data: bytes) -> int:
    h = FNV_OFF
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK
    return struct.unpack("<q", struct.pack("<Q", h))[0]


def u(v: int) -> int:
    """signed int64 -> unsigned 64 (драйвер печатает хеши как int64)."""
    return v & MASK


def recover(pref: dict) -> bytes:
    """Восстанавливает байты из префиксных FNV-хешей: h_k = (h_{k-1} ^ b) * p
    -> b = (h_k * p^-1) ^ h_{k-1}. На выходе байты [0 .. max_k]."""
    out = bytearray()
    prev = FNV_OFF
    for k in sorted(pref):
        h = u(pref[k])
        b = ((h * PRIME_INV) & MASK) ^ prev
        if k != len(out):
            raise SystemExit("ko_diff: дырка в префиксах на %d" % k)
        out.append(b & 0xFF)
        prev = h
    return bytes(out)


def env(fake=False):
    e = dict(os.environ)
    e["TMPDIR"] = TMP
    if fake:
        os.makedirs(FAKE, exist_ok=True)
        p = os.path.join(FAKE, "gcc")
        open(p, "w").write("#!/bin/sh\nexit 1\n")
        os.chmod(p, 0o755)
        e["PATH"] = FAKE + os.pathsep + e.get("PATH", "")
    return e


def run(cmd, fake=False):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env(fake))


def ref_case(tag, src, args, fake):
    """Пишет эталон в td/<tag> и возвращает байты ET_REL."""
    path = os.path.join(td, tag + ".z")
    open(path, "w", encoding="utf-8").write(src)
    base = os.path.join(td, tag)
    if fake:
        shutil.rmtree(KO_DIR, ignore_errors=True)
    r = run([REF, path, "--no-opt"] + args + ["-o", base], fake=fake)
    if fake:
        obj = os.path.join(KO_DIR, tag + ".o")
    else:
        obj = base + ".o"
    if not os.path.exists(obj):
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit("нет эталона %s" % obj)
    return open(obj, "rb").read()


def extract(name):
    s = open(DBG, encoding="utf-8").read()
    m = re.search(r'var %s: int = "((?:[^"\\]|\\.)*)"' % name, s)
    return bytes(m.group(1), "utf-8").decode("unicode_escape")


def main() -> int:
    global td
    if not os.path.exists(REF):
        sys.exit("нет эталона %s" % REF)
    srcD = extract("srcD")
    srcE = extract("srcE")

    exe = None
    with tempfile.TemporaryDirectory(prefix="kodiff") as td:
        refs = {
            "D": ref_case("srcD", srcD, ["--obj"], False),
            "E": ref_case("srcE", srcE, [], True),
        }

        out = os.path.join(td, "cgdbg")
        r = run([REF, DBG, "-o", out])
        if r.returncode != 0:
            sys.stderr.write(r.stdout + r.stderr)
            sys.exit("не собрался src/_cgdbg.z")
        exe = out + ".elf"
        os.chmod(exe, 0o755)
        r = run([exe])
        if r.returncode != 0:
            sys.stderr.write(r.stdout + r.stderr)
            sys.exit("драйвер упал")

        # разбор stdout. В .z print() всегда пишет перевод строки, поэтому
        # ключ печатается отдельными токенами: "D=", "1448", "P", "0", "=", h
        toks = [t for t in r.stdout.split("\n") if t.strip() != ""]
        cur = None
        pref = {}
        lens = {}
        i = 0
        while i < len(toks):
            t = toks[i]
            if t in ("D=", "E="):
                cur = t[0]
                lens[cur] = int(toks[i + 1])
                i += 2
            elif t == "P" and i + 3 < len(toks):
                k = int(toks[i + 1])
                if toks[i + 2] != "=":
                    sys.exit("сломанный разбор вывода: %r" % (toks[i:i + 4],))
                pref.setdefault(cur, {})[k] = int(toks[i + 3])
                i += 4
            else:
                i += 1

        bad = 0
        for tag in ("D", "E"):
            ref = refs[tag]
            n = lens.get(tag)
            if n is None:
                sys.exit("нет длины блока %s" % tag)
            selfb = recover(pref[tag])
            open("/tmp/opencode/%s_self.bin" % tag, "wb").write(selfb)
            open("/tmp/opencode/%s_ref.bin" % tag, "wb").write(ref)
            if n != len(ref):
                print("%s: длина selfhost=%d ref=%d" % (tag, n, len(ref)))
                bad = 1
            first = None
            for k in range(0, min(len(selfb), len(ref))):
                if selfb[k] != ref[k]:
                    first = k
                    break
            if first is None:
                print("%s: байты [0..%d) совпадают" % (tag, len(selfb)))
                if len(selfb) != len(ref):
                    bad = 1
                continue
            lo = max(0, first - 16)
            hi = min(len(ref), first + 16)
            print("%s: первый отличающийся байт = %d (из %d)" % (tag, first, n))
            print("  selfhost[%d:%d] = %s" % (lo, hi, selfb[lo:hi].hex()))
            print("  ref     [%d:%d] = %s" % (lo, hi, ref[lo:hi].hex()))
            bad = 1
        return bad


if __name__ == "__main__":
    sys.exit(main())
