#!/usr/bin/env python3
"""Проверка фронтенда (lexer/parser/AST) в статическом без-libc ELF.

«часть 20». Три selfhost-драйвера гоняются двумя путями и сверяются
байт-в-байт:

  REF   build/linux/zenith selfhost/_X.z --no-opt -> ref_X.elf
  SELF  src/_cgfront.z (харнесс, собран ЭТАЛОНОМ): склеенный исходник
        (srcprep_dump, потому что parseRun не раскрывает `use`) ->
        parseRun -> cgBind -> cgGenerateWide() -> build/linux/cgfront_out.elf

Для каждого таргета:
  1. пара (len, FNV-64) от cgImg против эталонного .elf;
  2. при расхождении — диф байт (первые смещения);
  3. оба .elf запускаются, сравниваются stdout/stderr/rc;
  4. статичность САМОГО артефакта: ровно 2 program headers, нет
     PT_INTERP и PT_DYNAMIC, т.е. печать через write(1), выход через
     exit_group, память — bump-хип в .bss (alloc), ни одного libc
     импорта. Харнесс — инструмент и может пользоваться libc.

--no-opt обязателен: optimizer.cpp в selfhost-кодеогене ещё нет.
Темп-файлы кладутся в build/ (корень диска почти полон, /tmp не трогаем).
"""
import glob
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, "build", "linux", "zenith")
HARNESS_SRC = os.path.join(ROOT, "src", "_cgfront.z")
HARNESS = os.path.join(ROOT, "build", "linux", "cgfront.elf")
SRCPREP = os.path.join(ROOT, "build", "linux", "srcprep_dump")
SRCPREP_SRC = os.path.join(ROOT, "tools", "srcprep_dump.cpp")
IN_PATH = os.path.join(ROOT, "build", "linux", "cgfront_in.z")
OUT_PATH = os.path.join(ROOT, "build", "linux", "cgfront_out.elf")

TARGETS = (
    ("_lexdrv", os.path.join("selfhost", "_lexdrv.z")),
    ("_astdrv", os.path.join("selfhost", "_astdrv.z")),
    ("_parsdrv", os.path.join("selfhost", "_parsdrv.z")),
)

# «часть 21»: vk-смоук (mini-dlopen + стабы libc). Эталон (C++) печатает
# vkrun динамически (PT_INTERP + DT_NEEDED libvulkan/libc), selfhost —
# статично с собственным лоадером, поэтому байтовый паритет неприменим
# по построению: сравниваем рантайм (rc/stdout/stderr) + статичность self.
VK_SRC = os.path.join(ROOT, "tools", "cgemit", "vkrun.z")
VK_REF = os.path.join(ROOT, "build", "vkrun_ref.elf")

FNV_OFF = 0x4BF29CE484222325
FNV_PRIME = 0x100000001B3

PT_DYNAMIC = 2
PT_INTERP = 3


def fnv64(data: bytes) -> int:
    h = FNV_OFF
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return struct.unpack("<q", struct.pack("<Q", h))[0]


def run(cmd, timeout=900, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, **kw)


def build_srcprep():
    if os.path.exists(SRCPREP) and os.path.getmtime(SRCPREP) >= max(
            os.path.getmtime(SRCPREP_SRC),
            os.path.getmtime(os.path.join(ROOT, "src", "use_resolver.cpp")),
            os.path.getmtime(os.path.join(ROOT, "tools", "srcprep.h"))):
        return
    r = run(["g++", "-O2", "-std=c++17", "-w", "-o", SRCPREP,
             SRCPREP_SRC, os.path.join(ROOT, "src", "use_resolver.cpp")])
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        raise SystemExit("cgfront_check: не собрался srcprep_dump")


def build_harness():
    deps = [HARNESS_SRC] + sorted(glob.glob(os.path.join(ROOT, "src", "cg_*.z")))
    stale = not os.path.exists(HARNESS) or any(
        os.path.getmtime(d) > os.path.getmtime(HARNESS) for d in deps)
    if not stale:
        return
    base = os.path.join(ROOT, "build", "linux", "cgfront")
    r = run([REF, HARNESS_SRC, "--no-opt", "-o", base], timeout=1800)
    if r.returncode != 0 or not os.path.exists(base + ".elf"):
        print(r.stdout + r.stderr)
        raise SystemExit("cgfront_check: не собрался харнесс src/_cgfront.z")
    os.chmod(base + ".elf", 0o755)


def build_vk_ref():
    """Эталонный vkrun (динамическая линковка — только для сравнения вывода)."""
    base = os.path.join(ROOT, "build", "vkrun_ref")
    r = run([REF, VK_SRC, "--no-opt", "-o", base], timeout=600)
    if r.returncode != 0 or not os.path.exists(VK_REF):
        print(r.stdout + r.stderr)
        raise SystemExit("cgfront_check: не собрался эталон vkrun")
    os.chmod(VK_REF, 0o755)


def splice(path: str) -> bytes:
    r = subprocess.run([SRCPREP, path], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode("utf-8", "replace"))
        raise SystemExit("cgfront_check: не склеился %s" % path)
    return r.stdout


def harness_pair(spliced: bytes):
    """Кладёт сплайс, гоняет харнесс, возвращает (len, FNV-64)."""
    with open(IN_PATH, "wb") as f:
        f.write(spliced)
    r = run([HARNESS], timeout=600)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        raise SystemExit("cgfront_check: харнесс упал")
    lines = r.stdout.split("\n")

    def val(key):
        try:
            i = lines.index(key)
        except ValueError:
            print(r.stdout + r.stderr)
            raise SystemExit("cgfront_check: в выводе харнесса нет %r" % key)
        return int(lines[i + 1])

    return val("front len="), val("front h=")


def elf_phtypes(data: bytes):
    """Типы program headers (e_phoff/e_phentsize/e_phnum, ELF64)."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("cgfront_check: это не ELF64")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    types = []
    for i in range(phnum):
        off = phoff + i * phentsize
        types.append(struct.unpack_from("<I", data, off)[0])
    return types


def check_static(name: str, data: bytes) -> int:
    types = elf_phtypes(data)
    bad = 0
    if len(types) != 2:
        print("cgfront %s: ожидалось 2 program headers, есть %d" % (name, len(types)))
        bad = 1
    if PT_INTERP in types:
        print("cgfront %s: есть PT_INTERP (динамический линкер)" % name)
        bad = 1
    if PT_DYNAMIC in types:
        print("cgfront %s: есть PT_DYNAMIC -> DT_NEEDED откуда-то есть" % name)
        bad = 1
    return bad


def run_elf(path: str):
    os.chmod(path, 0o755)
    r = subprocess.run([path], cwd=ROOT, capture_output=True, text=True,
                       timeout=300)
    return r.returncode, r.stdout, r.stderr


def byte_diff(a: bytes, b: bytes, limit: int = 8) -> str:
    offs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]][:limit]
    return ", ".join("0x%x" % i for i in offs)


def main() -> int:
    if not os.path.exists(REF):
        print("cgfront_check: нет эталона %s" % REF)
        return 1
    build_srcprep()
    build_harness()

    bad = 0
    with tempfile.TemporaryDirectory(prefix="cgfront",
                                     dir=os.path.join(ROOT, "build")) as td:
        for name, rel in TARGETS:
            path = os.path.join(ROOT, rel)
            if not os.path.exists(path):
                print("cgfront_check: нет таргета %s" % rel)
                return 1
            ref_base = os.path.join(td, "ref_" + name)
            r = run([REF, path, "--no-opt", "-o", ref_base])
            ref_elf_path = ref_base + ".elf"
            if r.returncode != 0 or not os.path.exists(ref_elf_path):
                print(r.stdout + r.stderr)
                print("cgfront_check: эталон не собрал %s" % rel)
                return 1
            ref_data = open(ref_elf_path, "rb").read()

            got = harness_pair(splice(path))
            want = (len(ref_data), fnv64(ref_data))
            if got != want:
                print("cgfront %s MISMATCH: selfhost=%r ref=%r" % (name, got, want))
                self_data = open(OUT_PATH, "rb").read() if os.path.exists(OUT_PATH) else b""
                if len(self_data) == len(ref_data):
                    print("  first diffs: %s" % byte_diff(self_data, ref_data))
                bad = 1
                continue

            self_data = open(OUT_PATH, "rb").read()
            bad |= check_static(name, self_data)
            rc_r, out_r, err_r = run_elf(ref_elf_path)
            rc_s, out_s, err_s = run_elf(OUT_PATH)
            if (rc_r, out_r, err_r) != (rc_s, out_s, err_s):
                print("cgfront %s: различие вывода:" % name)
                print("  ref rc=%d out=%r err=%r" % (rc_r, out_r, err_r))
                print("  slf rc=%d out=%r err=%r" % (rc_s, out_s, err_s))
                bad = 1
                continue
            if rc_r != 0:
                print("cgfront %s: драйвер упал rc=%d: %s" % (name, rc_r, err_r))
                bad = 1
                continue
            print("cgfront %s: len=%d h=%d OK (static, run OK)" % (name, want[0], want[1]))

        if not os.path.exists(VK_SRC):
            print("cgfront vk: нет таргета %s" % VK_SRC)
            bad = 1
        else:
            build_vk_ref()
            got = harness_pair(splice(VK_SRC))
            self_data = open(OUT_PATH, "rb").read()
            bad |= check_static("vk", self_data)
            rc_r, out_r, err_r = run_elf(VK_REF)
            rc_s, out_s, err_s = run_elf(OUT_PATH)
            if (rc_r, out_r, err_r) != (rc_s, out_s, err_s):
                print("cgfront vk: различие вывода:")
                print("  ref rc=%d out=%r err=%r" % (rc_r, out_r, err_r))
                print("  slf rc=%d out=%r err=%r" % (rc_s, out_s, err_s))
                bad = 1
            elif rc_s != 0:
                print("cgfront vk: смоук упал rc=%d: %s" % (rc_s, err_s))
                bad = 1
            else:
                print("cgfront vk: len=%d h=%d OK (static, runtime parity)"
                      % got)
    if bad:
        return 1
    print("codegen-front selfhost/lexer+parser+ast: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
