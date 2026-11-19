#!/usr/bin/env python3
"""Пересобирает cgSoundLutAppend() в src/cg_elf.z — 1024-байтовую sin-LUT.

codegen_elf.cpp:198..206 кладёт в .data восьмой слот soundUsed-блока:

    for (int i = 0; i < 512; i++) {
        double v = std::sin(2.0 * 3.14159265358979323846 * (double)i / 512.0);
        int16_t s = (int16_t)std::lround(v * 32767.0);
        data.push_back(s & 0xFF); data.push_back((s >> 8) & 0xFF);
    }

В порте нельзя звать sin(): Zenith-билтин sin — это x87 fsin поверх
float32-roundtrip (src/cg_expr.z:550, ровно так же его эмитит и C++ для
пользовательского кода), т.е. результат одинарной точности. std::sin в
эталоне — двойной. На 512 точках это даёт ровно одно расхождение (i=462:
-18868 против -18867), а образ обязан сойтись байт-в-байт, поэтому
таблица встроена литералом — так же, как kHttpdlBlob в cg_httpdl_blob.z.

Таблица считается math.sin (та же libm, что и std::sin) и проверена
против выходного файла эталона: р11.elf[0x3088..0x3188].

  python3 tools/gen_soundlut_z.py          # переписать функцию в src/cg_elf.z
  python3 tools/gen_soundlut_z.py --print   # только показать
"""
import math
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELF = os.path.join(ROOT, "src/cg_elf.z")

BEG = "# --- BEGIN cgSoundLutAppend (auto: tools/gen_soundlut_z.py) ---"
END = "# --- END cgSoundLutAppend ---"

PI = 3.14159265358979323846


def table() -> bytes:
    out = bytearray()
    for i in range(512):
        v = math.sin(2.0 * PI * float(i) / 512.0)
        x = v * 32767.0
        s = math.floor(x + 0.5) if x >= 0 else math.ceil(x - 0.5)
        out += struct.pack("<h", int(s))
    assert len(out) == 1024
    return bytes(out)


ESCAPE = {0x5C: b"\\\\", 0x22: b'\\"', 0x0A: b"\\n",
          0x0D: b"\\r", 0x09: b"\\t", 0x00: b"\\0"}


def literal(data: bytes) -> bytes:
    """Лексер знает только \\n \\t \\r \\\\ \\" \\0 (см. cg_httpdl_blob.z)."""
    out = bytearray()
    for c in data:
        out += ESCAPE.get(c, bytes([c]))
    return bytes(out)


def fn_bytes(data: bytes) -> bytes:
    return (
        BEG.encode() + b"\n"
        + b"func cgSoundLutAppend()\n"
        + b"    var p: int = \"" + literal(data) + b"\"\n"
        + b"    var i: int = 0\n"
        + b"    while i < 1024\n"
        + b"        cgDataPush(peek8(p + i))\n"
        + b"        i = i + 1\n"
        + b"    end\n"
        + b"end\n"
        + END.encode()
    )


LOOP_OLD = """        cgSoundLutRVA = cgDataRVA + cgDataLen
        # std::lround(sin(2*pi*i/512) * 32767) — half-away-from-zero.
        var si: int = 0
        while si < 512
            var v: float = sin(2.0 * 3.14159265358979323846 * itof(si) / 512.0)
            var x: float = v * 32767.0
            var r: float = 0.0
            if x >= 0.0
                r = floor(x + 0.5)
            else
                r = ceil(x - 0.5)
            end
            var s: int = r
            cgDataPush(s & 0xFF)
            cgDataPush((s >> 8) & 0xFF)
            si = si + 1
        end
"""
LOOP_NEW = """        cgSoundLutRVA = cgDataRVA + cgDataLen
        cgSoundLutAppend()
"""

ANCHOR = "func cgBuildLinuxImportData()"


def main() -> int:
    data = table()
    if "--print" in sys.argv:
        sys.stdout.buffer.write(fn_bytes(data))
        return 0
    raw = open(ELF, "rb").read()
    if BEG.encode() in raw:
        head = raw[: raw.index(BEG.encode())]
        tail = raw[raw.index(END.encode()) + len(END):]
        raw = head + fn_bytes(data) + tail
    else:
        i = raw.index(ANCHOR.encode())
        raw = raw[:i] + fn_bytes(data) + b"\n\n" + raw[i:]
    if LOOP_OLD.encode() in raw:
        raw = raw.replace(LOOP_OLD.encode(), LOOP_NEW.encode(), 1)
    elif LOOP_NEW.encode() not in raw:
        raise SystemExit("gen_soundlut_z: не нашёл ни цикл, ни cgSoundLutAppend()")
    open(ELF, "wb").write(raw)
    print("gen_soundlut_z: ok (1024 bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
