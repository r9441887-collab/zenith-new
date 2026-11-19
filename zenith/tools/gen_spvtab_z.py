#!/usr/bin/env python3
"""tools/gen_spvtab_z.py — генерирует src/cg_spvtab.z из src/spvasm.h + src/spvasm.cpp.

Кодоген-бэкенд переносится на selfhost `.z` (см. NEXT.md, «Юнит»), а один из
его кусков — маленький SPIR-V ассемблер src/spvasm.cpp — опирается на две
таблицы строковых литералов (kOps: имя опкода -> номер; kEnums: имя енума ->
u32). В `.z` нет designated-initializer/constexpr-таблиц, поэтому таблицы
выплачиваются в виде if-цепочки по NUL-терминированным `.z`-литералам.

Таблицы читаются из C++-исходника, а не дублируются руками, чтобы номера
опкодов/енумов не разъезжались.

Запуск:  python3 tools/gen_spvtab_z.py
Выход:   src/cg_spvtab.z   (не править руками — перегенерировать)
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HDR = os.path.join(ROOT, "src", "spvasm.h")
SRC = os.path.join(ROOT, "src", "spvasm.cpp")
OUT = os.path.join(ROOT, "src", "cg_spvtab.z")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def parse_opcode_enum(text):
    m = re.search(r"enum\s+Opcode\s*:\s*uint32_t\s*\{(.*?)\};", text, re.S)
    if not m:
        sys.exit("enum Opcode не найден в spvasm.h")
    out = {}
    for name, val in re.findall(r"(\w+)\s*=\s*(\d+)", m.group(1)):
        out[name] = int(val)
    if not out:
        sys.exit("enum Opcode пуст")
    return out


def parse_kops(text):
    m = re.search(r"static const OpNameRec kOps\[\]\s*=\s*\{(.*?)\};", text, re.S)
    if not m:
        sys.exit("kOps не найден в spvasm.cpp")
    # {"OpAccessChain", OpAccessChain}, — имя в кавычках всегда == имени
    # идентификатора опкода, но берём идентификатор и резолвим по enum, чтобы
    # не доверять порядку.
    return re.findall(r"\{\s*\"[^\"]+\"\s*,\s*(\w+)\s*\}", m.group(1))


def parse_kenums(text):
    m = re.search(r"static const EnumLit kEnums\[\]\s*=\s*\{(.*?)\};", text, re.S)
    if not m:
        sys.exit("kEnums не найден в spvasm.cpp")
    body = re.sub(r"//[^\n]*", "", m.group(1))  # выкидываем комментарии
    return [(n, int(v)) for n, v in re.findall(r"\{\s*\"([^\"]+)\"\s*,\s*(-?\d+)\s*\}", body)]


def parse_result_first(text):
    m = re.search(
        r"static const std::unordered_set<uint32_t>\s+kResultFirst\s*=\s*\{(.*?)\};",
        text,
        re.S,
    )
    if not m:
        sys.exit("kResultFirst не найден в spvasm.cpp")
    return [n for n in re.findall(r"\b(\w+)\b", m.group(1))]


def zlit(s):
    """Экранировать строку как .z-литерал (только то, что реально встречается)."""
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\0":
            out.append("\\0")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def main():
    hdr = read(HDR)
    src = read(SRC)

    enum = parse_opcode_enum(hdr)
    kops = parse_kops(src)
    kenums = parse_kenums(src)
    first = parse_result_first(src)

    for op in kops:
        if op not in enum:
            sys.exit(f"kOps ссылается на неизвестный опкод {op}")
    for op in first:
        if op not in enum:
            sys.exit(f"kResultFirst ссылается на неизвестный опкод {op}")

    L = []
    a = L.append
    a("# src/cg_spvtab.z — СГЕНЕРИРОВАНО tools/gen_spvtab_z.py, НЕ РЕДАКТИРОВАТЬ.")
    a("#")
    a("# Таблицы SPIR-V ассемблера из spvasm.cpp:")
    a("#   cgSpvOpCode       <- kOps      (имя опкода -> номер)")
    a("#   cgSpvEnumVal      <- kEnums    (имя енума -> u32, первый матч выигрывает)")
    a("#   cgSpvResultFirst  <- kResultFirst (опкоды, чей result id идёт ПЕРВЫМ словом)")
    a("#")
    a("# Имена сравниваются побайтово со срезом (p,n) ассемблируемого текста и")
    a("# .z-литералом, поэтому нужен cgSliceEqLit: ZAST-строки тут ни при чём —")
    a("# текст шейдера лежит в ZAST-строке, а её токены — просто срезы байтов.")
    a(f"# Опкодов: {len(kops)}, енумов: {len(kenums)}, result-first: {len(first)}.")
    a("")
    a("func cgSliceEqLit(p: int, n: int, lit: int) -> int")
    a("    var m: int = cgLitLen(lit)")
    a("    if m != n")
    a("        return 0")
    a("    end")
    a("    var i: int = 0")
    a("    while i < n")
    a("        if peek8(p + i) != peek8(lit + i)")
    a("            return 0")
    a("        end")
    a("        i = i + 1")
    a("    end")
    a("    return 1")
    a("end")
    a("")
    a("# spvasm.cpp:98..103 lookupOpcode (линейный проход, как в C++)")
    a("func cgSpvOpCode(p: int, n: int) -> int")
    for op in kops:
        a(f"    if cgSliceEqLit(p, n, {zlit(op)})")
        a(f"        return {enum[op]}")
        a("    end")
    a("    return -1")
    a("end")
    a("")
    a("# spvasm.cpp:162..167 lookupEnum — порядок ОБЯЗАТЕЛЕН: kEnums содержит")
    a("# повторяющиеся имена (Uniform: StorageClass=2 до Decoration=26), и C++")
    a("# возвращает первый матч.")
    a("func cgSpvEnumVal(p: int, n: int) -> int")
    for name, val in kenums:
        a(f"    if cgSliceEqLit(p, n, {zlit(name)})")
        a(f"        return {val}")
        a("    end")
    a("    return -1")
    a("end")
    a("")
    a("# spvasm.cpp:301..305 kResultFirst — result id ПЕРЕД остальными операндами")
    a("# (без Result Type); у всех остальных — [Result Type][Result id]...")
    a("func cgSpvResultFirst(opcode: int) -> int")
    for op in first:
        a(f"    if opcode == {enum[op]}")
        a("        return 1")
        a("    end")
    a("    return 0")
    a("end")
    a("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"cg_spvtab.z: {len(kops)} опкодов, {len(kenums)} енумов, "
          f"{len(first)} result-first, {sum(len(x) for x in L)} строк")


if __name__ == "__main__":
    main()
