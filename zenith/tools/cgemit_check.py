#!/usr/bin/env python3
"""Byte-for-byte differential test for src/codegen.z against src/codegen.cpp.

For every `return <expr>` in the given program this script compares the bytes
codegen.z emits with the bytes the C++ backend emits for the same function.
The C++ side is the reference (`zenith --obj --no-opt`, objdump of .o); the
.z side is produced by the generated harness src/_cgemit.z.

  python3 tools/cgemit_check.py tests/cgemit/expr.z
  python3 tools/cgemit_check.py -o <program>   # regenerate src/_cgemit.z only
  python3 tools/cgemit_check.py -b <program>   # mode B: plain-ELF reference

--no-opt matters: the AST optimizer strength-reduces `x * 2` into a shift and
folds constants, so with optimization on the two sides would legitimately
disagree.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, 'build/linux/zenith')

HARNESS_TEMPLATE = """# codegen.z emission differential harness — GENERATED, do not edit by hand.
# Source of truth: tools/cgemit_check.py (which regenerates this file from the
# template at the top of that script and runs the comparison).
#
# It parses the same program the C++ compiler sees and, for every function,
# replays the whole of emitFunction (codegen.cpp:7645) through cgEmitFunction:
# prologue, parameter copies, every statement of the body, epilogue. It then
# prints the byte length, an FNV hash and the raw bytes. tools/cgemit_check.py
# compares those bytes against what the C++ backend produced for the same
# function (objdump of `zenith --obj --no-opt`), so a transcription slip
# anywhere in the ported emitters shows up as a missing substring.
app console
use ../selfhost/parser
use codegen

var gTmp: int = 0

func pbHexBytes(p: int, n: int)
    if gTmp == 0
        gTmp = alloc(8192)
    end
    var i: int = 0
    while i < n
        var v: int = peek8(p + i)
        var hi: int = v / 16
        var lo: int = v % 16
        var a: int = 48
        if hi > 9
            a = 87
        end
        poke8(gTmp + i * 2, a + hi)
        var b: int = 48
        if lo > 9
            b = 87
        end
        poke8(gTmp + i * 2 + 1, b + lo)
        i = i + 1
    end
    poke8(gTmp + n * 2, 0)
    pbLit(gTmp)
end

func pbName(id: int)
    if gTmp == 0
        gTmp = alloc(8192)
    end
    var p: int = cgStrPtr(id)
    var n: int = cgStrLen(id)
    if n > 500
        n = 500
    end
    var i: int = 0
    while i < n
        poke8(gTmp + i, peek8(p + i))
        i = i + 1
    end
    poke8(gTmp + n, 0)
    pbLit(gTmp)
end

# per-function code/register reset. Unlike cgReset() the label counter is
# deliberately left alone: codegen.cpp keeps one nextLabel for the whole
# translation unit, so the ids in function N depend on functions 0..N-1.
# The relocation tables ARE reset: they never influence emitted bytes, and
# per-function reset is what lets pbMask() report only this function's slots.
func cgPerFuncReset()
    cgCodeLen = 0
    cgRegsUsed = 0
    cgXmmUsed = 0
    cgFixN = 0
    cgFixReset()
    cgStrFixN = 0
    cgKoStrFixN = 0
    # The http_json helper is built into .text exactly once per translation
    # unit (codegen.h:521), so cgHttpJsonHelperEmitted is a TU-wide one-shot.
    # Each per-function emission here is its own TU, and the whole-TU pass
    # calls this once before laying out all of them — which is exactly what
    # generateWide does for the real backend.
    cgHttpJsonHelperEmitted = 0
    cgHttpJsonHelperLabel = -1
end

# Every fixup slot is a 4-byte immediate whose value the C++ backend fills in
# from the final image layout (call rel32 to another function, rip-relative
# LEA to a global/string, GOT slot). The harness emits one function at a time
# into a fresh buffer, so those absolute positions cannot match — the harness
# prints the slots instead and tools/cgemit_check.py compares every OTHER byte
# exactly. Revisit once emitFunction lands and the whole translation unit is
# laid out in one buffer.
func pbMask()
    pbLit(" mask=")
    var first: int = 1
    var i: int = 0
    while i < cgCallFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgCallFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgFuncRefN
        if first == 0
            pbLit(",")
        end
        pbNum(cgFuncRefPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgGlobalFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgGlobalFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgStrFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgStrFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgKoStrFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgKoStrFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgElfImpN
        if first == 0
            pbLit(",")
        end
        pbNum(cgElfImpPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgImpCallN
        if first == 0
            pbLit(",")
        end
        pbNum(cgImpCallPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgHeapFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgHeapFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgNetFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgNetFixPos[i])
        first = 0
        i = i + 1
    end
    if first == 1
        pbLit("-")
    end
end

# Mask for the whole-TU line: unlike pbMask() this one does NOT hide
# call/funcRef slots, because that pass runs cgResolveFixups() which patches
# them from funcOffsets — so they have to match byte for byte too. What stays
# wild is only what buildELF is still going to fill in: rip-relative LEA to a
# global / string, the GOT slots of elfImportFixups, heap slots, the KO and
# network fixups.
func pbMaskWhole()
    pbLit(" mask=")
    var first: int = 1
    var i: int = 0
    while i < cgGlobalFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgGlobalFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgStrFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgStrFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgKoStrFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgKoStrFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgElfImpN
        if first == 0
            pbLit(",")
        end
        pbNum(cgElfImpPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgImpCallN
        if first == 0
            pbLit(",")
        end
        pbNum(cgImpCallPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgHeapFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgHeapFixPos[i])
        first = 0
        i = i + 1
    end
    i = 0
    while i < cgNetFixN
        if first == 0
            pbLit(",")
        end
        pbNum(cgNetFixPos[i])
        first = 0
        i = i + 1
    end
    if first == 1
        pbLit("-")
    end
end

# Same non-canonical FNV-1a basis as codegen.z's smoke hashes (the lexer
# rejects literals >= 2^63).
func cgFNV(p: int, n: int) -> int
    var h: int = 0x4BF29CE484222325
    var i: int = 0
    while i < n
        h = h ^ peek8(p + i)
        h = h * 0x100000001B3
        i = i + 1
    end
    return h
end

func main() -> int
    var src: int = "@SRCLITERAL@"
    var rc: int = parseRun(src, strLen(src))
    if rc != 0
        poke8(parseErrMsg() + parseErrMsgLen(), 0)
        pbInit()
        pbLit("parse rc=")
        pbNum(rc)
        pbLit(" msg=")
        pbLit(parseErrMsg())
        pbFlush()
        exit(1)
    end
    cgBind(parseOutPtr(), parseOutLen())
    cgComputeStructLayouts()
    cgWordSize = 64
    # codegen.cpp:8576 sets isLinux/sysvAbi from appType alone. Derive them
    # from the ZAST `app ...` line instead of assuming Linux: `app console` is
    # what unlocks the `!isLinux` inline arms (print, http_download*), and a
    # wrong isLinux would silently compare a different branch.
    cgIsLinux = 0
    cgSysvAbi = 0
    if cgH(H_APPTYPE) == 8
        cgIsLinux = 1
        cgSysvAbi = 1
    end
@FLAGS@
    cgInit()
    cgFuncEndLabel = -1

    var fs: int = cgH(H_FUNCS)
    var fl: int = cgH(H_FUNCS + 1)
    var fi: int = 0
    while fi < fl
        var fid: int = cgSide(fs + fi)
        if cgTag(fid) == N_FUNC && cgF(fid, 11) == 0
            cgPerFuncReset()
            cgEmitFunction(fid)
            cgApplyFixups(0)
            pbInit()
            pbName(cgF(fid, 0))
            pbLit(" len=")
            pbNum(cgCodeLen)
            pbMask()
            pbLit(" h=")
            pbNum(cgFNV(cgCode, cgCodeLen))
            pbLit(" ")
            pbHexBytes(cgCode, cgCodeLen)
            pbFlush()
        end
        fi = fi + 1
    end
@WHOLE@
    if cgHasErr() != 0
        eprintln(cgErrText())
        exit(1)
    end
    parseRelease()
    exit(0)
end
"""


MODE_A_FLAGS = """    # The reference is `zenith --obj --no-opt`, and main.cpp:1407 forces
    # koDriver=true whenever objOutput=true. Without these two the .z side
    # would take the `!koDriver`/`!objOutput` arms (alloc/free/arena/slotCreate,
    # extern-call GOT slot, string pool) that the reference does not take.
    cgObjOutput = 1
    cgKoDriverFlag = 1"""

# Mode B exists because buildKO() (codegen_ko.cpp:216) rejects heapFixups —
# `zenith --obj` literally refuses alloc/arenaCreate/poolCreate/slotCreate with
# "'alloc/free (heap builtins)' is not available in driver (kernel-module) mode".
# Those arms are gated on `!prog.koDriver`, so the reference has to be a plain
# ELF executable (`zenith --no-opt`, no --obj) and the harness must clear both
# flags to take the same branch.
MODE_B_FLAGS = """    cgObjOutput = 0
    cgKoDriverFlag = 0"""

WHOLE_TU_B = '''
    # ---- whole translation unit + _start in ONE buffer ----
    #
    # The per-function lines above start from a fresh buffer each time, so
    # `call rel32` targets cannot agree with the reference and pbMask() hides
    # them. This pass lays the entire .text out exactly like generateWide does
    # — every function in declaration order, then emitLinuxEntryPoint() — runs
    # cgResolveFixups() so the call displacements are real, and lets
    # tools/cgemit_check.py search for the result inside the reference's
    # executable segment. A mismatch here means the orchestration itself (or
    # the entry point) is wrong, not just one emitter.
    cgPerFuncReset()
    cgFuncOffsetsReset()
    var wf: int = cgH(H_FUNCS)
    var wl: int = cgH(H_FUNCS + 1)
    var wi: int = 0
    while wi < wl
        var wfid: int = cgSide(wf + wi)
        if cgTag(wfid) == N_FUNC
            cgEmitFunction(wfid)
        end
        wi = wi + 1
    end
    # `_start` only exists on the ELF path; a Windows/EFI/bare target follows
    # with emitEntryPoint() (codegen_pe.cpp, layer 2, unported), so the buffer
    # stops right after the last function — still a prefix of the reference
    # .text, which is what find_masked() looks for.
    # Часть 21: функции self больше не пушат импорты (syscall-only), а
    # эталонный C++ входит через exit-via-libc, потому что его callRipImport
    # импорты пушит. Whole-TU строка проверяет оркестровку (все функции +
    # пролог entry), поэтому для vk-программ накручиваем счётчик импортов
    # и снимаем ошибку запрета — ХАРНЕСС, не образ; образ всегда идёт через
    # raw exit. Не-vk программы в C++ тоже без импортов → raw exit без фейка.
    if cgIsLinux != 0
        if cgVkUsed != 0 && cgElfImpN == 0
            cgElfImpN = 1
            cgHarnessImportParity = 1
        end
        cgEmitLinuxEntryPoint()
        cgHarnessImportParity = 0
    end
    cgResolveFixups()
    cgApplyFixups(0)
    pbInit()
    pbLit("_text len=")
    pbNum(cgCodeLen)
    pbMaskWhole()
    pbLit(" h=")
    pbNum(cgFNV(cgCode, cgCodeLen))
    pbLit(" ")
    pbHexBytes(cgCode, cgCodeLen)
    pbFlush()
'''


def gen_harness(program_src, mode_b=False):
    lit = program_src.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    flags = MODE_B_FLAGS if mode_b else MODE_A_FLAGS
    # The whole-TU pass needs the ELF entry point, which only exists on the
    # plain-executable path (`--obj` takes the KO entry instead, unported).
    whole = WHOLE_TU_B if mode_b else ''
    return (HARNESS_TEMPLATE.replace('@SRCLITERAL@', lit)
            .replace('@FLAGS@', flags)
            .replace('@WHOLE@', whole))


def build(path, out):
    """Compile `path`, failing loudly on diagnostics.

    zenith returns rc=0 even for `Lexer error`/`Parser error` (it drops the
    offending token and keeps going), so a bad .z file would otherwise "pass"
    the parity check with a half-parsed program. Any diagnostic line is fatal.
    """
    r = subprocess.run([BIN, path, '-o', out], cwd=ROOT, capture_output=True, text=True)
    bad = [l for l in (r.stdout + r.stderr).splitlines() if is_diag(l)]
    if r.returncode != 0 or bad:
        for l in bad:
            sys.stderr.write(l + '\n')
        if not bad:
            sys.stderr.write(r.stdout + r.stderr)
        sys.exit('build failed: ' + path)


def is_diag(line):
    if line.startswith('Warning:') or line.startswith('Optimized'):
        return False
    return ('Lexer error' in line or 'Parser error' in line or 'Unexpected token' in line
            or line.startswith('Error') or 'error at line' in line.lower())


def objdump_funcs(obj):
    out = subprocess.run(['objdump', '-d', '--insn-width=16', obj],
                         capture_output=True, text=True).stdout
    funcs, cur = {}, None
    for line in out.splitlines():
        m = re.match(r'^[0-9a-f]+\s+<(.+)>:$', line)
        if m:
            cur = m.group(1)
            funcs[cur] = bytearray()
            continue
        if cur is None:
            continue
        m = re.match(r'^\s*[0-9a-f]+:\t(([0-9a-f]{2} )+)', line)
        if m:
            funcs[cur] += bytes(int(b, 16) for b in m.group(1).split())
    return funcs


def elf_exec_bytes(path):
    """Raw executable segment bytes of a Zenith-generated ELF ET_EXEC.

    Mode B's reference is a plain `zenith --no-opt` link, and codegen_elf.cpp
    writes no section headers at all ("no section header" in file(1)), so
    objdump has nothing to disassemble and there is no .symtab to split it
    into functions. The whole file is scanned as one blob instead: find_masked
    looks for each harness function inside it, exactly the way mode A's
    per-function objdump output is searched.
    """
    data = open(path, 'rb').read()
    if data[:4] != b'\x7fELF':
        sys.exit(path + ' is not an ELF file')
    phoff = int.from_bytes(data[32:40], 'little')
    phentsize = int.from_bytes(data[54:56], 'little')
    phnum = int.from_bytes(data[56:58], 'little')
    out = bytearray()
    for i in range(phnum):
        o = phoff + i * phentsize
        ptype = int.from_bytes(data[o:o + 4], 'little')
        pflags = int.from_bytes(data[o + 4:o + 8], 'little')
        poff = int.from_bytes(data[o + 8:o + 16], 'little')
        filesz = int.from_bytes(data[o + 32:o + 40], 'little')
        if ptype == 1 and (pflags & 1):  # PT_LOAD + PF_X
            out += data[poff:poff + filesz]
    if not out:
        sys.exit(path + ' has no executable PT_LOAD segment')
    return out


def pe_text_bytes(path):
    """Raw .text bytes of a Windows PE (PE32+) reference image.

    Mode B references that are NOT Linux targets (`app gui`, `app efi`,
    `app bare`, ...) never take the isLinux codegen path, and they also never
    produce an ELF: codegen_pe.cpp/efi/bios write a PE or a flat .bin, and
    codegen_elf.cpp is unreachable. objdump *can* read those (pei-x86-64), but
    the flat `.bin` cannot, so the .text section is parsed straight out of the
    file instead — find_masked then scans it the way it scans the ELF segment.
    """
    data = open(path, 'rb').read()
    if data[:2] == b'MZ':
        pe = int.from_bytes(data[0x3c:0x40], 'little')
        if data[pe:pe + 4] != b'PE\x00\x00':
            sys.exit(path + ': MZ without a PE header')
        nsec = int.from_bytes(data[pe + 6:pe + 8], 'little')
        optsz = int.from_bytes(data[pe + 20:pe + 22], 'little')
        sect = pe + 24 + optsz
        for i in range(nsec):
            o = sect + i * 40
            if data[o:o + 5] == b'.text':
                rawsz = int.from_bytes(data[o + 16:o + 20], 'little')
                rawptr = int.from_bytes(data[o + 20:o + 24], 'little')
                return data[rawptr:rawptr + rawsz]
        sys.exit(path + ' has no .text section')
    if data[:4] == b'\x7fELF':
        return elf_exec_bytes(path)
    if data[:4] == b'MZ\x00\x00':
        sys.exit(path + ': unknown image')
    return data  # flat firmware image (app bare / app bios)


def ref_image(stem, mode_b):
    """Locate the reference image `stem` produced and decode it to raw bytes.

    The extension depends on the app type: Linux -> stem+'.elf',
    GUI/EFI/Bare write to the bare `-o` path or '.efi'/'.bin'.
    """
    cands = [stem + '.elf', stem + '.efi', stem + '.bin', stem]
    for c in cands:
        if os.path.exists(c):
            return pe_text_bytes(c)
    sys.exit('no reference image among: ' + ' '.join(cands))


LINE_RE = re.compile(r'^(\S+) len=(\d+) mask=(\S+) h=(-?\d+) ([0-9a-f]+)$')


def find_masked(hb, ref, masks):
    """Offset of hb inside ref, ignoring the 4-byte reloc slots in `masks`.

    A reloc slot holds an address from the C++ backend's *final* layout (call
    rel32 to another function, rip-relative LEA to a global/string, GOT slot).
    The harness emits one function per fresh buffer, so those addresses cannot
    agree before emitFunction lays the whole translation unit out in one
    buffer — every other byte still has to match exactly.
    """
    wild = set()
    for p in masks:
        wild.update(range(p, p + 4))
    n = len(hb)
    idx = [i for i in range(n) if i not in wild]
    for d in range(0, len(ref) - n + 1):
        for i in idx:
            if ref[d + i] != hb[i]:
                break
        else:
            return d, len(wild)
    return -1, len(wild)


def main(argv):
    regen_only = False
    mode_b = False
    while argv and argv[0] in ('-o', '-b'):
        if argv[0] == '-o':
            regen_only = True
        else:
            mode_b = True
        argv = argv[1:]
    if len(argv) != 1:
        sys.exit(__doc__)
    program = argv[0]
    path = program if os.path.isabs(program) else os.path.join(ROOT, program)
    prog_src = open(path).read()

    harness_path = os.path.join(ROOT, 'src/_cgemit.z')
    open(harness_path, 'w').write(gen_harness(prog_src, mode_b))
    if regen_only:
        print('wrote', harness_path)
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        build(harness_path, os.path.join(tmp, 'cgemit'))
        exe = os.path.join(tmp, 'cgemit.elf')
        os.chmod(exe, 0o755)
        run = subprocess.run([exe], capture_output=True, text=True)
        # app console prints its buffer output on stderr
        lines = [l for l in run.stderr.splitlines() if l.strip()]
        if run.returncode != 0:
            sys.stderr.write(run.stdout + run.stderr)
            sys.exit('harness failed (rc=%d)' % run.returncode)

        # `-o stem` for an executable writes stem+'.elf'; `--obj` writes
        # stem+'.o'.
        stem = os.path.join(tmp, 'prog')
        if mode_b:
            # Plain ELF executable: main.cpp only forces koDriver=true for
            # --obj, and the heap builtins refuse to emit at all in ko mode.
            r = subprocess.run([BIN, '--no-opt', '-o', stem, program],
                               cwd=ROOT, capture_output=True, text=True)
            ref_out = stem + '.elf'
        else:
            r = subprocess.run([BIN, '--obj', '--no-opt', '-o', stem, program],
                               cwd=ROOT, capture_output=True, text=True)
            ref_out = stem + '.o'
        if r.returncode != 0 or any(is_diag(l) for l in (r.stdout + r.stderr).splitlines()):
            sys.stderr.write(r.stdout + r.stderr)
            sys.exit('C++ compile of ' + program + ' failed')
        if mode_b:
            ref_funcs, ref_blob = None, ref_image(stem, True)
        else:
            ref_funcs, ref_blob = objdump_funcs(ref_out), None

        total = ok = 0
        for line in lines:
            m = LINE_RE.match(line)
            if not m:
                print('?? ' + line)
                continue
            name, ln, masktok, _fh, hexs = m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5)
            hb = bytes.fromhex(hexs)
            total += 1
            if len(hb) != ln:
                print('%s: BAD line (len=%d, hex says %d)' % (name, ln, len(hb)))
                continue
            if masktok == '-':
                masks = []
            else:
                masks = [int(x) for x in masktok.split(',')]
            if any(p < 0 or p + 4 > len(hb) for p in masks):
                print('%s: BAD mask %s for len=%d' % (name, masktok, ln))
                continue
            ref = ref_blob if ref_blob is not None else ref_funcs.get(name)
            if ref is None:
                print(name + ': missing from C++ object')
                continue
            if not masks:
                if hb in ref:
                    ok += 1
                    print('%s: OK  len=%d  at 0x%x/0x%x' % (name, ln, ref.index(hb), len(ref)))
                    continue
            else:
                d, nwild = find_masked(hb, ref, masks)
                if d >= 0:
                    ok += 1
                    print('%s: OK  len=%d  at 0x%x/0x%x  reloc-masked %d bytes'
                          % (name, ln, d, len(ref), nwild))
                    continue
            print('%s: MISMATCH len=%d' % (name, ln))
            print('   .z :', hb.hex())
            if ref_blob is None:
                print('   c++:', ref.hex())
            else:
                # ref is the whole executable segment; show the window that
                # matches the most leading non-masked bytes for a diff.
                best, bestd = -1, -1
                wild = set()
                for p in masks:
                    wild.update(range(p, p + 4))
                idx = [i for i in range(len(hb)) if i not in wild]
                if idx:
                    for d in range(0, len(ref) - len(hb) + 1):
                        k = 0
                        while k < len(idx) and ref[d + idx[k]] == hb[idx[k]]:
                            k += 1
                        if k > bestd:
                            bestd, best = k, d
                print('   c++: text=%d best-match at 0x%x (%d/%d bytes)'
                      % (len(ref), best, bestd, len(idx)))
        print('--- %d/%d functions byte-identical' % (ok, total))
        return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
