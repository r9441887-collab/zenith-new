// =====================================================================
// zenith disasm <file> <start> <end> [--att|--no-addr]
//
// Command-line disassembler for already-built Zenith binaries (ELF or PE).
// Uses the SAME embedded freestanding disassembler blob (tools/disasm_blob.cpp
// -> src/disasm_blob.h) that powers the runtime disasm()/disasm_one() builtins,
// so the output matches what disasm() would print inside a running program.
//
// The blob is position-independent freestanding code with its ASCII/data
// globals inside itself. We copy it into an RWX mmap, locate its
// disasm_entry by byte offset, and call it with the SysV ABI:
//     long long entry(op=rdi, dst=rsi, cap=rdx, src=rcx,
//                     srcLen=r8, base=r9, syntax=[rsp+8], flags=[rsp+16])
//   op 1: decode src[0..srcLen) to dst, "0x<base>: mnem ...\0" per line
//         (Intel default; syntax=1 -> AT&T, flags bit0 -> print addr).
//         Returns 0 if it fit, else the required dst capacity.
//   op 2: decode a single instruction at src -> its length.
//
// VA range resolves to file bytes through the binary's PT_LOAD (ELF) or
// section headers (PE): both are read-only; we never map or run the target.
// =====================================================================

#include "main.h"
#include "disasm_blob.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

// ---- LE readers (bounded) ----
uint16_t read16le(const std::vector<uint8_t>& img, uint64_t o) {
    if (o + 2 > img.size()) return 0;
    return (uint16_t)(img[o] | (img[o+1] << 8));
}
uint32_t read32le(const std::vector<uint8_t>& img, uint64_t o) {
    if (o + 4 > img.size()) return 0;
    return (uint32_t)(img[o] | (img[o+1] << 8) | (img[o+2] << 16) | (img[o+3] << 24));
}
uint64_t read64le(const std::vector<uint8_t>& img, uint64_t o) {
    if (o + 8 > img.size()) return 0;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | img[o + (uint64_t)i];
    return v;
}

// ---- minimal ELF64 program-header walk ----
// Returns the file offset for a VA, or (size_t)-1 if it falls in a gap.
// i_va is the VA the binary's code was linked at (LOAD_BASE + section RVA);
// imageBase is where LoadModuleData maps it for execution. Both live in the
// LOAD segment(s). We map VA->file via the PT_LOAD that covers it.
struct ElfSeg { uint64_t vaddr, off, filesz; };
std::vector<ElfSeg> elfLoads(const std::vector<uint8_t>& img) {
    std::vector<ElfSeg> out;
    if (img.size() < 64 || !(img[0] == 0x7F && img[1] == 'E' && img[2] == 'L' && img[3] == 'F'))
        return out;
    uint64_t phoff = read64le(img, 32);
    uint16_t phents = read16le(img, 54);
    uint16_t phnum  = read16le(img, 56);
    for (uint32_t i = 0; i < phnum; i++) {
        uint64_t base = phoff + (uint64_t)i * phents;
        if (base + 56 > img.size()) break;
        uint32_t type = read32le(img, base);
        if (type != 1) continue;                 // PT_LOAD
        ElfSeg s;
        s.off    = read64le(img, base + 8);
        s.vaddr  = read64le(img, base + 16);
        s.filesz = read64le(img, base + 32);
        out.push_back(s);
    }
    return out;
}
size_t elfVaToOff(const std::vector<ElfSeg>& segs, uint64_t va, uint64_t len) {
    for (auto& s : segs)
        if (va >= s.vaddr && len > 0 && va + len <= s.vaddr + s.filesz)
            return (size_t)(s.off + (va - s.vaddr));
    return (size_t)-1;
}

// ---- minimal PE section walk ----
struct PeSec { uint32_t va, vsz, roff, rsz; uint32_t chars; };
bool isPE(const std::vector<uint8_t>& img) {
    if (img.size() < 0x40 || img[0] != 'M' || img[1] != 'Z') return false;
    uint32_t peOff;
    memcpy(&peOff, &img[0x3C], 4);
    return peOff + 24 <= img.size() && img[peOff] == 'P' && img[peOff+1] == 'E';
}
std::vector<PeSec> peSections(const std::vector<uint8_t>& img) {
    std::vector<PeSec> out;
    if (!isPE(img)) return out;
    uint32_t peOff;
    memcpy(&peOff, &img[0x3C], 4);
    uint16_t numSections = read16le(img, peOff + 6);
    uint16_t optSize     = read16le(img, peOff + 20);
    uint32_t secStart    = peOff + 24 + optSize;
    for (uint32_t i = 0; i < numSections; i++) {
        uint32_t s = secStart + i * 40;
        if (s + 40 > img.size()) break;
        PeSec sec;
        sec.vsz    = read32le(img, s + 8);
        sec.va     = read32le(img, s + 12);
        sec.rsz    = read32le(img, s + 16);
        sec.roff   = read32le(img, s + 20);
        sec.chars  = read32le(img, s + 36);
        out.push_back(sec);
    }
    return out;
}
// imageBase lives in the optional header; subtract it to get an RVA, then
// map RVA -> file offset through the section table.
uint64_t peImageBase(const std::vector<uint8_t>& img) {
    uint32_t peOff; memcpy(&peOff, &img[0x3C], 4);
    uint16_t magic = read16le(img, peOff + 24);
    if (magic == 0x20b) return read64le(img, peOff + 24 + 24);   // PE32+
    if (magic == 0x10b) return read32le(img, peOff + 24 + 28);   // PE32
    return 0;
}
size_t peVaToOff(const std::vector<uint8_t>& img, const std::vector<PeSec>& secs,
                 uint64_t base, uint64_t va, uint64_t len) {
    if (va < base) return (size_t)-1;
    uint64_t rva = va - base;
    for (auto& s : secs) {
        if (rva >= s.va && len > 0 && rva + len <= (uint64_t)s.va + s.vsz)
            return (size_t)(s.roff + (rva - s.va));
    }
    return (size_t)-1;
}

// Run the blob in a fresh RWX mapping (blob + one scratch text/output buffer).
// Returns 0 on success, -1 on failure (unmapping before return).
long long runBlob(const std::vector<uint8_t>& text, uint64_t va, uint64_t srcLen,
                  int syntax, int flags, std::string& outText) {
#ifdef __linux__
    // One page-aligned RWX region: [blob ... | out buf ...]. The blob is
    // PIC and self-contained, so any base works.
    size_t blobPage = (kDsBlobSize + 0xFFF) & ~0xFFFu;
    size_t outCap   = srcLen * 64 + 4096;   // ample, plus newline framing
    size_t total    = blobPage + outCap;
    void* map = mmap(nullptr, total, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) return -1;

    memcpy(map, kDsBlob, kDsBlobSize);
    uint8_t* blobBase = (uint8_t*)map;
    uint8_t* outBuf   = blobBase + blobPage;

    // The blob reads stack args [rsp+8]=syntax, [rsp+16]=flags (SysV arg7/8).
    typedef long long (*EntryFn)(long long, uint8_t*, long long,
                                 uint8_t*, long long, long long, long long, long long);
    EntryFn entry = (EntryFn)(blobBase + kDsDisasm_entry);
    long long rc = entry(1, outBuf, (long long)outCap,
                         (uint8_t*)text.data(), (long long)srcLen,
                         (long long)va, syntax, flags);
    if (rc == 0) {
        outText.assign((char*)outBuf);
    }
    munmap(map, total);
    return rc;
#else
    (void)text; (void)va; (void)srcLen; (void)syntax; (void)flags; (void)outText;
    return -1;
#endif
}

void printHelp() {
    std::cout << "Usage: zenith disasm <binary> <startVA> <endVA> [options]\n"
              << "Disassemble a VA range of a built Zenith ELF/PE using the\n"
              << "built-in disassembler blob (same engine as disasm()/disasm_one()).\n"
              << "  <startVA>/<endVA>  hex (0x...) or decimal, inclusive range.\n"
              << "  --att              AT&T syntax (default: Intel).\n"
              << "  --no-addr          omit the '0x<addr>: ' address prefix.\n";
}

}  // namespace

int cmdDisasm(const std::vector<std::string>& args) {
    if (args.size() < 3) { printHelp(); return 1; }

    std::string file = args[0];
    std::string sStart = args[1];
    std::string sEnd   = args[2];
    int syntax = 0, flags = 1;

    for (size_t i = 3; i < args.size(); i++) {
        if (args[i] == "--att")      syntax = 1;
        else if (args[i] == "--no-addr") flags = 0;
        else { std::cerr << "Unknown option: " << args[i] << "\n"; return 1; }
    }

    auto parseVA = [&](const std::string& s) -> uint64_t {
        return (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                   ? strtoull(s.c_str(), nullptr, 16)
                   : strtoull(s.c_str(), nullptr, 10);
    };
    uint64_t start = parseVA(sStart);
    uint64_t end   = parseVA(sEnd);
    if (end <= start) { std::cerr << "Error: endVA must be > startVA\n"; return 1; }
    uint64_t srcLen = end - start;

    std::ifstream f(file, std::ios::binary | std::ios::ate);
    if (!f) { std::cerr << "Error: cannot open '" << file << "'\n"; return 1; }
    std::streamsize sz = f.tellg();
    if (sz <= 0) { std::cerr << "Error: empty file\n"; return 1; }
    std::vector<uint8_t> img((size_t)sz);
    f.seekg(0);
    f.read((char*)img.data(), sz);
    f.close();

    // ---- resolve VA -> file bytes ----
    size_t off;
    uint64_t base = 0;
    if (elfLoads(img).size()) {
        off = elfVaToOff(elfLoads(img), start, srcLen);
        if (off == (size_t)-1) {
            std::cerr << "Error: range 0x" << std::hex << start << "-0x" << end
                      << " falls outside any executable ELF LOAD segment\n" << std::dec;
            return 1;
        }
    } else if (isPE(img)) {
        base = peImageBase(img);
        off  = peVaToOff(img, peSections(img), base, start, srcLen);
        if (off == (size_t)-1) {
            std::cerr << "Error: range 0x" << std::hex << start << "-0x" << end
                      << " falls outside any PE section\n" << std::dec;
            return 1;
        }
    } else {
        std::cerr << "Error: not a Zenith ELF or PE binary\n";
        return 1;
    }
    if (off + srcLen > img.size()) srcLen = img.size() - off;
    if (srcLen == 0) { std::cerr << "Error: empty range\n"; return 1; }

    std::string out;
    long long rc = runBlob(std::vector<uint8_t>(img.begin() + off, img.begin() + off + srcLen),
                           start, srcLen, syntax, flags, out);
    if (rc < 0) { std::cerr << "Error: blob mmap/exec failed\n"; return 1; }
    if (rc > 0) { std::cerr << "Error: output needs " << rc << " bytes (too many instructions)\n"; return 1; }
    fwrite(out.data(), 1, out.size(), stdout);
    if (out.empty() || out.back() != '\n') fputc('\n', stdout);
    return 0;
}