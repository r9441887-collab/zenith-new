#include "codegen.h"
#include "mix.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// ============================================================================
// Kernel-module (.ko) target: 'app console driver' / 'app linux driver'.
//
// The .z program is compiled to regular x86-64 code exactly like the other
// backends (shared emitFunction/emitStmt), but instead of a userspace ELF/PE
// container we hand-assemble a relocatable ELF64 (ET_REL) object with:
//
//   .text              the machine code (init_module/cleanup_module + helpers)
//   .rodata.str1.1     the string pool (same layout as the Linux backend)
//   .modinfo           "license=GPL\0" (modpost refuses to proceed without it)
//   .data              zero-initialized globals (initializers run in the
//                      init_module wrapper via emitGlobalInit)
//   .rela.text         relocations:
//                        R_X86_64_PC32 (-4)  -> call sites / LEA targets
//                        R_X86_64_32S (S+A)  -> mov r64, imm32 string addrs
//   .symtab/.strtab    init_module, cleanup_module, user funcs, undef _printk
//
// A relocatable object alone is not a loadable module: the module loader also
// needs `struct module` (__this_module), the __versions table (CONFIG_MODVERSIONS)
// and the vermagic/build-salt kbuild normally folds in. Those come from the
// kernel's own tooling, which we drive exactly like kbuild does:
//
//   1. scripts/mod/modpost  -> <stem>.mod.c   (__this_module + __versions)
//   2. gcc <stem>.mod.c     -> <stem>.mod.o
//   3. gcc scripts/module-common.c -> .module-common.o  (vermagic/BUILD_SALT)
//   4. ld -r ... -o <final>.ko  <stem>.o <stem>.mod.o .module-common.o
//
// The kernel build tree is located via /lib/modules/$(uname -r)/build. Debian
// splits arch headers out of `linux-headers-<ver>-common`; self-contained trees
// (Ubuntu etc.) keep include/linux next to the generated headers. Both layouts
// are handled by detecting where include/linux lives.
// ============================================================================

namespace {

// ---- ELF64 + tooling constants (freestanding, no external headers) ----
constexpr uint16_t ET_REL    = 1;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint8_t  SHN_UNDEF = 0;
constexpr uint16_t SHN_ABS   = 0xFFF1;

constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB   = 2;
constexpr uint32_t SHT_STRTAB   = 3;
constexpr uint32_t SHT_RELA     = 4;

constexpr uint32_t SHF_WRITE     = 0x1;
constexpr uint32_t SHF_ALLOC     = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;
constexpr uint32_t SHF_MERGE     = 0x10;
constexpr uint32_t SHF_STRINGS   = 0x20;

constexpr uint8_t STB_LOCAL  = 0;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STT_NOTYPE = 0;
constexpr uint8_t STT_OBJECT = 1;
constexpr uint8_t STT_FUNC   = 2;
constexpr uint8_t STT_SECTION= 3;
constexpr uint8_t STT_FILE   = 4;

constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_PLT32 = 4;
constexpr uint32_t R_X86_64_32S  = 11;

struct Kosym {
    uint32_t name;         // byte offset into .strtab
    uint8_t  info;         // (bind<<4)|type
    uint16_t shndx;
    uint64_t value;        // offset within the target section (or 0 for UND)
    uint64_t size;
};

constexpr int SEC_NULL = 0;
constexpr int SEC_TEXT = 1;
constexpr int SEC_RODATA = 2;
constexpr int SEC_MODINFO = 3;
constexpr int SEC_DATA = 4;
constexpr int SEC_SYMTAB = 5;
constexpr int SEC_STRTAB = 6;
constexpr int SEC_SHSTRTAB = 7;
constexpr int SEC_RELA = 8;
constexpr int SEC_COUNT = 9;

// Wraps a path in single quotes so a value with spaces cannot break the shell
// command assembled for modpost/gcc/ld.
inline std::string shq(const std::string& p) {
    std::string o = "'";
    for (char c : p) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    o += '\'';
    return o;
}

bool runScript(const std::string& script, const std::string& what) {
    int rc = std::system(script.c_str());
    if (rc != 0) {
        std::cerr << "Error: kernel-module build step failed (" << what << "), "
                  << "command exited with code " << rc << ".\n";
        return false;
    }
    return true;
}

} // namespace

// ============================================================================
// emitKOEntry: appends the two exported module funcs to .text.
//   init_module    = runs global initializers, calls user main (or the first
//                    function) and returns 0 (success). The kernel invokes it
//                    through an indirect call, so the prologue keeps rsp 16-
//                    aligned for the inner `call` sites (endbr64 for IBT).
//   cleanup_module = calls user cleanup() if present, else is a bare `ret`.
// ============================================================================
void Codegen::emitKOEntry() {
    std::string entry;
    if (funcOffsets.count("main")) entry = "main";
    else for (auto& f : prog.functions) if (!f->isExtern) { entry = f->name; break; }

    // ---- init_module ----
    koInitOffset = code.size();
    emit8(0xF3); emit8(0x0F); emit8(0x1E); emit8(0xFA);  // endbr64   (IBT)
    emit8(0x55);                                         // push rbp
    emit8(0x53);                                         // push rbx
    emit8(0x48); emit8(0x89); emit8(0xE5);               // mov rbp, rsp
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 0x28
    emitGlobalInit();                                    // nested self-contained frame (no-op unless globals need init)
    if (!entry.empty()) {
        emit8(0xE8);
        size_t fp = code.size();
        emit32(0);
        callFixups.push_back({fp, entry});
    }
    emit8(0x31); emit8(0xC0);                            // xor eax, eax  -> 0 (success)
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 0x28
    emit8(0x5B);                                         // pop rbx
    emit8(0x5D);                                         // pop rbp
    emit8(0xC3);                                         // ret
    koInitSize = code.size() - koInitOffset;

    // ---- cleanup_module ----
    koCleanupOffset = code.size();
    emit8(0xF3); emit8(0x0F); emit8(0x1E); emit8(0xFA);  // endbr64
    if (funcOffsets.count("cleanup")) {
        emit8(0x55); emit8(0x53);
        emit8(0x48); emit8(0x89); emit8(0xE5);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        emit8(0xE8);
        size_t fp = code.size();
        emit32(0);
        callFixups.push_back({fp, "cleanup"});
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x5B);
        emit8(0x5D);
        emit8(0xC3);
    } else {
        emit8(0xC3);                                     // ret  (void cleanup)
    }
    koCleanupSize = code.size() - koCleanupOffset;
}

// ============================================================================
// buildKO: assemble the ET_REL .o, then run modpost/gcc/ld to produce the .ko.
// ============================================================================
void Codegen::buildKO(const std::string& path) {
    namespace fs = std::filesystem;

    auto fail = [&](const char* what) {
        std::cerr << "Error: '" << what << "' is not available in driver (kernel-module) mode.\n";
        throw std::runtime_error("feature unavailable in .ko driver");
    };

    // ---- reject userspace-only machinery ----
    if (!heapFixups.empty())                       fail("alloc/free (heap builtins)");
    if (!netFixups.empty() || !sockFixups.empty() || httpGetUsed) fail("network builtins");
    if (!soundFixups.empty() || soundUsed)         fail("sound builtins");
    if (!tlsFixups.empty() || tlsUsed)             fail("tls_* builtins");
    if (!jsFixups.empty() || jsUsed)               fail("js_* builtins");
    if (disasmUsed)                                fail("disasm builtins");
    if (vkUsed || wlUsed)                          fail("vk_*/wl_* builtins");
    if (!importCallFixups.empty() || !elfImportFixups.empty()) fail("extern OS imports");

    // Local (intra-.text) jump fixups are position-independent already; patch
    // them now (they are the ONLY fixup class that can be resolved statically).
    resolveJmpFixups();

    std::vector<uint8_t> rodata;
    stringOffsets.clear();
    // ---- KO OPT: string deduplication ----
    // Identical strings (e.g. the many "%d\n" from print(int)) share a single
    // rodata slot, reducing .ko .rodata size.  Build a map from string content
    // to first-seen offset; duplicates get the same offset.
    std::unordered_map<std::string, uint32_t> rodataDedup;
    for (auto& s : stringPool) {
        auto it = rodataDedup.find(s);
        if (it != rodataDedup.end()) {
            stringOffsets.push_back(it->second);
        } else {
            uint32_t off = (uint32_t)rodata.size();
            for (char c : s) rodata.push_back((uint8_t)c);
            rodata.push_back(0);
            rodataDedup[s] = off;
            stringOffsets.push_back(off);
        }
    }
    while (rodata.size() % 8 != 0) rodata.push_back(0);

    std::vector<uint8_t> modinfo;
    auto mi = [&](const char* s) {
        for (const char* p = s; *p; p++) modinfo.push_back((uint8_t)*p);
        modinfo.push_back(0);
    };
    mi("license=GPL");
    // ---- KO OPT: enhanced .modinfo from program annotations ----
    // If the program has module description/author/version set, emit them
    // as additional modinfo entries so modpost includes them in the .ko.
    if (!prog.moduleDescription.empty()) {
        mi("description=");
        for (char c : prog.moduleDescription) modinfo.push_back((uint8_t)c);
        modinfo.push_back(0);
    }
    if (!prog.moduleAuthor.empty()) {
        mi("author=");
        for (char c : prog.moduleAuthor) modinfo.push_back((uint8_t)c);
        modinfo.push_back(0);
    }
    if (!prog.moduleVersion.empty()) {
        mi("version=");
        for (char c : prog.moduleVersion) modinfo.push_back((uint8_t)c);
        modinfo.push_back(0);
    }

    // ---- .strtab ------------------------------------------------------------------
    std::vector<uint8_t> strtab;
    strtab.push_back(0);  // "" for the null symbol and STT_SECTION symbols
    auto intern = [&](const std::string& s) -> uint32_t {
        uint32_t off = (uint32_t)strtab.size();
        for (char c : s) strtab.push_back((uint8_t)c);
        strtab.push_back(0);
        return off;
    };

    // ---- .shstrtab -----------------------------------------------------------------
    std::vector<uint8_t> shstr;  // indexed like SEC_*: [0] must be the NUL byte
    uint32_t secName[SEC_COUNT] = {0};
    {
        const char* secNames[SEC_COUNT] = {
            "", ".text", ".rodata.str1.1", ".modinfo", ".data",
            ".symtab", ".strtab", ".shstrtab", ".rela.text"
        };
        for (int s = 0; s < SEC_COUNT; s++) {
            uint32_t off = (uint32_t)shstr.size();
            for (const char* p = secNames[s]; *p; p++) shstr.push_back((uint8_t)*p);
            shstr.push_back(0);
            secName[s] = off;
        }
    }

    // ---- symbol table (order matters: locals first, sh_info = first global) --------
    std::vector<Kosym> syms;
    syms.push_back({0, 0, 0, 0, 0});                       // NULL
    syms.push_back({intern("zenith.z"), (STB_LOCAL << 4) | STT_FILE, SHN_ABS, 0, 0});
    syms.push_back({0, (STB_LOCAL << 4) | STT_SECTION, SEC_TEXT, 0, 0});
    syms.push_back({0, (STB_LOCAL << 4) | STT_SECTION, SEC_RODATA, 0, 0});
    syms.push_back({0, (STB_LOCAL << 4) | STT_SECTION, SEC_DATA, 0, 0});
    const int firstGlobal = (int)syms.size();              // sh_info

    // User functions: emitted in declaration order; size = distance to the next.
    std::vector<FunctionDecl*> emitted;
    for (auto& f : prog.functions) if (!f->isExtern) emitted.push_back(f.get());
    for (size_t i = 0; i < emitted.size(); i++) {
        auto it = funcOffsets.find(emitted[i]->name);
        if (it == funcOffsets.end()) continue;
        uint64_t start = it->second;
        uint64_t end = (i + 1 < emitted.size())
            ? funcOffsets[emitted[i + 1]->name]
            : koInitOffset;
        if (end < start) end = koInitOffset;
        syms.push_back({intern(emitted[i]->name), (STB_GLOBAL << 4) | STT_FUNC, SEC_TEXT, start, end - start});
    }

    syms.push_back({intern("init_module"), (STB_GLOBAL << 4) | STT_FUNC, SEC_TEXT, koInitOffset, koInitSize});
    syms.push_back({intern("cleanup_module"), (STB_GLOBAL << 4) | STT_FUNC, SEC_TEXT, koCleanupOffset, koCleanupSize});
    syms.push_back({intern("_printk"), (STB_GLOBAL << 4) | STT_NOTYPE, SHN_UNDEF, 0, 0});
    int symPrintk = (int)syms.size() - 1;

    // ---- map: string sym index / data sym index / fn sym index ----------------------
    // Relocations reference symbols by table index. Function symbols live after
    // the 4 locals; find them by (re)building a small lookup.
    auto fnSymIndex = [&](const std::string& nm) -> int {
        for (size_t i = firstGlobal; i < syms.size(); i++) {
            uint32_t off = syms[i].name;
            const char* base = (const char*)strtab.data();
            const char* sp = base + off;
            size_t n = strtab.size() - off;
            size_t len = strnlen(sp, n);
            if (nm.size() == len && memcmp(sp, nm.c_str(), len) == 0) return (int)i;
        }
        return -1;
    };
    int symText   = 2;
    int symRdata  = 3;
    int symData   = 4;

    // Additional kernel exports imported by drivers (each an SHN_UNDEF entry;
    // resolved by modpost/loader against the running kernel's symbol table).
    // Keep in sync with codegen_builtins_linux.cpp (tryKOCall) and the
    // "don't reject" list in generateWide. Names must exist in
    // /lib/modules/<ver>/build/Module.symvers (this is kernel 6.12 "noprof":
    // allocators are __kmalloc_noprof; smp_processor_id is a header macro and
    // is NOT a symbol).
    // ---- KO OPT: emit only the extern symbols the program actually uses ----
    // The UND entries above are unconditional; they inflate .rela.text with
    // dead relocations even when the driver never calls e.g. __kmalloc_noprof.
    // Build the needed set from the fixup lists and re-emit a slimmer symtab.
    std::unordered_set<std::string> koNeeded;
    for (auto& kf : koExtCallFixups) koNeeded.insert(kf.symbol);
    for (auto& df : koDataFixups)    koNeeded.insert(df.symbol);
    koNeeded.erase("_printk");  // always present below
    bool koJiffiesUsed = koNeeded.count("jiffies") != 0;
    koNeeded.erase("jiffies");
    for (const char* ks : {"__kmalloc_noprof", "kfree", "ktime_get_boot_fast_ns"}) {
        if (!koNeeded.count(ks)) continue;
        koNeeded.erase(ks);
        syms.push_back({intern(ks), (STB_GLOBAL << 4) | STT_NOTYPE, SHN_UNDEF, 0, 0});
    }
    if (koJiffiesUsed)
        syms.push_back({intern("jiffies"), (STB_GLOBAL << 4) | STT_OBJECT, SHN_UNDEF, 0, 0});
    for (auto& unused : koNeeded) {
        std::cerr << "Error: kernel symbol '" << unused
                  << "' is referenced but not in the KO import table.\n";
        throw std::runtime_error("unknown kernel symbol in driver");
    }

    // C/C++ mix: symbols provided by mixed-in C/C++ objects (folded into the
    // final ld -r). Emit as SHN_UNDEF so a z->C call fixup binds to the real
    // definition in the combined object instead of erroring out below.
    if (mixCtx) {
        for (const auto& nm : mixCtx->koProvidedNames) {
            if (fnSymIndex(nm) < 0)
                syms.push_back({intern(nm), (STB_GLOBAL << 4) | STT_FUNC, SHN_UNDEF, 0, 0});
        }
    }

    // ---- relocations (.rela.text) ---------------------------------------------------
    struct Rela { uint64_t r_offset; uint64_t r_info; int64_t r_addend; };
    std::vector<Rela> relas;

    // koStrFixups: mov r64, imm32 — R_X86_64_32S, S = .rodata base + addend.
    for (auto& sf : koStrFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        relas.push_back({sf.codePos,
                         ((uint64_t)symRdata << 32) | R_X86_64_32S,
                         stringOffsets[sf.stringIndex]});
    }

    // strFixups: lea r,[rip+disp32] — R_X86_64_PC32, addend = offset - 4.
    for (auto& sf : strFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        relas.push_back({sf.codePos,
                         ((uint64_t)symRdata << 32) | R_X86_64_PC32,
                         (int64_t)stringOffsets[sf.stringIndex] - 4});
    }

    // callFixups / funcRefFixups to local functions — R_X86_64_PC32, addend -4.
    // KO OPT / BUGFIX: a `call` to a function with no kernel symbol is *never*
    // legal — silently leaving `E8 00 00 00 00` makes init_module call the next
    // instruction and pop the return address off the stack (the drv_imports Oops
    // of 2026-09-13). Fail loudly instead of emitting a mistargeted call.
    auto fcall = [&](size_t pos, const std::string& target) {
        int idx = fnSymIndex(target);
        if (idx < 0) {
            if (koNeeded.count(target)) {          // real kernel symbol, just MISSING from import table
                std::cerr << "Error: kernel symbol '" << target
                          << "' referenced but not in the KO import table.\n";
            } else {
                std::cerr << "Error: call to unknown function '" << target
                          << "' in kernel-module mode.\n";
            }
            throw std::runtime_error("unknown function in driver");
        }
        relas.push_back({pos, ((uint64_t)idx << 32) | R_X86_64_PC32, -4});
    };
    for (auto& cf : callFixups) fcall(cf.codePos, cf.target);
    for (auto& fr : funcRefFixups) fcall(fr.codePos, fr.target);

    // koExtCallFixups: extern kernel symbols — R_X86_64_PC32, addend -4 (UND).
    // koDataFixups:    extern kernel DATA symbols (e.g. jiffies) read via
    //                  `mov rax, [rip+disp32]` — same relocation kind.
    auto undSymIndex = [&](const std::string& name) -> int {
        for (size_t i = 0; i < syms.size(); i++) {
            uint32_t off = syms[i].name;
            const char* sp = (const char*)strtab.data() + off;
            size_t len = strnlen(sp, strtab.size() - off);
            if (syms[i].shndx == SHN_UNDEF && len &&
                memcmp(sp, name.c_str(), name.size()) == 0 && len == name.size())
                return (int)i;
        }
        return -1;
    };
    auto koReloc = [&](const std::string& symbol, size_t codePos, uint32_t type) {
        int idx = undSymIndex(symbol);
        if (idx < 0) {
            std::cerr << "Error: unresolved kernel symbol reference '" << symbol << "'\n";
            throw std::runtime_error("unknown kernel symbol in driver");
        }
        relas.push_back({codePos, ((uint64_t)idx << 32) | type, -4});
    };
    // Calls to external kernel functions must use R_X86_64_PLT32: with
    // CONFIG_X86_KERNEL_IBT the module loader rejects a plain PC32 direct
    // call to an undefined symbol (no ENDBR64 at the target) and instead
    // routes through a PLT stub it synthesizes. Data references stay PC32.
    for (auto& kf : koExtCallFixups) {
        if (kf.symbol == "_printk")
            relas.push_back({kf.codePos, ((uint64_t)symPrintk << 32) | R_X86_64_PLT32, -4});
        else
            koReloc(kf.symbol, kf.codePos, R_X86_64_PLT32);
    }
    for (auto& df : koDataFixups) koReloc(df.symbol, df.codePos, R_X86_64_PC32);

    // globalFixups: globals live in .data; targetRVA = globalsRVA + offset.
    // The .data blob produced by buildLinuxImportData keeps globals at
    // (targetRVA - dataRVA) bytes into the section.
    for (auto& gf : globalFixups) {
        uint64_t off = (uint64_t)gf.targetRVA - dataRVA;
        relas.push_back({gf.codePos,
                         ((uint64_t)symData << 32) | R_X86_64_PC32,
                         (int64_t)off - 4});
    }

    std::sort(relas.begin(), relas.end(),
              [](const Rela& a, const Rela& b) { return a.r_offset < b.r_offset; });

    // ---- assemble the file ----------------------------------------------------------
    auto put16 = [](std::vector<uint8_t>& v, uint64_t x) {
        v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
    };
    auto put32 = [](std::vector<uint8_t>& v, uint64_t x) {
        v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
        v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
    };
    auto put64 = [](std::vector<uint8_t>& v, uint64_t x) {
        for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xFF);
    };

    // Lay out section data and record (offset, size) per section.
    auto alignUp = [](uint64_t v, uint64_t a) { return a ? ((v + a - 1) & ~(a - 1)) : v; };

    uint64_t shOff[SEC_COUNT] = {0};
    uint64_t shSize[SEC_COUNT] = {0};
    uint32_t shAln[SEC_COUNT] = {0};

    uint64_t cursor = 64;  // ELF header
    struct SecDesc { uint32_t type; uint64_t align; std::vector<uint8_t>* data; };
    // .text, .rodata, .modinfo, .data carry file bytes
    shSize[SEC_TEXT] = (uint32_t)code.size();
    shSize[SEC_RODATA] = (uint32_t)rodata.size();
    shSize[SEC_MODINFO] = (uint32_t)modinfo.size();
    shSize[SEC_DATA] = (uint32_t)data.size();
    shAln[SEC_TEXT] = 16; shAln[SEC_RODATA] = 1; shAln[SEC_MODINFO] = 1; shAln[SEC_DATA] = 8;

    cursor = alignUp(cursor, shAln[SEC_TEXT]);
    shOff[SEC_TEXT] = cursor; cursor += shSize[SEC_TEXT];
    cursor = alignUp(cursor, shAln[SEC_RODATA]);
    shOff[SEC_RODATA] = cursor; cursor += shSize[SEC_RODATA];
    cursor = alignUp(cursor, shAln[SEC_MODINFO]);
    shOff[SEC_MODINFO] = cursor; cursor += shSize[SEC_MODINFO];
    cursor = alignUp(cursor, shAln[SEC_DATA]);
    shOff[SEC_DATA] = cursor; cursor += shSize[SEC_DATA];

    shAln[SEC_SYMTAB] = 8;
    cursor = alignUp(cursor, 8);
    shOff[SEC_SYMTAB] = cursor; shSize[SEC_SYMTAB] = (uint64_t)syms.size() * 24; cursor += shSize[SEC_SYMTAB];

    shOff[SEC_STRTAB] = cursor; shSize[SEC_STRTAB] = strtab.size(); cursor += shSize[SEC_STRTAB];
    shOff[SEC_SHSTRTAB] = cursor; shSize[SEC_SHSTRTAB] = shstr.size(); cursor += shSize[SEC_SHSTRTAB];

    shAln[SEC_RELA] = 8;
    cursor = alignUp(cursor, 8);
    shOff[SEC_RELA] = cursor; shSize[SEC_RELA] = (uint64_t)relas.size() * 24; cursor += shSize[SEC_RELA];

    uint64_t shdrOff = cursor;

    std::vector<uint8_t> out;
    out.reserve(cursor + SEC_COUNT * 64);
    out.resize(64);
    // e_ident[0..15]
    static const uint8_t ident[16] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t* h = out.data();
    memcpy(h, ident, 16);
    // Fixed-offset header fields (must land at their ELF offsets, not appended).
    auto wh16 = [&](size_t o, uint64_t x) { h[o] = x & 0xFF; h[o + 1] = (x >> 8) & 0xFF; };
    auto wh32 = [&](size_t o, uint64_t x) { for (int i = 0; i < 4; i++) h[o + i] = (x >> (8 * i)) & 0xFF; };
    auto wh64 = [&](size_t o, uint64_t x) { for (int i = 0; i < 8; i++) h[o + i] = (x >> (8 * i)) & 0xFF; };
    wh16(16, ET_REL);
    wh16(18, EM_X86_64);
    wh32(20, 1);            // e_version
    wh64(24, 0);            // e_entry
    wh64(32, 0);            // e_phoff
    wh64(40, shdrOff);      // e_shoff
    wh32(48, 0);            // e_flags
    wh16(52, 64);           // e_ehsize
    wh16(54, 0);            // e_phentsize
    wh16(56, 0);            // e_phnum
    wh16(58, 64);           // e_shentsize
    wh16(60, SEC_COUNT);    // e_shnum
    wh16(62, SEC_SHSTRTAB); // e_shstrndx

    out.resize(shOff[SEC_TEXT]);
    out.insert(out.end(), code.begin(), code.end());
    out.resize(shOff[SEC_RODATA]);
    out.insert(out.end(), rodata.begin(), rodata.end());
    out.resize(shOff[SEC_MODINFO]);
    out.insert(out.end(), modinfo.begin(), modinfo.end());
    out.resize(shOff[SEC_DATA]);
    out.insert(out.end(), data.begin(), data.end());
    out.resize(shOff[SEC_SYMTAB]);
    for (auto& sy : syms) {
        put32(out, sy.name);
        out.push_back(sy.info);
        out.push_back(0);      // st_other
        put16(out, sy.shndx);
        put64(out, sy.value);
        put64(out, sy.size);
    }
    out.insert(out.end(), strtab.begin(), strtab.end());
    out.insert(out.end(), shstr.begin(), shstr.end());
    out.resize(shOff[SEC_RELA]);
    for (auto& r : relas) {
        put64(out, r.r_offset);
        put64(out, r.r_info);
        put64(out, (uint64_t)r.r_addend);
    }
    out.resize(shdrOff);

    auto putShdr = [&](uint32_t name, uint32_t type, uint64_t flags, uint64_t off,
                       uint64_t size, uint32_t link, uint32_t info, uint64_t align,
                       uint64_t entsize) {
        put32(out, name);
        put32(out, type);
        put64(out, flags);
        put64(out, 0);          // sh_addr
        put64(out, off);
        put64(out, size);
        put32(out, link);
        put32(out, info);
        put64(out, align);
        put64(out, entsize);
    };

    putShdr(0, 0, 0, 0, 0, 0, 0, 0, 0);
    putShdr(secName[SEC_TEXT], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, shOff[SEC_TEXT], shSize[SEC_TEXT], 0, 0, shAln[SEC_TEXT], 0);
    putShdr(secName[SEC_RODATA], SHT_PROGBITS, SHF_ALLOC | SHF_MERGE | SHF_STRINGS, shOff[SEC_RODATA], shSize[SEC_RODATA], 0, 0, shAln[SEC_RODATA], 0);
    putShdr(secName[SEC_MODINFO], SHT_PROGBITS, SHF_ALLOC, shOff[SEC_MODINFO], shSize[SEC_MODINFO], 0, 0, shAln[SEC_MODINFO], 0);
    putShdr(secName[SEC_DATA], SHT_PROGBITS, SHF_WRITE | SHF_ALLOC, shOff[SEC_DATA], shSize[SEC_DATA], 0, 0, shAln[SEC_DATA], 0);
    putShdr(secName[SEC_SYMTAB], SHT_SYMTAB, 0, shOff[SEC_SYMTAB], shSize[SEC_SYMTAB], SEC_STRTAB, firstGlobal, 8, 24);
    putShdr(secName[SEC_STRTAB], SHT_STRTAB, 0, shOff[SEC_STRTAB], shSize[SEC_STRTAB], 0, 0, 1, 0);
    putShdr(secName[SEC_SHSTRTAB], SHT_STRTAB, 0, shOff[SEC_SHSTRTAB], shSize[SEC_SHSTRTAB], 0, 0, 1, 0);
    putShdr(secName[SEC_RELA], SHT_RELA, 0, shOff[SEC_RELA], shSize[SEC_RELA], SEC_SYMTAB, SEC_TEXT, 8, 24);

    // ---- locate the kernel build tree ------------------------------------------------
    auto readCmdOut = [](const char* cmd) -> std::string {
        FILE* p = popen(cmd, "r");
        if (!p) return "";
        char buf[256];
        std::string s;
        while (fgets(buf, sizeof buf, p)) s += buf;
        pclose(p);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    };
    std::string rev = readCmdOut("uname -r");

    fs::path buildPath;
    std::error_code ec;
    if (!rev.empty()) {
        fs::path lp("/lib/modules/" + rev + "/build");
        fs::path c = fs::canonical(lp, ec);
        if (!ec) buildPath = c;
    }
    if (buildPath.empty()) {
        fs::path c = fs::canonical("/lib/modules/current/build", ec);
        if (!ec) buildPath = c;
    }
    if (buildPath.empty() || !fs::exists(buildPath / "scripts/mod/modpost")) {
        std::cerr << "Error: no kernel build tree found via /lib/modules/" << rev
                  << "/build (need linux-headers installed).\n";
        throw std::runtime_error("kernel build tree not found");
    }
    fs::path commonPath = buildPath;
    {
        std::string fn = buildPath.filename().string();
        size_t pos = fn.find_last_of('-');
        if (pos != std::string::npos) {
            fs::path cand = buildPath.parent_path() / (fn.substr(0, pos) + "-common");
            if (fs::exists(cand / "include/linux")) commonPath = cand;
        }
        if (!fs::exists(commonPath / "include/linux")) commonPath = buildPath;
    }

    // ---- temp work directory -----------------------------------------------------------
    fs::path outFile(path);
    std::string stem = outFile.filename().replace_extension("").string();
    if (stem.empty()) stem = "zenith";
    fs::path tmp = fs::temp_directory_path();
    static unsigned long koSeq = 0;
    koSeq++;
    tmp /= "zenith_ko_" + std::to_string(koSeq);
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);

    std::string tq = tmp.string();
    std::string bq = buildPath.string();
    std::string kq = commonPath.string();
    std::string fq = outFile.string();

    // ---- write the ET_REL .o + modpost side files ------------------------------------
    {
        std::ofstream f(tq + "/" + stem + ".o", std::ios::binary);
        if (!f) { std::cerr << "Error: cannot write '" << tq << "/" << stem << ".o'\n"; throw std::runtime_error("cannot write object"); }
        f.write((const char*)out.data(), (std::streamsize)out.size());
    }
    {
        std::ofstream f(tq + "/." + stem + ".o.cmd");
        f << "KBUILD_MODNAME:=\"" << stem << "\" -DKBUILD_MODNAME=\"" << stem << "\"\n";
    }
    {
        std::ofstream f(tq + "/modules.order");
        f << tq << "/" << stem << ".o\n";
    }
    {
        std::ofstream f(tq + "/" + stem + ".mod");
        f << tq << "/" << stem << ".o\n";
    }

    std::string cflags =
        "-std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE "
        "-fno-strict-aliasing -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx "
        "-m64 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 "
        "-mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel "
        "-fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -O2 "
        "-fno-strict-overflow -fno-stack-check -fconserve-stack "
        "-fcf-protection=branch -DMODULE -D__KERNEL__ ";

    std::string incs =
        " -nostdinc"
        " -I" + shq(kq + "/arch/x86/include") +
        " -I" + shq(bq + "/arch/x86/include/generated") +
        " -I" + shq(kq + "/include") +
        " -I" + shq(bq + "/include") +
        " -I" + shq(kq + "/arch/x86/include/uapi") +
        " -I" + shq(bq + "/arch/x86/include/generated/uapi") +
        " -I" + shq(kq + "/include/uapi") +
        " -I" + shq(bq + "/include/generated/uapi");

    std::string pres =
        " -include " + shq(kq + "/include/linux/compiler-version.h") +
        " -include " + shq(kq + "/include/linux/kconfig.h") +
        " -include " + shq(kq + "/include/linux/compiler_types.h");

    // ---- 1. modpost: generate .mod.c -------------------------------------------------
    {
        std::string s = "cd " + shq(tq) + " && " + shq(bq + "/scripts/mod/modpost") +
                        " -M -m -o " + shq(tq + "/Module.symvers") +
                        " -T " + shq(tq + "/modules.order");
        if (fs::exists(buildPath / "Module.symvers"))
            s += " -i " + shq(bq + "/Module.symvers");
        s += " -e " + shq(tq + "/" + stem + ".o");
        if (!runScript(s, "modpost")) throw std::runtime_error("modpost failed");
    }

    // ---- 2. gcc .mod.c ----------------------------------------------------------------
    {
        std::string s = "cd " + shq(tq) + " && gcc " + cflags +
                        " -DKBUILD_BASENAME=\\\"" + stem + "\\\"" +
                        " -DKBUILD_MODNAME=\\\"" + stem + "\\\"" +
                        incs + pres + " -c -o " + shq(tq + "/" + stem + ".mod.o") +
                        " " + shq(tq + "/" + stem + ".mod.c");
        if (!runScript(s, "gcc (.mod.c)")) throw std::runtime_error("gcc .mod.c failed");
    }

    // ---- 3. gcc module-common.c (vermagic / build-salt) --------------------------------
    {
        std::string s = "cd " + shq(tq) + " && gcc " + cflags +
                        incs + pres + " -c -o " + shq(tq + "/.module-common.o") +
                        " " + shq(bq + "/scripts/module-common.c");
        if (!runScript(s, "gcc (module-common.c)")) throw std::runtime_error("gcc module-common failed");
    }

    // ---- 4. ld -r: final .ko ------------------------------------------------------------
    {
        std::string s = "ld -r -m elf_x86_64 -z noexecstack --no-warn-rwx-segments "
                        "--build-id=sha1 -T " + shq(bq + "/arch/x86/module.lds") +
                        " -o " + shq(fq) + " " +
                        shq(tq + "/" + stem + ".o") + " " +
                        shq(tq + "/" + stem + ".mod.o") + " " +
                        shq(tq + "/.module-common.o");
        if (!runScript(s, "ld -r")) throw std::runtime_error("link failed");
    }

    fs::remove_all(tmp, ec);
    std::cout << "Built kernel module: " << fq << std::endl;
}