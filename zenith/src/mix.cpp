#include "mix.h"
#include "codegen.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <set>

namespace mix {

// ============================================================================
// Itanium ABI mangling (subset).
// ============================================================================
static std::string mangleParam(const Type& t) {
    switch (t.kind) {
        case TypeKind::Int:   return "i";
        case TypeKind::Float: return "f";
        case TypeKind::Bool:  return "b";
        case TypeKind::String:return "Pc";
        case TypeKind::Void:  return "v";
        default:              return "";   // structs/vec/etc: unsupported
    }
}

std::string mangleName(const std::string& name) {
    return "_Z" + std::to_string(name.size()) + name;
}

std::string mangleName(const std::string& name, const std::vector<Type>& params) {
    std::string s = "_Z" + std::to_string(name.size()) + name;
    for (auto& p : params) s += mangleParam(p);
    if (params.empty()) s += "v";
    return s;
}

// ============================================================================
// byte helpers
// ============================================================================
static uint64_t rdField(const std::vector<uint8_t>& v, size_t off, int width) {
    uint64_t x = 0;
    for (int i = 0; i < width && off + (size_t)i < v.size(); i++)
        x |= (uint64_t)v[off + i] << (8 * i);
    return x;
}

static void wrField(std::vector<uint8_t>& v, size_t off, int width, uint64_t val) {
    for (int i = 0; i < width && off + (size_t)i < v.size(); i++)
        v[off + i] = (uint8_t)((val >> (8 * i)) & 0xFF);
}

uint32_t MixContext::bucketBase(Codegen& cg, int b) {
    if (b == 0) return cg.textRVA;
    if (b == 1) return cg.rdataRVA;
    return cg.dataRVA;
}

static int bucketAlign(uint64_t addrAlign) {
    if (addrAlign == 0 || addrAlign < 16) return 16;
    if (addrAlign > 64) return 64;
    return (int)addrAlign;
}

static bool isInitArraySection(const mixobj::Section& sec) {
    return sec.name.rfind(".init_array", 0) == 0 ||
           sec.name == ".ctors" || sec.name == ".ctors.$" ||
           sec.name.rfind(".ctors.", 0) == 0;
}

// math-library symbols live in libm.so.6, everything else in libc.so.6.
static const std::set<std::string>& libmSymbols() {
    static std::set<std::string> s = {
        "acos","asin","atan","atan2","cos","sin","tan","cosh","sinh","tanh",
        "exp","log","log10","pow","sqrt","cbrt","ceil","floor","fabs","fmod",
        "ldexp","frexp","modf","hypot","trunc","round","lround","llround",
        "exp2","expm1","log1p","log2","cospi","sinpi","erf","erfc","lgamma","tgamma"
    };
    return s;
}

// ============================================================================
// import classification / naming
// ============================================================================
int MixContext::dynKindFor(const mixobj::Reloc& r) const {
    switch (r.kind) {
        case mixobj::RelKind::PcRel32:   // call-site reloc (PLT32 / REL32)
            return 1;
        case mixobj::RelKind::GotPcRel:  // GOTPCREL to an external: pointer cell
            return 2;
        case mixobj::RelKind::Abs64:     // 8-byte absolute pointer cell
            return 2;
        default:
            return 0;
    }
}

bool MixContext::dynKindRef2(const mixobj::Reloc& r) const {
    return r.kind == mixobj::RelKind::GotPcRel || r.kind == mixobj::RelKind::Abs64;
}

std::string MixContext::dllFor(const std::string& sym) const {
    (void)sym;
    return "msvcrt.dll";
}

std::string MixContext::sonameFor(const std::string& sym) const {
    if (libmSymbols().count(sym)) return "libm.so.6";
    return "libc.so.6";
}

std::string MixContext::cOptFlag() const {
    switch (cOptLevel) {
        case 0: return "-O0";
        case 1: return "-O2";
        case 2: return "-Os";
        case 3: return "-O3";
        default: return "-O2";
    }
}

// ============================================================================
// step 0: compile a C/C++ source with the system compiler, parse the object
// ============================================================================
bool MixContext::addSource(const std::string& path, bool isCpp,
                           const std::vector<std::string>& extraArgs, std::string& err) {
    if (!std::filesystem::exists(path)) {
        err = "source file not found: " + path;
        return false;
    }

    std::string compiler;
    std::vector<std::string> args;
    switch (target) {
        case Target::WindowsPe:
            compiler = isCpp ? "x86_64-w64-mingw32-g++" : "x86_64-w64-mingw32-gcc";
            args = {"-c", "-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-pic",
                    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                    "-ffunction-sections", "-fdata-sections", "-g0"};
            break;
        case Target::Arm64:
            compiler = isCpp ? "clang++" : "clang";
            args = {"--target=aarch64-none-elf", "-c", "-ffreestanding", "-fno-builtin",
                    "-fno-pic", "-fno-pie",
                    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                    "-ffunction-sections", "-fdata-sections", "-mno-implicit-float", "-g0"};
            break;
        case Target::Arm32:
            compiler = isCpp ? "clang++" : "clang";
            args = {"--target=armv7m-none-eabi", "-mcpu=cortex-m3", "-mthumb", "-c",
                    "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-pie",
                    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                    "-ffunction-sections", "-fdata-sections", "-mno-implicit-float", "-g0"};
            break;
        case Target::Wasm:
            compiler = isCpp ? "clang++" : "clang";
            args = {"--target=wasm32", "-c", "-fno-builtin",
                    "-ffunction-sections", "-fdata-sections", "-g0"};
            break;
        default:
            compiler = isCpp ? "g++" : "gcc";
            args = {"-c", "-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-pic",
                    "-mno-red-zone", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                    "-ffunction-sections", "-fdata-sections", "-fcf-protection=none"};
            break;
    }
    // Optimization: forward the z-side intent to the C/C++ compiler. The
    // default -1r (Basic) maps to -O2 so mixing is never silently degraded.
    args.push_back(cOptFlag());
    if (isCpp) {
        args.push_back("-fno-exceptions");
        args.push_back("-fno-rtti");
        args.push_back("-fno-threadsafe-statics");
    }

    auto tmp = std::filesystem::temp_directory_path();
    std::string objPath = (tmp / ("zenith_mix_" + std::to_string(objs.size()) + "_" +
                                  (isCpp ? "cpp" : "c") + ".o")).string();

    std::string cmd = compiler;
    for (auto& a : args) cmd += " " + a;
    for (auto& a : extraArgs) cmd += " " + a;
    cmd += " -o " + objPath + " " + path;
    cmd += " 2>/dev/null";

    int rc = system(cmd.c_str());
    if (rc != 0) {
        err = "C/C++ compile failed (command: " + cmd + ")";
        return false;
    }

    mixobj::Object obj;
    if (!mixobj::readObjectFile(objPath, obj) || !obj.valid) {
        err = obj.error.empty() ? "could not parse compiler output object" : obj.error;
        return false;
    }
    std::error_code ec;
    if (target == Target::KernelModule) {
        // Objects stay around for the external ld -r / modpost toolchain of the
        // kernel build; do not delete the temp .o, but still parse + register
        // the symbols so z->C call routing works in driver mode.
        koObjects.push_back(objPath);
    } else {
        std::filesystem::remove(objPath, ec);
    }

    bool archOk = false;
    if (target == Target::Arm64) archOk = (obj.arch == mixobj::Arch::ARM64);
    else if (target == Target::Arm32) archOk = (obj.arch == mixobj::Arch::ARM32);
    else if (target == Target::Wasm)  archOk = (obj.arch == mixobj::Arch::Wasm);
    else archOk = (obj.arch == mixobj::Arch::X86_64);
    if (!archOk) {
        err = "C/C++ object architecture does not match the target backend";
        return false;
    }

// Record undefined function symbols (PE target uses these to inject IAT
    // entries before buildImportData runs). clang marks undefined references
    // to functions as NOTYPE on ELF (aarch64) and FUNC on PE, so accept both
    // except on PE where NOTYPE is ambiguous (data refs).
    for (auto& sym : obj.symbols) {
        if (sym.section == -2 && !sym.name.empty()) {
            if (sym.type == 2 || (sym.type == 0 && target != Target::WindowsPe))
                undefFuncs.push_back(sym.name);
        }
    }
    // Register defined symbols early (providesLocal/localSymbol are consulted
    // during function codegen, i.e. BEFORE layout()). placeObject() fills in
    // the real offsets later.
    for (auto& sym : obj.symbols) {
        if (sym.section >= 0 && !sym.name.empty() && sym.bind != 0 &&
            !sym.isSectionSym && !defs.count(sym.name)) {
            defs[sym.name] = 0;
            defBucket[sym.name] = -1;
        }
    }
    ObjState st;
    st.obj = std::move(obj);
    st.path = path;
    st.isCpp = isCpp;
    st.bucket.assign(st.obj.sections.size(), -1);
    st.off.assign(st.obj.sections.size(), 0);
    objs.push_back(std::move(st));
    hasAny = true;
    hasCpp = hasCpp || isCpp;
    return true;
}

// ============================================================================
// provided/local symbol queries (used by codegen.cpp call-site routing)
// ============================================================================
bool MixContext::providesLocal(const std::string& name) const {
    if (defs.count(name)) return true;
    return false;
}

bool MixContext::providesLocal(const std::string& name, const std::vector<Type>& params) const {
    if (defs.count(name) || defs.count(mangleName(name, params))) return true;
    return false;
}

std::string MixContext::localSymbol(const std::string& name, const std::vector<Type>& params) const {
    if (defs.count(name)) return name;
    return mangleName(name, params);
}

// Layout (step 1): bucket the C sections into code/rdata/data, register defs.
// KernelModule never merges bytes (ld -r does); it only registers symbols.
void MixContext::placeObject(Codegen& cg, size_t oi) {
    bool registerOnly = (target == Target::KernelModule);
    ObjState& O = objs[oi];
    auto& obj = O.obj;

    for (size_t s = 0; s < obj.sections.size(); s++) {
        auto& sec = obj.sections[s];
        if (sec.name.size() >= 4 && sec.name.rfind(".ARM.", 0) == 0) continue;
        if (sec.name.rfind(".debug", 0) == 0) continue;
        if (sec.name == ".comment" || sec.name == ".eh_frame") continue;
        int b = -1;
        bool ctorSec = false;

        if (!obj.isCoff) {
            uint32_t shf = (uint32_t)sec.flags;
            if (!(shf & 0x2)) continue;                 // !SHF_ALLOC -> drop
            if (isInitArraySection(sec)) { b = 1; ctorSec = true; }
            else if (shf & 0x4) b = 0;                  // SHF_EXECINSTR
            else if (shf & 0x1) b = 2;                  // SHF_WRITE
            else b = 1;
        } else {
            uint32_t ch = (uint32_t)sec.flags;
            if (ch & 0x20000000) b = 0;                 // IMAGE_SCN_MEM_EXECUTE
            else if (ch & 0x80) b = 2;                  // IMAGE_SCN_CNT_UNINITIALIZED_DATA
            else if (ch & 0x80000000) b = 2;            // IMAGE_SCN_MEM_WRITE
            else if (ch & 0x40000000) b = 1;            // IMAGE_SCN_MEM_READ
            else continue;
            if (isInitArraySection(sec)) ctorSec = true;
        }
        if (sec.bytes.empty() && !sec.noBits) continue;

        // COMDAT-dedupe: if this section defines a global symbol that was already
        // PLACED by an earlier object, drop the whole section (and its relocs).
        // (defs is pre-populated in addSource; only bucket!=-1 counts as placed.)
        bool dup = false;
        for (auto& sym : obj.symbols) {
            if (sym.section < 0 || sym.section != (int)s) continue;
            if (sym.bind == 0 || sym.isSectionSym) continue;
            if (sym.value >= sec.bytes.size()) continue;
            auto dbb = defBucket.find(sym.name);
            if (dbb != defBucket.end() && dbb->second != -1) { dup = true; break; }
        }
        if (dup) continue;
        O.bucket[s] = b;

        if (!registerOnly) {
            auto& vec = (b == 0) ? cg.code : ((b == 1) ? cg.rdata : cg.data);
            int al = bucketAlign(sec.addrAlign);
            size_t start = vec.size();
            while (start % (size_t)al != 0) start++;
            O.off[s] = start;
            if (start > vec.size()) vec.insert(vec.end(), start - vec.size(), 0);
            vec.insert(vec.end(), sec.bytes.begin(), sec.bytes.end());
            if (sec.noBits) {
                size_t need = sec.bytes.size();
                for (size_t i = 0; i < need; i++) vec.push_back(0);
            }

            // ctor table bookkeeping
            if (ctorSec) {
                CtorSection cs;
                cs.bucket = b;
                cs.off = O.off[s];
                cs.count = (int64_t)(sec.bytes.size() / 8);
                ctorSections.push_back(cs);
            }
        }

        // register defined symbols
        for (auto& sym : obj.symbols) {
            if (sym.section < 0 || sym.section != (int)s) continue;
            if (sym.bind == 0 || sym.isSectionSym) continue;
            if (sym.name.empty() || sym.value >= sec.bytes.size()) continue;
            if (defBucket.count(sym.name) && defBucket[sym.name] != -1) continue;
            uint64_t base = registerOnly ? 0 : O.off[s];
            defs[sym.name] = base + sym.value;
            defBucket[sym.name] = b;
            if (b == 0) {
                if (cg.funcOffsets.count(sym.name)) {
                    errors.push_back("duplicate function '" + sym.name + "' between z and C/C++ code");
                    continue;
                }
                cg.funcOffsets[sym.name] = base + sym.value;
            }
            if (target == Target::KernelModule) koProvidedNames.insert(sym.name);
        }
    }
}

void MixContext::layout(Codegen& cg) {
    if (laidOut) return;
    if (!hasAny) return;

    // align code/rdata/data (skip the z-side leading padding; sections align themselves)
    // append per-object content
    for (size_t oi = 0; oi < objs.size(); oi++) {
        if (objs[oi].bucket.empty()) {
            objs[oi].bucket.assign(objs[oi].obj.sections.size(), -1);
            objs[oi].off.assign(objs[oi].obj.sections.size(), 0);
        }
        placeObject(cg, oi);
    }

    laidOut = true;
}

bool MixContext::flatMergeImage(uint64_t imageBase, size_t imageEnd,
                                std::vector<uint8_t>& out,
                                std::unordered_map<std::string, uint64_t>& funcs,
                                std::string& err) {
    // The scratch Codegen only ever reads prog.arch (via its ctor); the merge
    // itself never touches the Program. A shared instance is safe here.
    static Program dummy;
    Codegen scratch(dummy);
    scratch.mixCtx = this;
    return flatMerge(scratch, imageBase, imageEnd, out, funcs, err);
}

bool MixContext::hasCFunction(const std::string& name) const {
    return defs.count(name) != 0;
}

int64_t MixContext::ctorCountEstimate() const {
    int64_t n = 0;
    for (auto& cs : ctorSections) n += cs.count;
    return n;
}

size_t MixContext::mixcrt0Size(bool haveCtor) const {
    switch (target) {
        case Target::Arm64:
            if (!haveCtor) return 4;                 // ret
            return (uint64_t)ctorCountEstimate() > 0xFFFF ? 48u : 44u;
        case Target::Arm32:
            if (!haveCtor) return 2;                 // bx lr
            return 26u;
        default:
            if (!haveCtor) return 15u;               // 4 pushes + 8 lea + 4 = pad to 16
            return 44u;
    }
}

bool MixContext::flatMerge(Codegen& scratch, uint64_t imageBase, size_t imageEnd,
                           std::vector<uint8_t>& out,
                           std::unordered_map<std::string, uint64_t>& funcs,
                           std::string& err) {
    if (!laidOut) layout(scratch);
    size_t cCode  = scratch.code.size();
    size_t cRdata = scratch.rdata.size();
    size_t cData  = scratch.data.size();

    bool haveCtor = ctorCountEstimate() > 0;
    size_t crt0Bytes = mixcrt0Size(haveCtor);
    // resolve() step-2 appends one contiguous ctor table to .rdata; reserve
    // for it so the following placement decisions stay valid.
    int64_t ctorEntries = ctorCountEstimate();
    size_t ctorTableBytes = (size_t)ctorEntries * 8;
    ctorTableBytes = (ctorTableBytes + 7u) & ~7u;

    size_t textPlace  = (imageEnd + 7u) & ~7u;
    size_t crt0Pad    = (4 - (cCode & 3)) & 3;
    size_t rdataPlace = (textPlace + cCode + crt0Pad + crt0Bytes + 7u) & ~7u;
    size_t dataPlace  = (rdataPlace + cRdata + ctorTableBytes + 7u) & ~7u;

    if (target == Target::Arm64 || target == Target::Wasm) {
        if (rdataPlace > 0xFFFFFFFFull || dataPlace > 0xFFFFFFFFull || crt0Pad > 0) {
            err = "flat image too large";
            return false;
        }
    }
    scratch.textRVA  = (uint32_t)textPlace;
    scratch.rdataRVA = (uint32_t)rdataPlace;
    scratch.dataRVA  = (uint32_t)dataPlace;

    try {
        resolve(scratch);
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    scratch.applyMixAbsPatches(imageBase);

    if (getenv("ZT_MIX_DEBUG"))
        fprintf(stderr, "mix flat: imageEnd=%zu textPlace=%zx crt0Pad=%zu crt0=%zu "
                        "cCode=%zu cRdata=%zu ctorTbl=%zu rdataPlace=%zx cData=%zu "
                        "dataPlace=%zx imageBase=%llx ctorRVA=%llx\n",
                imageEnd, textPlace, crt0Pad, crt0Bytes, cCode, cRdata, ctorTableBytes,
                rdataPlace, cData, dataPlace, (unsigned long long)imageBase,
                (unsigned long long)ctorTableRVA);

    size_t mixTotal = dataPlace + cData;
    if (rdataPlace + scratch.rdata.size() > mixTotal)
        mixTotal = rdataPlace + scratch.rdata.size();
    if (out.size() < mixTotal) out.resize((mixTotal + 15u) & ~15u, 0);
    for (size_t i = 0; i < scratch.code.size(); i++)  out[textPlace + i] = scratch.code[i];
    for (size_t i = 0; i < scratch.rdata.size(); i++) out[rdataPlace + i] = scratch.rdata[i];
    for (size_t i = 0; i < scratch.data.size(); i++)  out[dataPlace + i] = scratch.data[i];
    for (auto& fo : scratch.funcOffsets)
        funcs[fo.first] = (uint64_t)scratch.textRVA + fo.second;
    return true;
}

void MixContext::fail(const std::string& msg, const std::string& what) {
    throw std::runtime_error(msg + ": " + what);
}

// ============================================================================
// symbol lookup
// ============================================================================
uint64_t MixContext::symRVA(Codegen& cg, const std::string& name, bool& found) const {
    auto it = defs.find(name);
    if (it != defs.end()) {
        found = true;
        auto bit = defBucket.find(name);
        return (uint64_t)bucketBase(cg, bit != defBucket.end() ? bit->second : 2) + it->second;
    }
    auto fit = cg.funcOffsets.find(name);
    if (fit != cg.funcOffsets.end()) {
        found = true;
        return (uint64_t)cg.textRVA + fit->second;
    }
    // Flat-image targets: z functions live outside the scratch codegen; the
    // backend records their base-less image offsets before layout().
    auto zit = zFuncRVAs.find(name);
    if (zit != zFuncRVAs.end()) {
        found = true;
        return zit->second;
    }
    found = false;
    return 0;
}

// ============================================================================
// resolve (step 2): patch relocations
// ============================================================================
#define MIX_ERR(msg) do { err = (msg); return false; } while (0)

// ============================================================================
// AArch64 relocation field encoders (little-endian 32-bit instructions).
// ============================================================================
static uint32_t a64Word(const std::vector<uint8_t>& v, size_t off) {
    return (uint32_t)rdField(v, off, 4);
}
static void a64Write(std::vector<uint8_t>& v, size_t off, uint32_t w) {
    wrField(v, off, 4, w);
}
// BL: imm26 = (S + A - P) / 4, bits [25:0].
static uint32_t a64PatchCall(uint32_t word, int64_t delta, bool& ok) {
    ok = (delta & 3) == 0;
    if (ok) {
        int64_t imm26 = delta / 4;
        ok = imm26 >= -(1ll << 25) && imm26 < (1ll << 25);
        if (ok) return (word & 0xFC000000u) | ((uint32_t)(imm26 & 0x3FFFFFFu));
    }
    return word;
}
// ADRP: immlo[30:29] + immhi[23:5] = ((S + A) >> 12) - (P >> 12), 21-bit.
static uint32_t a64PatchAdrp(uint32_t word, int64_t pageDelta, bool& ok) {
    ok = pageDelta >= -(1ll << 20) && pageDelta < (1ll << 20);
    if (!ok) return word;
    uint32_t imm21 = (uint32_t)(pageDelta & 0x1FFFFF);
    uint32_t immlo = imm21 & 0x3;
    uint32_t immhi = (imm21 >> 2) & 0x7FFFF;
    return (word & 0x9F00001Fu) | (immlo << 29) | (immhi << 5);
}
// ADR: 21-bit PC-relative.
static uint32_t a64PatchAdr(uint32_t word, int64_t pcRel, bool& ok) {
    ok = pcRel >= -(1ll << 20) && pcRel < (1ll << 20);
    if (!ok) return word;
    uint32_t imm21 = (uint32_t)(pcRel & 0x1FFFFF);
    uint32_t immlo = imm21 & 0x3;
    uint32_t immhi = (imm21 >> 2) & 0x7FFFF;
    return (word & 0x9F00001Fu) | (immlo << 29) | (immhi << 5);
}
// ADD/LDR/STR imm12: bits [21:10].
static uint32_t a64PatchLo12(uint32_t word, uint64_t val) {
    return (word & 0xFFC003FFu) | (((uint32_t)(val & 0xFFF)) << 10);
}

// ============================================================================
// ARM32 (ARM-state and Thumb) relocation field encoders.
// ============================================================================
static uint16_t armThumbHalf(const std::vector<uint8_t>& v, size_t off) {
    return (uint16_t)rdField(v, off, 2);
}
static void armThumbHalfWrite(std::vector<uint8_t>& v, size_t off, uint16_t h) {
    wrField(v, off, 2, h);
}
static uint32_t armThumbWord(const std::vector<uint8_t>& v, size_t off) {
    return (uint32_t)armThumbHalf(v, off) | ((uint32_t)armThumbHalf(v, off + 2) << 16);
}
static void armThumbWrite(std::vector<uint8_t>& v, size_t off, uint32_t w) {
    armThumbHalfWrite(v, off, (uint16_t)w);
    armThumbHalfWrite(v, off + 2, (uint16_t)(w >> 16));
}
// Thumb BL (R_ARM_THM_CALL): 25-bit immediate, J1/J2 inverted.
static uint32_t armThumbPatchBl(uint32_t first, uint32_t second, int64_t rel, bool& ok) {
    ok = (rel & 1) == 0;
    if (!ok) return 0;
    int64_t imm = rel / 2;
    if (imm < -(1ll << 24) || imm >= (1ll << 24)) { ok = false; return 0; }
    uint32_t S   = ((uint32_t)imm >> 24) & 1;
    uint32_t i1  = (((uint32_t)imm >> 23) ^ S) ? 0u : 1u;
    uint32_t i2  = (((uint32_t)imm >> 22) ^ S) ? 0u : 1u;
    uint32_t imm10 = ((uint32_t)imm >> 12) & 0x3FF;
    uint32_t imm11 = (uint32_t)imm & 0x7FF;
    first  = (first & 0xF800u) | (S << 10) | imm10;
    second = (second & 0xD000u) | (i1 << 13) | (i2 << 11) | imm11;
    return (first << 16) | second;
}
// Thumb B.W (R_ARM_THM_JUMP24): 24-bit immediate, J1/J2 not inverted.
static uint32_t armThumbPatchBw(uint32_t first, uint32_t second, int64_t rel, bool& ok) {
    ok = (rel & 1) == 0;
    if (!ok) return 0;
    int64_t imm = rel / 2;
    if (imm < -(1ll << 23) || imm >= (1ll << 23)) { ok = false; return 0; }
    uint32_t S   = ((uint32_t)imm >> 23) & 1;
    uint32_t j1  = ((uint32_t)imm >> 22) & 1;
    uint32_t j2  = ((uint32_t)imm >> 21) & 1;
    uint32_t imm10 = ((uint32_t)imm >> 11) & 0x3FF;
    uint32_t imm11 = (uint32_t)imm & 0x7FF;
    first  = (first & 0xF800u) | (S << 10) | imm10;
    second = (second & 0xD000u) | (j1 << 13) | (j2 << 11) | imm11;
    return (first << 16) | second;
}
// Decode the distance currently stored in a Thumb BL (signed 25-bit << 1).
static int64_t armThumbBlAddend(uint32_t first, uint32_t second) {
    uint32_t S = (first >> 10) & 1;
    uint32_t j1 = (second >> 13) & 1;
    uint32_t j2 = (second >> 11) & 1;
    uint32_t i1 = (j1 ^ S) ? 0u : 1u;
    uint32_t i2 = (j2 ^ S) ? 0u : 1u;
    int64_t imm = ((int64_t)S << 24) | ((int64_t)i1 << 23) | ((int64_t)i2 << 22) |
                  ((uint32_t)(first & 0x3FF) << 12) | ((uint32_t)(second & 0x7FF) << 1);
    if (imm & (1ll << 25)) imm |= ~((1ll << 26) - 1);
    return imm;
}
// Thumb MOVW/MOVT pair: first half = 11110 i 100100/101100 imm4, second = 0 imm3 Rd imm8.
static uint32_t armThumbPatchMov(uint32_t word, uint64_t val, bool isMovt, bool& done) {
    uint16_t imm16 = (uint16_t)(isMovt ? (val >> 16) : val);
    uint8_t imm4 = (uint16_t)((imm16 >> 12) & 0xF);
    uint8_t i    = (uint16_t)((imm16 >> 11) & 1);
    uint8_t imm3 = (uint16_t)((imm16 >> 8) & 0x7);
    uint8_t imm8 = (uint16_t)(imm16 & 0xFF);
    uint16_t first = (uint16_t)((isMovt ? 0xF2C0 : 0xF240) | ((uint16_t)i << 10) | imm4);
    uint16_t second = (uint16_t)(((uint16_t)word & 0x0F00u) | ((uint16_t)imm3 << 12) | imm8);
    done = true;
    return ((uint32_t)first << 16) | second;
}
static int64_t armThumbMovAddend(const std::vector<uint8_t>& v, size_t off, bool isMovt) {
    uint32_t w = armThumbWord(v, off);
    uint16_t first = (uint16_t)w, second = (uint16_t)(w >> 16);
    uint16_t imm4 = first & 0xF;
    uint16_t i = (first >> 10) & 1;
    uint16_t imm3 = (second >> 12) & 0x7;
    uint16_t imm8 = second & 0xFF;
    uint16_t imm16 = (uint16_t)((imm4 << 12) | (i << 11) | (imm3 << 8) | imm8);
    return isMovt ? ((int64_t)imm16 << 16) : imm16;
}
// ARM-state BL (R_ARM_CALL/JUMP24): imm24 = (S + A - P) / 4.
static uint32_t armPatchCall(uint32_t word, int64_t delta, bool& ok) {
    ok = (delta & 3) == 0;
    if (!ok) return word;
    int64_t imm24 = delta / 4;
    ok = imm24 >= -(1ll << 23) && imm24 < (1ll << 23);
    if (ok) return (word & 0xFF000000u) | ((uint32_t)(imm24 & 0xFFFFFFu));
    return word;
}
// ARM-state MOVW/MOVT: imm4[19:16] + imm12[11:0].
static uint32_t armPatchMov(uint32_t word, uint64_t val, bool isMovt) {
    uint16_t imm16 = (uint16_t)(isMovt ? (val >> 16) : val);
    return (word & 0xFFF0F000u) | ((uint32_t)((imm16 >> 12) & 0xF) << 16) | (uint32_t)(imm16 & 0xFFF);
}
static int64_t armMovAddend(uint32_t w, bool isMovt) {
    uint16_t imm16 = (uint16_t)(((w >> 16) & 0xF) << 12 | (w & 0xFFF));
    return isMovt ? ((int64_t)imm16 << 16) : imm16;
}

bool MixContext::resolveReloc(Codegen& cg, size_t oi, const mixobj::Reloc& r, std::string& err) {
    ObjState& O = objs[oi];
    auto& obj = O.obj;
    if (r.section < 0 || r.section >= (int)O.bucket.size()) return true;
    int secIdx = r.section;
    int b = O.bucket[secIdx];
    if (b < 0) return true;   // section dropped (non-alloc / COMDAT dup)
    // Relocs without any target (metadata/junk like .ARM.exidx tables) are inert.
    if (r.targetName.empty() && r.targetSection < 0) return true;
    auto& vec = (b == 0) ? cg.code : ((b == 1) ? cg.rdata : cg.data);

    mixobj::RelKind kind = r.kind;
    if (kind == mixobj::RelKind::None) return true;

    // --- addend ---
    int64_t A = 0;
    int fwidth = (kind == mixobj::RelKind::Abs64) ? 8 : 4;
    auto& secBytes = obj.sections[(size_t)secIdx].bytes;
    if (r.explicitAddend) A = (int64_t)r.addend;
    else {
        // REL objects carry the addend inside the instruction. Decode it from
        // the encoded immediate for the ARM/Thumb kinds instead of reading a
        // raw little-endian field.
        switch (kind) {
            case mixobj::RelKind::ArmThmCall:
                A = armThumbBlAddend((uint32_t)armThumbHalf(secBytes, r.offset),
                                     (uint32_t)armThumbHalf(secBytes, r.offset + 2));
                break;
            case mixobj::RelKind::ArmThmMovwAbs:
                A = armThumbMovAddend(secBytes, r.offset, r.rawType == 48);
                break;
            case mixobj::RelKind::ArmMovwAbs:
                A = armMovAddend((uint32_t)rdField(secBytes, r.offset, 4), r.rawType == 44);
                break;
            case mixobj::RelKind::ArmCall:
                A = (((int64_t)(uint32_t)rdField(secBytes, r.offset, 4) << 8) >> 8) << 2;
                break;
            default:
                A = (int64_t)rdField(secBytes, r.offset, fwidth);
                break;
        }
    }
    // COFF REL32: displacement is relative to the byte AFTER the instruction.
    if (obj.isCoff && (r.rawType == 4 || r.rawType == 0x14)) A -= 4;

    bool isAbs = (kind == mixobj::RelKind::Abs64 || kind == mixobj::RelKind::Abs32);

    uint64_t S = 0;
    bool defined = false;
    bool isSectionRef = r.targetName.empty() && r.targetSection >= 0;

    size_t byteOff = O.off[(size_t)secIdx] + r.offset;

    if (isSectionRef) {
        int tb = r.targetSection;
        if (tb >= (int)O.bucket.size() || O.bucket[tb] < 0) MIX_ERR("relocation references a non-placed section");
        S = (uint64_t)bucketBase(cg, O.bucket[tb]) + O.off[tb];
        defined = true;
    } else {
        std::string sym = r.targetName;
        bool found = false;
        defined = (symRVA(cg, sym, found), found);
        if (defined) S = symRVA(cg, sym, found);
        else {
            int dynKind = dynKindFor(r);
            if (target == Target::LinuxElf && dynKind == 1) {
                uint64_t stub = 0;
                if (stubOffsets.count(sym)) stub = stubOffsets[sym];
                else {
                    stub = cg.code.size();
                    cg.code.push_back(0xFF); cg.code.push_back(0x25);
                    cg.elfImportFixups.push_back({cg.code.size(), sym, sonameFor(sym)});
                    cg.code.push_back(0); cg.code.push_back(0);
                    cg.code.push_back(0); cg.code.push_back(0);
                    stubOffsets[sym] = stub;
                }
                S = (uint64_t)cg.textRVA + stub;
                defined = true;
            } else if (target == Target::WindowsPe && dynKind == 1) {
                uint64_t stub = 0;
                if (stubOffsets.count(sym)) stub = stubOffsets[sym];
                else {
                    stub = cg.code.size();
                    cg.code.push_back(0xFF); cg.code.push_back(0x25);
                    cg.importCallFixups.push_back({cg.code.size(), sym, dllFor(sym)});
                    cg.code.push_back(0); cg.code.push_back(0);
                    cg.code.push_back(0); cg.code.push_back(0);
                    stubOffsets[sym] = stub;
                }
                S = (uint64_t)cg.textRVA + stub;
                defined = true;
            } else if (target == Target::LinuxElf && dynKindRef2(r)) {
                uint32_t cellOff = (uint32_t)cg.data.size();
                cg.data.push_back(0); cg.data.push_back(0); cg.data.push_back(0); cg.data.push_back(0);
                cg.data.push_back(0); cg.data.push_back(0); cg.data.push_back(0); cg.data.push_back(0);
                cg.mixDynCells.push_back({cg.dataRVA + cellOff, sym});
                S = (uint64_t)cg.dataRVA + cellOff;
                defined = true;
            } else {
                std::string why = "undefined symbol '" + sym + "' referenced from C/C++ code";
                if (target == Target::LinuxElf || target == Target::WindowsPe)
                    why += " (only direct calls of undefined functions are supported in C/C++ mix; data/pointer references to OS symbols must be wrapped in a small C function)";
                else
                    why += " (dynamic imports are not supported on this target)";
                MIX_ERR(why);
            }
        }
    }

    uint64_t P = (uint64_t)bucketBase(cg, b) + byteOff;

    switch (kind) {
        case mixobj::RelKind::Abs16: {
            int64_t v = (int64_t)S + A;
            wrField(vec, byteOff, 2, (uint64_t)v);
            absPatches.push_back({b, (uint64_t)byteOff, (uint64_t)v, 2});
            return true;
        }
        case mixobj::RelKind::Abs32:
        case mixobj::RelKind::Abs64: {
            int64_t v = (int64_t)S + A;
            wrField(vec, byteOff, fwidth, (uint64_t)v);
            absPatches.push_back({b, (uint64_t)byteOff, (uint64_t)v, (uint8_t)fwidth});
            return true;
        }
        case mixobj::RelKind::PcRel32:
        case mixobj::RelKind::GotPcRel: {
            int64_t v = (int64_t)S - (int64_t)P + A;
            wrField(vec, byteOff, 4, (uint64_t)v);
            return true;
        }
        case mixobj::RelKind::PcRel64: {
            int64_t v = (int64_t)S - (int64_t)P + A;
            wrField(vec, byteOff, 8, (uint64_t)v);
            return true;
        }
        case mixobj::RelKind::Arm64Call26: {
            int64_t v = (int64_t)S - (int64_t)P + A;
            bool ok = false;
            uint32_t w = a64PatchCall(a64Word(vec, byteOff), v, ok);
            if (!ok) MIX_ERR("AArch64 call out of range or misaligned");
            a64Write(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::Arm64AdrpPg: {
            int64_t d = (((int64_t)S + A) >> 12) - ((int64_t)P >> 12);
            bool ok = false;
            uint32_t w = a64PatchAdrp(a64Word(vec, byteOff), d, ok);
            if (!ok) MIX_ERR("AArch64 ADRP out of range");
            a64Write(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::Arm64AdrLo: {
            int64_t v = (int64_t)S + A - (int64_t)P;
            bool ok = false;
            uint32_t w = a64PatchAdr(a64Word(vec, byteOff), v, ok);
            if (!ok) MIX_ERR("AArch64 ADR out of range");
            a64Write(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::Arm64AddLo12:
        case mixobj::RelKind::Arm64LdStLo12: {
            a64Write(vec, byteOff, a64PatchLo12(a64Word(vec, byteOff), S + A));
            return true;
        }
        case mixobj::RelKind::ArmCall: {
            int64_t v = (int64_t)S + A - (int64_t)P;
            bool ok = false;
            uint32_t w = armPatchCall(a64Word(vec, byteOff), v, ok);
            if (!ok) MIX_ERR("ARM call out of range or misaligned");
            a64Write(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::ArmMovwAbs: {
            bool isMovt = (r.rawType == 44);
            a64Write(vec, byteOff, armPatchMov(a64Word(vec, byteOff), S + A, isMovt));
            return true;
        }
        case mixobj::RelKind::ArmThmCall: {
            int64_t v = (int64_t)S + A - (int64_t)P;
            uint32_t first = armThumbHalf(vec, byteOff);
            uint32_t second = armThumbHalf(vec, byteOff + 2);
            bool ok = false;
            uint32_t w = armThumbPatchBl(first, second, v, ok);
            if (!ok) MIX_ERR("Thumb BL out of range or misaligned");
            armThumbWrite(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::ArmThmMovwAbs: {
            bool isMovt = (r.rawType == 48);
            bool done = false;
            uint32_t w = armThumbPatchMov(armThumbWord(vec, byteOff), S + A, isMovt, done);
            armThumbWrite(vec, byteOff, w);
            return true;
        }
        case mixobj::RelKind::ArmPcRel31: {
            int64_t v = (int64_t)S + A - (int64_t)P;
            uint32_t w = (a64Word(vec, byteOff) & 0x80000000u) | ((uint32_t)v & 0x7FFFFFFFu);
            a64Write(vec, byteOff, w);
            return true;
        }
        default:
            return true;
    }
}

void MixContext::resolve(Codegen& cg) {
    if (!laidOut || !hasAny) return;
    if (target == Target::KernelModule) return;   // objects folded by ld -r instead

    // 1. resolve every relocation
    for (size_t oi = 0; oi < objs.size(); oi++) {
        for (auto& r : objs[oi].obj.relocs) {
            std::string err;
            if (!resolveReloc(cg, oi, r, err)) {
                fail(err, objs[oi].path);
            }
        }
    }

    // 2. build a contiguous ctor table: copy the (now-patched) entry bytes of
    // every .init_array/.ctors section into one block at the end of .rdata.
    if (!ctorSections.empty()) {
        uint64_t tblOff = cg.rdata.size();
        int64_t total = 0;
        for (auto& cs : ctorSections) {
            for (int64_t i = 0; i < cs.count; i++) {
                uint64_t val = rdField(cg.rdata, (size_t)(cs.off + (uint64_t)i * 8), 8);
                size_t dstOff = cg.rdata.size();
                for (int k = 0; k < 8; k++) cg.rdata.push_back((uint8_t)(val >> (8 * k)));
                absPatches.push_back({1, (uint64_t)dstOff, val, 8});
                total++;
            }
        }
        while ((cg.rdata.size() & 7) != 0) cg.rdata.push_back(0);
        haveCtorTable = true;
        ctorTableRVA = (uint64_t)cg.rdataRVA + tblOff;
        ctorTableCount = total;
    }

    // 3. $mixcrt0 runner appended at end of code
    emitMixCrt0(cg);
}

void MixContext::emitMixCrt0(Codegen& cg) {
    uint64_t pos = cg.code.size();
    cg.funcOffsets["$mixcrt0"] = pos;
    mixcrt0Offset = pos;

    if (target == Target::Arm64) {
        if (!haveCtorTable) {
            cg.code.push_back(0xC0); cg.code.push_back(0x03); cg.code.push_back(0x5F); cg.code.push_back(0xD6);
            return;
        }
        auto emit32w = [&](uint32_t w) {
            for (int i = 0; i < 4; i++) cg.code.push_back((uint8_t)(w >> (8 * i)));
        };
        // stp x29, x30, [sp, #-16]!
        emit32w(0xA9BF7BFD);
        // adrp x9, page(ctorTableRVA)
        size_t adrpPos = cg.code.size();
        {
            int64_t d = ((int64_t)ctorTableRVA >> 12) - ((int64_t)((uint64_t)cg.textRVA + adrpPos) >> 12);
            bool ok = false;
            emit32w(a64PatchAdrp(0x90000009, d, ok));
        }
        // add x9, x9, #lo12:ctorTableRVA
        emit32w(a64PatchLo12(0x91000129, ctorTableRVA));
        // movz x10, #ctorTableCount (movk high part if it overflows 16 bits)
        uint64_t cnt = (uint64_t)ctorTableCount;
        {
            uint16_t lo = (uint16_t)(cnt & 0xFFFF);
            emit32w(0xD2800000u | ((uint32_t)lo << 5) | 0xAu);
            if (cnt > 0xFFFF) {
                uint16_t hi = (uint16_t)((cnt >> 16) & 0xFFFF);
                emit32w(0xF2A00000u | ((uint32_t)hi << 5) | 0xAu);
            }
        }
        size_t loopOff = cg.code.size();
        emit32w(0xF940012B);   // ldr x11, [x9]
        emit32w(0x91002129);   // add x9, x9, #8
        emit32w(0xD63F0160);   // blr x11
        emit32w(0xD100054A);   // sub x10, x10, #1
        size_t cbPos = cg.code.size();
        emit32w(0xB500004A);   // cbnz x10, loop
        {
            int64_t rel = (int64_t)loopOff - (int64_t)cbPos;
            uint32_t imm19 = (uint32_t)(rel >> 2) & 0x7FFFFu;
            wrField(cg.code, cbPos, 4, 0xB500004Au | (imm19 << 5));
        }
        emit32w(0xA8C17BFD);   // ldp x29, x30, [sp], #16
        emit32w(0xD65F03C0);   // ret
        return;
    }

    if (target == Target::Arm32) {
        if (!haveCtorTable) {
            cg.code.push_back(0x70); cg.code.push_back(0x47);   // bx lr
            return;
        }
        auto emit16 = [&](uint16_t h) {
            cg.code.push_back((uint8_t)h); cg.code.push_back((uint8_t)(h >> 8));
        };
        // push {r4, r5, lr}
        emit16(0xB570);
        // movw r4, #(ctorTableRVA & 0xFFFF) ; movt r4, #(ctorTableRVA >> 16)
        {
            uint16_t lo = (uint16_t)(ctorTableRVA & 0xFFFF);
            uint16_t hi = (uint16_t)((ctorTableRVA >> 16) & 0xFFFF);
            uint8_t l4 = (uint8_t)((lo >> 12) & 0xF), il = (uint8_t)((lo >> 11) & 1),
                    l3 = (uint8_t)((lo >> 8) & 0x7), l8 = (uint8_t)(lo & 0xFF);
            emit16((uint16_t)(0xF240u | ((uint16_t)il << 10) | l4));
            emit16((uint16_t)(0x0400u | ((uint16_t)l3 << 12) | l8));
            uint8_t h4 = (uint8_t)((hi >> 12) & 0xF), ih = (uint8_t)((hi >> 11) & 1),
                    h3 = (uint8_t)((hi >> 8) & 0x7), h8 = (uint8_t)(hi & 0xFF);
            emit16((uint16_t)(0xF2C0u | ((uint16_t)ih << 10) | h4));
            emit16((uint16_t)(0x0400u | ((uint16_t)h3 << 12) | h8));
        }
        // movw r5, #(count & 0xFFFF) ; movt r5, #(count >> 16)
        {
            uint16_t lo = (uint16_t)((uint64_t)ctorTableCount & 0xFFFF);
            uint16_t hi = (uint16_t)(((uint64_t)ctorTableCount >> 16) & 0xFFFF);
            uint8_t l4 = (uint8_t)((lo >> 12) & 0xF), il = (uint8_t)((lo >> 11) & 1),
                    l3 = (uint8_t)((lo >> 8) & 0x7), l8 = (uint8_t)(lo & 0xFF);
            emit16((uint16_t)(0xF240u | ((uint16_t)il << 10) | l4));
            emit16((uint16_t)(0x0500u | ((uint16_t)l3 << 12) | l8));
            uint8_t h4 = (uint8_t)((hi >> 12) & 0xF), ih = (uint8_t)((hi >> 11) & 1),
                    h3 = (uint8_t)((hi >> 8) & 0x7), h8 = (uint8_t)(hi & 0xFF);
            emit16((uint16_t)(0xF2C0u | ((uint16_t)ih << 10) | h4));
            emit16((uint16_t)(0x0500u | ((uint16_t)h3 << 12) | h8));
        }
        size_t loopOff = cg.code.size();
        emit16(0xF8D00004);   // ldr.w r0, [r4, #0]
        emit16(0xF1040408);   // add.w r4, r4, #8
        emit16(0x4700);       // blx r0
        emit16(0x3D01);       // subs r5, r5, #1
        size_t cbPos = cg.code.size();
        emit16(0xD100);       // bne loop (patched below)
        {
            int64_t rel = (int64_t)loopOff - (int64_t)(cbPos + 2);
            int16_t imm8 = (int16_t)((rel >> 1) & 0xFF);
            wrField(cg.code, cbPos, 2, (uint16_t)(0xD100u + imm8));
        }
        emit16(0xBD70);       // pop {r4, r5, pc}
        return;
    }

    if (haveCtorTable) {
        // push rbx ; push r12
        cg.code.push_back(0x53);
        cg.code.push_back(0x41); cg.code.push_back(0x54);
        // lea rbx, [rip+ctorTable]
        cg.code.push_back(0x48); cg.code.push_back(0x8D); cg.code.push_back(0x1D);
        uint64_t leaPos = cg.code.size();
        int64_t disp = (int64_t)ctorTableRVA - (int64_t)((uint64_t)cg.textRVA + leaPos + 4);
        for (int i = 0; i < 4; i++) cg.code.push_back((uint8_t)((uint64_t)disp >> (8 * i)));
        // mov r12d, ctorTableCount
        cg.code.push_back(0x41); cg.code.push_back(0xBC);
        for (int i = 0; i < 4; i++) cg.code.push_back((uint8_t)((uint64_t)ctorTableCount >> (8 * i)));
        // L: mov rcx, [rbx]
        cg.code.push_back(0x48); cg.code.push_back(0x8B); cg.code.push_back(0x0B);
        // add rbx, 8
        cg.code.push_back(0x48); cg.code.push_back(0x83); cg.code.push_back(0xC3); cg.code.push_back(0x08);
        // call rcx
        cg.code.push_back(0xFF); cg.code.push_back(0xD1);
        // dec r12d
        cg.code.push_back(0x41); cg.code.push_back(0xFF); cg.code.push_back(0xCC);
        // jnz L
        cg.code.push_back(0x75); cg.code.push_back(0xF2);
        // pop r12 ; pop rbx ; ret
        cg.code.push_back(0x41); cg.code.push_back(0x5C);
        cg.code.push_back(0x5B);
        cg.code.push_back(0xC3);
    } else {
        cg.code.push_back(0xC3);   // ret
    }
    // keep code 16-aligned for the container
    while ((cg.code.size() & 0xF) != 0) cg.code.push_back(0xCC);
}

} // namespace mix

// ============================================================================
// Codegen-side applications (declared in codegen.h, MixContext is a friend)
// ============================================================================
void Codegen::emitMixCrt0Call() {
    if (!mixCtx || !mixCtx->hasAny) return;
    if (prog.koDriver) return;
    emit8(0xE8);
    callFixups.push_back({code.size(), "$mixcrt0"});
    emit32(0);
}

void Codegen::applyMixAbsPatches(uint64_t base) {
    if (!mixCtx) return;
    if (getenv("ZT_MIX_DEBUG"))
        fprintf(stderr, "mix abs patches=%zu base=%llx\n", mixCtx->absPatches.size(),
                (unsigned long long)base);
    for (auto& p : mixCtx->absPatches) {
        auto& vec = (p.bucket == 0) ? code : ((p.bucket == 1) ? rdata : data);
        uint64_t v = p.value + base;
        uint8_t raw[8];
        for (int i = 0; i < 8; i++) raw[i] = (uint8_t)(v >> (8 * i));
        for (int i = 0; i < p.width; i++) vec[p.off + (size_t)i] = raw[i];
    }
}