#include "mix.h"
#include "codegen.h"
#include "syslibs.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>

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
    return mingwDllFor(sym);
}

std::string MixContext::sonameFor(const std::string& sym) const {
    return linuxSonameFor(sym);
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
                    "-ffunction-sections", "-fdata-sections", "-g0",
                    // Route libc references to real msvcrt.dll exports instead
                    // of the __imp_* import pointers mingw normally emits, and
                    // call printf directly rather than the static __mingw_
                    // formatting helpers. The remaining static-only helpers are
                    // folded in by prelinkWindows().
                    "-D__USE_MINGW_ANSI_STDIO=0", "-D_CRTIMP=", "-D__MINGW_IMPORT="};
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
    } else if (target == Target::WindowsPe) {
        // Keep the object so prelinkWindows() can fold the mingw CRT glue in.
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

    ObjState st;
    st.obj = std::move(obj);
    st.path = path;
    st.objPath = objPath;
    st.isCpp = isCpp;
    st.bucket.assign(st.obj.sections.size(), -1);
    st.off.assign(st.obj.sections.size(), 0);
    objs.push_back(std::move(st));
    registerObject(objs.back());
    hasAny = true;
    hasCpp = hasCpp || isCpp;
    return true;
}

// Record symbols + relocations of a freshly parsed object. Shared by the
// per-source addSource() path and the WindowsPE prelink step.
void MixContext::registerObject(ObjState& st) {
    auto& obj = st.obj;

    // Record undefined function symbols (PE target uses these to inject IAT
    // entries before buildImportData runs). clang marks undefined references
    // to functions as NOTYPE on ELF (aarch64) and FUNC on PE, so accept both
    // except on PE where NOTYPE is ambiguous (data refs).
    for (auto& sym : obj.symbols) {
        if (sym.section != -2 || sym.name.empty()) continue;
        if (sym.type == 2 || (sym.type == 0 && target != Target::WindowsPe))
            undefFuncs.push_back(sym.name);
        else if (sym.type == 0)
            undefData.push_back(sym.name);
    }
    // Record undefined symbols referenced by call-site relocations anywhere in
    // the mixed sources: used at resolve() time to classify unknown host
    // symbols (kind==0 from the probe) as functions vs data objects.
    for (auto& r : obj.relocs) {
        if (r.targetName.empty()) continue;
        if (r.targetSection != -2) continue;                // only undefined targets
        bool call = obj.isCoff ? (r.rawType == 4 || r.rawType == 0x14)
                               : (r.rawType == 4);          // R_X86_64_PLT32
        if (call) undefCalled.insert(r.targetName);
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
}

// ============================================================================
// WindowsPE: fold the mingw CRT glue archives into the mixed objects.
//
// The C/C++ sources are compiled with __imp_/-D__USE_MINGW_ANSI_STDIO=0 so the
// only libc references they emit are plain msvcrt.dll exports. A handful of
// helpers have no DLL export at all (round, cbrt, __mingw_vfprintf,
// __mingw_strtod, _CRT_MT, ...): mingw normally satisfies them from the static
// libmingwex/libmingw32/libgcc archives. `ld -r` over those archives folds the
// needed members (and their own references) into one relocatable object, while
// leaving every msvcrt/libstdc++ symbol undefined so it can still be routed to
// the runtime DLL. Two passes let the first pass's resolved members pull in
// what the second pass still needs.
// ============================================================================
static std::string probeToolchainFile(const std::string& cc, const std::string& lib) {
    std::string cmd = cc + " -print-file-name=" + lib + " 2>/dev/null";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "";
    char buf[1024];
    std::string out;
    while (fgets(buf, sizeof buf, f)) out += buf;
    pclose(f);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
        out.pop_back();
    if (out.empty() || out == lib) return "";
    return out;
}

bool MixContext::prelinkWindows(std::string& err) {
    if (target != Target::WindowsPe || objs.empty()) return true;

    const char* envCC = getenv("ZENITH_MINGW_CC");
    std::string cc = (envCC && *envCC) ? envCC : "x86_64-w64-mingw32-gcc";
    // Derive the sibling `-ld` driver (<triple>-gcc -> <triple>-ld).
    std::string ld = cc;
    {
        size_t slash = ld.find_last_of('/');
        std::string dir = (slash == std::string::npos) ? "" : ld.substr(0, slash + 1);
        std::string base = (slash == std::string::npos) ? ld : ld.substr(slash + 1);
        if (base.size() > 4 && base.compare(base.size() - 4, 4, "-gcc") == 0)
            base = base.substr(0, base.size() - 4) + "-ld";
        else
            base = "ld";
        ld = dir + base;
    }

    std::vector<std::string> libs;
    for (const char* l : {"libmingwex.a", "libmingw32.a", "libgcc.a", "libgcc_eh.a"}) {
        std::string p = probeToolchainFile(cc, l);
        if (!p.empty()) libs.push_back(p);
    }
    if (libs.empty()) {
        err = "WindowsPE mix: mingw CRT archives not found (is the "
              "x86_64-w64-mingw32 toolchain installed?)";
        return false;
    }

    // mingw keeps a handful of CRT helpers that have no msvcrt.dll export as
    // static members of libmsvcrt.a (`__acrt_iob_func`, `__p__environ`, ...)
    // rather than in libmingwex. The archive's other members are import thunks
    // (defs/defh/deft), so extract only the static `_common_a-`/`_extra_a-`
    // members into a private archive and fold that in too.
    std::string msvcrtStatic;
    {
        std::string ar = cc;
        {
            size_t slash = ar.find_last_of('/');
            std::string dir = (slash == std::string::npos) ? "" : ar.substr(0, slash + 1);
            std::string base = (slash == std::string::npos) ? ar : ar.substr(slash + 1);
            if (base.size() > 4 && base.compare(base.size() - 4, 4, "-gcc") == 0)
                base = base.substr(0, base.size() - 4) + "-ar";
            else
                base = "ar";
            ar = dir + base;
        }
        std::string libmsvcrt = probeToolchainFile(cc, "libmsvcrt.a");
        std::string msDir = std::filesystem::temp_directory_path().string() +
                            "/zenith_msvcrt_static";
        std::error_code ec;
        std::filesystem::remove_all(msDir, ec);
        std::filesystem::create_directories(msDir, ec);
        if (!libmsvcrt.empty() && !ec) {
            std::string listCmd = ar + " t " + libmsvcrt + " 2>/dev/null";
            FILE* lf = popen(listCmd.c_str(), "r");
            std::vector<std::string> members;
            if (lf) {
                char lbuf[1024];
                while (fgets(lbuf, sizeof lbuf, lf)) {
                    std::string m = lbuf;
                    while (!m.empty() && (m.back() == '\n' || m.back() == '\r')) m.pop_back();
                    if (m.find("_common_a-") != std::string::npos ||
                        m.find("_extra_a-") != std::string::npos)
                        members.push_back(m);
                }
                pclose(lf);
            }
            if (!members.empty()) {
                std::string extractCmd = "cd " + msDir + " && " + ar + " x " + libmsvcrt;
                for (auto& m : members) extractCmd += " " + m;
                extractCmd += " 2>/dev/null";
                msvcrtStatic = msDir + "/libzenith_msvcrt_static.a";
                std::string combineCmd = "cd " + msDir + " && " + ar + " rcs " +
                                         msvcrtStatic + " ";
                for (auto& m : members) combineCmd += m + " ";
                combineCmd += "2>/dev/null";
                if (system(extractCmd.c_str()) == 0 &&
                    system(combineCmd.c_str()) == 0)
                    libs.push_back(msvcrtStatic);
                else
                    msvcrtStatic.clear();
            }
        }
    }

    std::string tmpDir = std::filesystem::temp_directory_path().string();
    std::string combPath = tmpDir + "/zenith_mix_win_glue.o";

    auto buildCmd = [&](const std::string& outPath,
                        const std::vector<std::string>& inputs) {
        std::string cmd = ld + " -r --allow-multiple-definition -o " + outPath +
                          " --start-group";
        for (auto& in : inputs) cmd += " " + in;
        for (auto& l : libs) cmd += " " + l;
        cmd += " --end-group 2>/dev/null";
        return cmd;
    };

    std::vector<std::string> inputs;
    for (auto& o : objs)
        if (!o.objPath.empty()) inputs.push_back(o.objPath);
    if (inputs.empty()) return true;

    // Pass 1: resolve the directly-used glue. Pass 2 feeds the result back so
    // members pulled in by pass 1 have their own undefined glue resolved too.
    std::string pass1 = combPath + ".1";
    if (system(buildCmd(pass1, inputs).c_str()) != 0) {
        err = "WindowsPE mix: CRT glue prelink failed";
        return false;
    }
    if (system(buildCmd(combPath, {pass1}).c_str()) != 0) {
        err = "WindowsPE mix: second CRT glue prelink pass failed";
        return false;
    }

    mixobj::Object comb;
    if (!mixobj::readObjectFile(combPath, comb) || !comb.valid) {
        err = comb.error.empty() ? "could not parse prelinked CRT glue object"
                                 : comb.error;
        return false;
    }

    // Remove the per-source objects + intermediate; only the combined object
    // is kept for the rest of the pipeline.
    std::error_code ec;
    for (auto& p : inputs) std::filesystem::remove(p, ec);
    std::filesystem::remove(pass1, ec);

    // Rebuild all registration state from the prelinked object: the archives
    // bring in definitions (round, ...) and new undefined references.
    objs.clear();
    defs.clear();
    defBucket.clear();
    undefFuncs.clear();
    undefData.clear();
    undefCalled.clear();
    stubOffsets.clear();
    linuxDataCell.clear();

    ObjState st;
    st.obj = std::move(comb);
    st.path = combPath;
    st.objPath = combPath;
    st.isCpp = hasCpp;
    st.bucket.assign(st.obj.sections.size(), -1);
    st.off.assign(st.obj.sections.size(), 0);
    objs.push_back(std::move(st));
    registerObject(objs.back());
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

        // WindowsPE: a `.rdata$.refptr.<X>` cell for an *undefined* data symbol
        // <X> is the mingw idiom for importing a data object (std::cout). The
        // relocatable object has no way to fill the cell with the loader's
        // resolved address, so drop the cell and redirect the REL32 that read
        // it at <X>'s IAT slot (resolveReloc). Defined symbols keep the normal
        // cell (e.g. _CRT_MT / __tinytens_D2A from the prelinked CRT glue).
        if (obj.isCoff && target == Target::WindowsPe &&
            sec.name.rfind(".rdata$.refptr.", 0) == 0) {
            std::string X = sec.name.substr(15);
            bool isUndef = false;
            for (auto& sym : obj.symbols)
                if (sym.section == -2 && sym.name == X) { isUndef = true; break; }
            if (isUndef) {
                O.refptrImport[sec.name] = X;                    // .rdata$.refptr.<X>
                O.refptrImport[".refptr." + X] = X;              // linker alias
                continue;
            }
        }

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

        // object-local defined symbols (".LCn" labels / local statics): names
        // may collide across translation units, so resolve them per-object.
        for (auto& sym : obj.symbols) {
            if (sym.section < 0 || sym.section != (int)s) continue;
            if (sym.bind != 0 || sym.isSectionSym) continue;
            if (sym.name.empty() || sym.value >= sec.bytes.size()) continue;
            if (O.locals.count(sym.name)) continue;
            uint64_t base = registerOnly ? 0 : O.off[s];
            O.locals[sym.name] = base + sym.value;
            O.localBucket[sym.name] = b;
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
    int sBucket = -1;             // bucket where S lives: 0 text, 1 rdata, 2 data
    bool defined = false;
    bool isSectionRef = r.targetName.empty() && r.targetSection >= 0;

    size_t byteOff = O.off[(size_t)secIdx] + r.offset;

    if (isSectionRef) {
        int tb = r.targetSection;
        if (tb >= (int)O.bucket.size() || O.bucket[tb] < 0) MIX_ERR("relocation references a non-placed section");
        S = (uint64_t)bucketBase(cg, O.bucket[tb]) + O.off[tb] +
            (uint64_t)r.targetSectionOffset;
        sBucket = O.bucket[tb];
        defined = true;
    } else {
        std::string sym = r.targetName;

        // WindowsPE imported data. Two spellings reach us:
        //   * `.refptr.<X>` — the mingw COMDAT cell for using an imported data
        //     object <X> (std::cout). The cell section was dropped; the code
        //     does `mov <cell>(%rip), reg`, so point it straight at <X>'s IAT
        //     slot, whose loader-filled content is &<X>.
        //   * `__imp_<F>` — the import pointer for a function <F> (the prelinked
        //     CRT glue uses these for Sleep / critical sections). Same trick:
        //     the reference is the address of the IAT slot.
        // In both cases the import entry (and its IAT slot) was allocated by
        // buildImportData() from the synthetic externs main.cpp injected.
        if (target == Target::WindowsPe) {
            std::string base;
            auto rit = O.refptrImport.find(sym);
            if (rit != O.refptrImport.end()) base = rit->second;
            else if (sym.rfind("__imp_", 0) == 0) base = sym.substr(6);
            if (!base.empty()) {
                auto eit = cg.externFuncMap.find(base);
                if (eit == cg.externFuncMap.end())
                    MIX_ERR("WindowsPE mix: no import slot for data symbol '" + base + "'");
                S = (uint64_t)eit->second.second;   // RVA of the IAT slot
                sBucket = 2;
                defined = true;
                uint64_t P = (uint64_t)bucketBase(cg, b) + byteOff;
                if (kind == mixobj::RelKind::Abs64 ||
                    kind == mixobj::RelKind::Abs32) {
                    int fw = (kind == mixobj::RelKind::Abs64) ? 8 : 4;
                    wrField(vec, byteOff, fw, (uint64_t)(S + A));
                    baked.push_back({b, byteOff, 1, 2, (uint8_t)fw});
                } else {
                    int64_t disp = (int64_t)S + A - (int64_t)P;
                    wrField(vec, byteOff, 4, (uint64_t)(uint32_t)disp);
                    baked.push_back({b, byteOff, 0, 2, 4});
                }
                return true;
            }
        }
        // Object-local defined symbols (".LCn" labels / local statics) resolve
        // per-translation-unit, not against the global defs map.
        auto lit = O.locals.find(sym);
        if (lit != O.locals.end()) {
            auto lb = O.localBucket.find(sym);
            S = (uint64_t)bucketBase(cg, lb != O.localBucket.end() ? lb->second : 2) + lit->second;
            sBucket = lb != O.localBucket.end() ? lb->second : 2;
            defined = true;
        } else {
            bool found = false;
            defined = (symRVA(cg, sym, found), found);
            if (defined) {
                S = symRVA(cg, sym, found);
                auto dbit = defBucket.find(sym);
                sBucket = (dbit != defBucket.end()) ? dbit->second : 0;   // else a z func / flat image (text)
            }
        }
        if (!defined) {
            // crtbegin.o normally provides __dso_handle as a local, self-referential
            // data cell (its address is passed to __cxa_atexit as the DSO handle).
            // A mix has no CRT, so synthesize it once; the cell content is its own
            // image address (patched by applyMixAbsPatches).
            if (sym == "__dso_handle") {
                auto dh = defs.find(sym);
                uint32_t cellOff;
                if (dh == defs.end()) {
                    cellOff = (uint32_t)cg.data.size();
                    for (int i = 0; i < 8; i++) cg.data.push_back(0);
                    defs[sym] = cellOff;
                    defBucket[sym] = 2;
                } else cellOff = (uint32_t)dh->second;
                absPatches.push_back({2, (uint64_t)cellOff, (uint64_t)(cg.dataRVA + cellOff), 8, 2});
                S = (uint64_t)cg.dataRVA + cellOff;
                sBucket = 2;
                defined = true;
            }
            // 8-byte pointer cell for a library data/function symbol: appended
            // to .data, resolved at runtime by an R_X86_64_64 against the
            // probed soname (GOTPCREL / Abs64 relocations).
            auto makePtrCell = [&](const std::string& nm) -> uint32_t {
                uint32_t cellOff = (uint32_t)cg.data.size();
                for (int k = 0; k < 8; k++) cg.data.push_back(0);
                cg.mixDynCells.push_back({cg.dataRVA + cellOff, nm, sonameFor(nm)});
                return cellOff;
            };
            // 8-byte (or host-size) data cell for a library data object: sized
            // from the host .dynsym, deduplicated per symbol, and loaded at
            // startup by an R_X86_64_COPY relocation (a -no-pie style copy).
            auto makeDataCell = [&](const std::string& nm) -> uint32_t {
                auto it = linuxDataCell.find(nm);
                if (it != linuxDataCell.end()) return it->second;
                size_t sz = linuxDynSymSize(nm);
                if (sz < 8) sz = 8;
                sz = (size_t)((sz + 7) & ~7ull);
                uint32_t cellOff = (uint32_t)cg.data.size();
                for (size_t k = 0; k < sz; k++) cg.data.push_back(0);
                cg.copyRelocs.push_back({cg.dataRVA + cellOff, nm});
                linuxDataCell[nm] = cellOff;
                return cellOff;
            };
            // Jump-indirect stub for a library function (call-site / PLT32).
            // The 32-bit disp pointing at the GOT slot is patched by buildELF.
            auto makeLinuxStub = [&](const std::string& nm) -> uint64_t {
                if (stubOffsets.count(nm)) return stubOffsets[nm];
                uint64_t stub = cg.code.size();
                cg.code.push_back(0xFF); cg.code.push_back(0x25);
                cg.elfImportFixups.push_back({cg.code.size(), nm, sonameFor(nm)});
                cg.code.push_back(0); cg.code.push_back(0);
                cg.code.push_back(0); cg.code.push_back(0);
                stubOffsets[nm] = stub;
                return stub;
            };
            auto makeWinStub = [&](const std::string& nm) -> uint64_t {
                if (stubOffsets.count(nm)) return stubOffsets[nm];
                uint64_t stub = cg.code.size();
                cg.code.push_back(0xFF); cg.code.push_back(0x25);
                cg.importCallFixups.push_back({cg.code.size(), nm, dllFor(nm)});
                cg.code.push_back(0); cg.code.push_back(0);
                cg.code.push_back(0); cg.code.push_back(0);
                stubOffsets[nm] = stub;
                return stub;
            };

            int dynKind = dynKindFor(r);
            if (!defined) {
                if (target == Target::LinuxElf && dynKind == 1 && r.rawType == 4) {
                // R_X86_64_PLT32 call-site: a function, always a jmp stub.
                S = (uint64_t)cg.textRVA + makeLinuxStub(sym);
                sBucket = 0;
                defined = true;
            } else if (target == Target::WindowsPe && dynKind == 1) {
                S = (uint64_t)cg.textRVA + makeWinStub(sym);
                sBucket = 0;
                defined = true;
            } else if (target == Target::LinuxElf && dynKindRef2(r)) {
                uint32_t cellOff = makePtrCell(sym);
                S = (uint64_t)cg.dataRVA + cellOff;
                sBucket = 2;
                defined = true;
            } else if (target == Target::LinuxElf) {
                // Abs32/32S or PC32 (data) reference to a host symbol: probe
                // the system library for the symbol's kind and route it as a
                // function (stub) or a data object (copy cell).
                int hostKind = linuxSymbolKind(sym);
                bool isFunc = (hostKind == 1) || (hostKind == 0 && undefCalled.count(sym) > 0);
                if (isFunc) {
                    S = (uint64_t)cg.textRVA + makeLinuxStub(sym);
                    sBucket = 0;
                } else {
                    uint32_t cellOff = makeDataCell(sym);
                    S = (uint64_t)cg.dataRVA + cellOff;
                    sBucket = 2;
                }
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
    }

    uint64_t P = (uint64_t)bucketBase(cg, b) + byteOff;

    // Record x86 relocation writes so the ELF backend can re-bake the field if
    // the .rdata/.data bases move after resolve() (final fixupSectionRVAs()).
    auto noteBaked = [&](int bakedKind, int width) {
        if (sBucket < 0) return;
        if (b == 0 && sBucket == 0) return;    // text<->text, never shifts
        if (b < 0 || b > 2 || sBucket < 0 || sBucket > 2) return;
        baked.push_back({b, (uint64_t)byteOff, bakedKind, sBucket, (uint8_t)width});
    };

    switch (kind) {
        case mixobj::RelKind::Abs16: {
            int64_t v = (int64_t)S + A;
            wrField(vec, byteOff, 2, (uint64_t)v);
            absPatches.push_back({b, (uint64_t)byteOff, (uint64_t)v, 2, sBucket});
            noteBaked(1, 2);
            return true;
        }
        case mixobj::RelKind::Abs32:
        case mixobj::RelKind::Abs64: {
            int64_t v = (int64_t)S + A;
            wrField(vec, byteOff, fwidth, (uint64_t)v);
            absPatches.push_back({b, (uint64_t)byteOff, (uint64_t)v, (uint8_t)fwidth, sBucket});
            noteBaked(1, fwidth);
            return true;
        }
        case mixobj::RelKind::PcRel32:
        case mixobj::RelKind::GotPcRel: {
            int64_t v = (int64_t)S - (int64_t)P + A;
            wrField(vec, byteOff, 4, (uint64_t)v);
            noteBaked(0, 4);
            return true;
        }
        case mixobj::RelKind::PcRel64: {
            int64_t v = (int64_t)S - (int64_t)P + A;
            wrField(vec, byteOff, 8, (uint64_t)v);
            noteBaked(0, 8);
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

    // Bases the relocator bakes references against. The ELF backend may re-run
    // fixupSectionRVAs() after this (final sizes) and calls rebaseELF() to
    // re-bake everything by the resulting deltas.
    resolveRdataRVA = cg.rdataRVA;
    resolveDataRVA  = cg.dataRVA;
    baked.clear();

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
            auto& srcVec = (cs.bucket == 0) ? cg.code
                        : ((cs.bucket == 1) ? cg.rdata : cg.data);
            for (int64_t i = 0; i < cs.count; i++) {
                uint64_t val = rdField(srcVec, (size_t)(cs.off + (uint64_t)i * 8), 8);
                size_t dstOff = cg.rdata.size();
                for (int k = 0; k < 8; k++) cg.rdata.push_back((uint8_t)(val >> (8 * k)));
                absPatches.push_back({1, (uint64_t)dstOff, val, 8, 0});   // ctor fn ptr lives in .text
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
        // Wide (32-bit) Thumb-2 encodings are two halfwords: passing the whole
        // word to emit16() would silently drop the top 16 bits.
        emit16(0xF8D0); emit16(0x0004);   // ldr.w r0, [r4, #0]
        emit16(0xF104); emit16(0x0408);   // add.w r4, r4, #8
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
        if (target == Target::LinuxElf)
            baked.push_back({0, (uint64_t)leaPos, 0, 1, 4});   // re-bake if .rdata moves
        // mov r12d, ctorTableCount
        cg.code.push_back(0x41); cg.code.push_back(0xBC);
        for (int i = 0; i < 4; i++) cg.code.push_back((uint8_t)((uint64_t)ctorTableCount >> (8 * i)));
        // sub rsp, 8: after two pushes the stack is rsp%16==8, but per the SysV
        // ABI rsp must be 16-aligned immediately before each `call` (here the
        // `call rcx`), so the callee observes the required rsp%16==8 at entry.
        cg.code.push_back(0x48); cg.code.push_back(0x83); cg.code.push_back(0xEC); cg.code.push_back(0x08);
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
        // add rsp, 8 (balance the pre-call alignment pad below)
        cg.code.push_back(0x48); cg.code.push_back(0x83); cg.code.push_back(0xC4); cg.code.push_back(0x08);
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

// ============================================================================
// rebaseELF: re-bake every reference resolve() pinned to the .rdata/.data bases
// that existed at resolve() time. After resolve() (and the late string pool)
// the ELF pipeline re-runs fixupSectionRVAs() on the final section sizes, which
// moves rdataRVA/dataRVA by whole pages. The ET_EXEC program headers map file
// offset == RVA, so any stale reference would point at the wrong byte: each
// recorded cell RVA, written relocation field and abs patch must chase the new
// bases.
// ============================================================================
void MixContext::rebaseELF(Codegen& cg) {
    if (target != Target::LinuxElf) return;
    int32_t dRdata = (int32_t)cg.rdataRVA - (int32_t)resolveRdataRVA;
    int32_t dData  = (int32_t)cg.dataRVA  - (int32_t)resolveDataRVA;
    if (dRdata == 0 && dData == 0) return;
    if (getenv("ZT_MIX_DEBUG"))
        fprintf(stderr, "mix rebaseELF dRdata=%d dData=%d baked=%zu abs=%zu\n",
                dRdata, dData, baked.size(), absPatches.size());

    auto deltaOf = [&](int tb) { return tb == 1 ? (int64_t)dRdata
                              : (tb == 2 ? (int64_t)dData : 0); };

    // 8-byte dynamic cells / copy cells in .data chase dataRVA (buildELF emits
    // their .rela entries from these cellRVAs).
    for (auto& c : cg.mixDynCells) c.cellRVA = (uint32_t)((int64_t)c.cellRVA + dData);
    for (auto& c : cg.copyRelocs)  c.cellRVA = (uint32_t)((int64_t)c.cellRVA + dData);

    // Relocation fields resolve() wrote against the old bucket bases.
    for (auto& bk : baked) {
        auto& vec = (bk.src == 0) ? cg.code : ((bk.src == 1) ? cg.rdata : cg.data);
        if (bk.off + bk.width > vec.size()) continue;
        uint64_t v = rdField(vec, (size_t)bk.off, bk.width);
        int64_t delta = (bk.kind == 1) ? deltaOf(bk.tgt) : deltaOf(bk.tgt) - deltaOf(bk.src);
        if (delta != 0) wrField(vec, (size_t)bk.off, bk.width, (uint64_t)((int64_t)v + delta));
    }

    // Absolute patches (applied by applyMixAbsPatches at container build) that
    // point into .rdata/.data: shift the recorded target RVA by its section.
    for (auto& p : absPatches) {
        if (p.tgt == 1) p.value += (uint64_t)dRdata;
        else if (p.tgt == 2) p.value += (uint64_t)dData;
    }

    // The ctor table sits at the end of .rdata; its crt0 lea was re-baked
    // through the baked list above. Keep the recorded RVA in sync for flat
    // backends that reuse the same context.
    if (haveCtorTable) ctorTableRVA += (uint64_t)dRdata;
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