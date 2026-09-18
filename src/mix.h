#pragma once
#include "ast.h"
#include "mixobj.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

class Codegen;

namespace mix {

enum class Target {
    LinuxElf,    // ELF64 ET_EXEC ('app linux')
    WindowsPe,   // PE console/gui/dll and EFI (static relocations baked)
    Flat,        // BIOS/Bare flat x86 images (base 0)
    KernelModule,// .ko driver: objects handed to ld -r, never merged
    Arm64,       // flat AArch64 image (classic or IR; base baked at imageBase)
    Arm32,       // flat ARMv7-M thumb image (STM32, base 0)
    Wasm         // WebAssembly module (functions spliced into the code section)
};

// A location in the merged codegen buckets that needs an absolute (base +
// targetRVA) value written into it at container-build time.
struct AbsPatch {
    int bucket;      // 0 = code, 1 = rdata, 2 = data
    uint64_t off;    // offset within the bucket vector
    uint64_t value;  // base-less target RVA
    uint8_t width;   // 4 or 8
};

// An 8-byte absolute pointer cell in the merged .data/.rdata whose runtime
// value is supplied by the dynamic loader / PE import machinery.
struct DynCell {
    uint64_t dataOff = 0;   // offset within the codegen data bucket
    std::string symbol;     // undefined symbol name
};

// Mangled names: `_Z<len><name><types>` (subset of the Itanium ABI sufficient
// for interop with C++ *.cpp sources that do not use classes).
std::string mangleName(const std::string& name);
std::string mangleName(const std::string& name, const std::vector<Type>& params);

class MixContext {
public:
    Target target = Target::LinuxElf;
    bool hasAny = false;
    bool hasCpp = false;
    std::vector<std::string> errors;

    // Optimization level (0..3, mirroring Zenith's) forwarded to the C/C++
    // compiler as -O0/-O1/-O2/-O3/-Os. set from main() so mixed objects are
    // built with the same optimization intent as the z side.
    int cOptLevel = 2;
    // Mapping: 0 -> -O0, 1 -> -O2, 2 -> -Os, 3 -> -O3 (size optimization by
    // default, matching the classic backend's "Max" intent).
    std::string cOptFlag() const;

    // ---- step 0 (main.cpp): compile a C/C++ source, parse the .o ----
    bool addSource(const std::string& path, bool isCpp,
                   const std::vector<std::string>& extraArgs, std::string& err);

    // Undefined function symbols collected during addSource (used by PE target
    // to inject synthetic IAT stubs before buildImportData).
    std::vector<std::string> undefFuncs;

    // ---- codegen hooks ----
    // true when the symbol is defined (statically) by one of the C/C++ objects
    // (plain name, or mangled name for C++ sources).
    bool providesLocal(const std::string& name) const;
    bool providesLocal(const std::string& name, const std::vector<Type>& params) const;
    // symbol under which the local function is registered (plain for C,
    // mangled for C++) — used as the callFixups target name.
    std::string localSymbol(const std::string& name, const std::vector<Type>& params) const;

    // Registers the C-defined functions in codegen funcOffsets and appends the
    // merged section bytes to code/rdata/data. Call BEFORE fixupSectionRVAs.
    void layout(Codegen& cg);

    // Resolves C-internal and C<->z relocations, emits dyn import stubs, the
    // $mixcrt0 runner and the ctor table. Call AFTER fixupSectionRVAs.
    void resolve(Codegen& cg);

    // number of constructor-table entries known after layout() (used by the
    // flat-image backends to size $mixcrt0 before resolve() runs)
    int64_t ctorCountEstimate() const;

    // Exact $mixcrt0 byte size for the target arch (called before resolve()).
    size_t mixcrt0Size(bool haveCtor) const;

    // Flat-image merge for the arm64/arm32/wasm backends. Appends the C/C++
    // text/rdata/data (+ $mixcrt0) to 'out' after 'imageEnd', bakes
    // 'imageBase' into absolute cells and records C function offsets
    // (base-less image RVAs) into 'funcs'. Returns false+error on failure.
    // 'scratch' is a Codegen on the same program whose buckets receive the
    // merge (mixCtx.zFuncRVAs must be filled first).
    bool flatMerge(Codegen& scratch, uint64_t imageBase, size_t imageEnd,
                   std::vector<uint8_t>& out,
                   std::unordered_map<std::string, uint64_t>& funcs,
                   std::string& err);

    // Same as flatMerge, but builds its own scratch Codegen internally; used
    // by IR backends that do not carry a Program of their own.
    bool flatMergeImage(uint64_t imageBase, size_t imageEnd,
                        std::vector<uint8_t>& out,
                        std::unordered_map<std::string, uint64_t>& funcs,
                        std::string& err);

    // true if one of the C/C++ objects defines a function with this name.
    bool hasCFunction(const std::string& name) const;

    // ---- results consumed by the container builders ----
    std::vector<AbsPatch> absPatches;
    std::vector<DynCell>  dynCells;
    bool haveCtorTable = false;
    uint64_t ctorTableRVA = 0;          // base-less RVA of the ctor array (.rdata)
    int64_t  ctorTableCount = 0;
    uint64_t mixcrt0Offset = 0;         // $mixcrt0 code offset
    // Flat-image backends (arm64/arm32/wasm): base-less image offsets of the z
    // functions, filled by the backend before layout() so C objects can target
    // z functions. Uses the same RVA space as the scratch codegen buckets.
    std::unordered_map<std::string, uint64_t> zFuncRVAs;
    // KO: extra ET_REL objects to fold into the final ld -r, and the symbol
    // names they define (emitted as SHN_UNDEF so buildKO's call fixups bind).
    std::vector<std::string> koObjects;
    std::unordered_set<std::string> koProvidedNames;

private:
    // one parsed object + its placement state
    struct ObjState {
        mixobj::Object obj;
        std::string path;
        bool isCpp = false;
        // per-section bucket (-1 dropped) and bucket offset, filled by layout()
        std::vector<int>    bucket;
        std::vector<uint64_t> off;
    };
    // one .init_array/.ctors section that contributes entries to the ctor table
    struct CtorSection {
        int bucket = 1;      // always rdata
        uint64_t off = 0;    // byte offset of the first entry inside the bucket
        int64_t count = 0;   // number of 8-byte entries
    };
    std::vector<ObjState> objs;
    std::unordered_map<std::string, uint64_t> defs; // defined symbol -> offset within its bucket
    std::unordered_map<std::string, int> defBucket;
    std::unordered_map<std::string, uint64_t> stubOffsets; // "$imp_"+sym -> code offset
    std::vector<CtorSection> ctorSections;
    bool laidOut = false;

    void placeObject(Codegen& cg, size_t oi);
    static uint32_t bucketBase(Codegen& cg, int b);
    // returns true if the relocation was resolved (field patched), false if it
    // needs a deferred abs patch, or throws on error.
    bool resolveReloc(Codegen& cg, size_t oi, const mixobj::Reloc& r, std::string& err);
    uint64_t symRVA(Codegen& cg, const std::string& name, bool& found) const;
    void emitMixCrt0(Codegen& cg);
    int  dynKindFor(const mixobj::Reloc& r) const; // 0 none, 1 call stub, 2 cell
    bool dynKindRef2(const mixobj::Reloc& r) const; // data-pointer cell import
    std::string dllFor(const std::string& sym) const;
    std::string sonameFor(const std::string& sym) const;
    void fail(const std::string& msg, const std::string& what);
};

} // namespace mix