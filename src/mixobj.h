#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace mixobj {

enum class Arch { X86_64, X86_32, ARM32, ARM64, Wasm };

enum class RelKind {
    None,
    PcRel32,     // S + A - P, 32-bit field
    PcRel64,     // S + A - P, 64-bit field
    Abs32,       // S + A, 32-bit field
    Abs64,       // S + A, 64-bit field
    Abs16,       // S + A, 16-bit field
    GotPcRel,    // G(S) + A - P: call through a per-address cell
    ArmCall,     // ARM32 BL: (S + A - P) >> 2, 24-bit
    ArmThmCall,  // ARM32 Thumb BL: (S + A - P) >> 1, 24-bit
    ArmPcRel31,  // ARM32 PREL31
    Arm64Call26, // AArch64 BL: (S + A - P) >> 2, 26-bit
    ArmMovwAbs,  // ARM32 MOVW/MOVT imm16 low/high: (S + A) & 0xFFFF / >> 16
    ArmThmMovwAbs, // ARM32 Thumb MOVW/MOVT imm16 pair (same value as ArmMovwAbs)
    Arm64AdrpPg, // AArch64 ADRP: page(s) of (S + A) minus page(P) >> 12
    Arm64AdrLo,  // AArch64 ADR: (S + A - P), low 21 bits
    Arm64AddLo12,// AArch64 ADD imm12: (S + A) & 0xFFF
    Arm64LdStLo12,// AArch64 LDR/STR imm12: (S + A) & 0xFFF
};

struct Section {
    std::string name;
    uint32_t type = 0;
    uint64_t flags = 0;
    std::vector<uint8_t> bytes;
    bool noBits = false;
    uint64_t addrAlign = 1;
    uint32_t info = 0;
    uint32_t link = 0;
    // Layout result (set by the relocator before use).
    int bucket = -1;          // 0 = code, 1 = rdata, 2 = data
    uint64_t bucketOffset = 0;
};

struct Symbol {
    std::string name;
    int section = -2;         // -2 common undef, -1 absolute, >= 0 section index
    uint64_t value = 0;
    uint8_t bind = 0;
    uint8_t type = 0;
    bool weak = false;
    bool isSectionSym = false;
};

struct Reloc {
    int section = -1;
    uint64_t offset = 0;
    uint32_t rawType = 0;
    bool explicitAddend = false;
    int64_t addend = 0;
    int64_t symbolIndex = -1;
    std::string targetName;
    int targetSection = -2;
    // Offset encoded in the referenced section symbol's st_value. `ld -r`
    // folds the input-section offset of a merged section into the merged
    // section symbol, so a section-only reference (targetName empty) must add
    // this to the section base.
    int64_t targetSectionOffset = 0;
    RelKind kind = RelKind::None;
};

struct Object {
    Arch arch = Arch::X86_64;
    bool isCoff = false;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<Reloc> relocs;
    bool isCpp = false;
    bool valid = false;
    std::string error;
};

bool readObjectFile(const std::string& path, Object& out);

// Same as readObjectFile, but parses an already-loaded buffer (ELF or COFF).
bool readObjectBytes(const std::vector<uint8_t>& b, Object& out);

} // namespace mixobj