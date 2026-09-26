#include "mixobj.h"
#include <fstream>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <map>

namespace mixobj {

namespace {

uint16_t rd16(const std::vector<uint8_t>& b, size_t off) {
    if (off + 2 > b.size()) return 0;
    return (uint16_t)b[off] | ((uint16_t)b[off + 1] << 8);
}
uint32_t rd32(const std::vector<uint8_t>& b, size_t off) {
    if (off + 4 > b.size()) return 0;
    return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}
uint64_t rd64(const std::vector<uint8_t>& b, size_t off) {
    uint64_t lo = rd32(b, off);
    uint64_t hi = rd32(b, off + 4);
    return lo | (hi << 32);
}

void appendTo(std::vector<uint8_t>& v, const std::vector<uint8_t>& b, size_t off, size_t sz) {
    if (off >= b.size()) return;
    if (sz > b.size() - off) sz = b.size() - off;
    v.insert(v.end(), b.begin() + (ptrdiff_t)off, b.begin() + (ptrdiff_t)(off + sz));
}

std::string readStr(const std::vector<uint8_t>& b, size_t off) {
    if (off >= b.size()) return "";
    size_t end = off;
    while (end < b.size() && b[end] != 0) end++;
    return std::string((const char*)b.data() + off, end - off);
}

// A string table: pieces are NUL-terminated strings starting at arbitrary
// offsets; we keep the raw arena for random access.
struct StrArena {
    std::vector<uint8_t> data;
    std::string at(size_t off) const {
        if (off >= data.size()) return "";
        size_t end = off;
        while (end < data.size() && data[end] != 0) end++;
        return std::string((const char*)data.data() + off, end - off);
    }
};

// ============================================================================
// ELF (32 and 64 bit)
// ============================================================================

struct ElfFile {
    bool is64 = false;
    uint16_t machine = 0;
    uint64_t shoff = 0;
    uint16_t shentsize = 0;
    uint16_t shnum = 0;
    uint16_t shstrndx = 0;
};

bool parseElfHeader(const std::vector<uint8_t>& b, ElfFile& h) {
    if (b.size() < 52) return false;
    uint8_t cls = b[4];
    if (cls == 2) {
        h.is64 = true;
        h.machine = rd16(b, 18);
        h.shoff = rd64(b, 40);
        h.shentsize = rd16(b, 58);
        h.shnum = rd16(b, 60);
        h.shstrndx = rd16(b, 62);
    } else if (cls == 1) {
        h.is64 = false;
        h.machine = rd16(b, 18);
        h.shoff = rd32(b, 32);
        h.shentsize = rd16(b, 46);
        h.shnum = rd16(b, 48);
        h.shstrndx = rd16(b, 50);
    } else {
        return false;
    }
    return true;
}

// Section header offsets for the raw numeric fields.
uint64_t shNameOff(bool is64) { return 0; }
uint64_t shTypeOff(bool is64) { return 4; }
uint64_t shFlagsOff(bool is64) { return is64 ? 8 : 8; }
uint64_t shAddrOff(bool is64) { return is64 ? 16 : 12; }
uint64_t shOffsetOff(bool is64) { return is64 ? 24 : 16; }
uint64_t shSizeOff(bool is64) { return is64 ? 32 : 20; }
uint64_t shLinkOff(bool is64) { return is64 ? 40 : 24; }
uint64_t shInfoOff(bool is64) { return is64 ? 44 : 28; }
uint64_t shAlignOff(bool is64) { return is64 ? 48 : 32; }
uint64_t shEntsizeOff(bool is64) { return is64 ? 56 : 36; }

uint64_t readField(const std::vector<uint8_t>& b, uint64_t off, bool is64) {
    return is64 ? rd64(b, (size_t)off) : rd32(b, (size_t)off);
}

// x86-64 ELF relocation types -> RelKind (only the ones we can relocate).
RelKind elf64RelKind(uint32_t t) {
    switch (t) {
        case 1:             return RelKind::Abs64;   // R_X86_64_64
        case 2:             return RelKind::PcRel32; // R_X86_64_PC32
        case 4:             return RelKind::PcRel32; // R_X86_64_PLT32
        case 9:             return RelKind::GotPcRel;// R_X86_64_GOTPCREL
        case 10: case 11:   return RelKind::Abs32;   // R_X86_64_32 / _32S
        case 41: case 42:   return RelKind::GotPcRel;// GOTPCRELX / REX_GOTPCRELX
        default:            return RelKind::None;
    }
}

RelKind coffRelKind(uint16_t machine, uint16_t t) {
    if (machine == 0x8664) {
        switch (t) {
            case 1: return RelKind::Abs64;   // IMAGE_REL_AMD64_ADDR64
            case 2: return RelKind::Abs32;   // IMAGE_REL_AMD64_ADDR32
            case 4: return RelKind::PcRel32; // IMAGE_REL_AMD64_REL32
            default: return RelKind::None;
        }
    }
    switch (t) {
        case 6:  return RelKind::Abs32;     // IMAGE_REL_I386_DIR32
        case 0x14: return RelKind::PcRel32; // IMAGE_REL_I386_REL32
        default: return RelKind::None;
    }
}

// AArch64 ELF relocation types -> RelKind.
RelKind elfA64RelKind(uint32_t t) {
    switch (t) {
        case 257: return RelKind::Abs64;       // R_AARCH64_ABS64
        case 258: return RelKind::Abs32;       // R_AARCH64_ABS32
        case 261: return RelKind::PcRel32;     // R_AARCH64_PREL32
        case 260: return RelKind::PcRel64;     // R_AARCH64_PREL64
        case 274: return RelKind::Arm64AdrLo;  // R_AARCH64_ADR_PREL_LO21
        case 275: return RelKind::Arm64AdrpPg; // R_AARCH64_ADR_PREL_PG_HI21
        case 277: return RelKind::Arm64AddLo12;// R_AARCH64_ADD_ABS_LO12_NC
        case 283: return RelKind::Arm64Call26; // R_AARCH64_CALL26
        case 282: return RelKind::Arm64Call26; // R_AARCH64_JUMP26
        case 290: case 291: case 292: case 293: case 299:
            return RelKind::Arm64LdStLo12;     // LDST{32,64,8,16,128}_ABS_LO12_NC
        default: return RelKind::None;
    }
}

// ARM32 ELF relocation types -> RelKind.
RelKind elfArmRelKind(uint32_t t) {
    switch (t) {
        case 2:  return RelKind::Abs32;         // R_ARM_ABS32
        case 3:  return RelKind::PcRel32;       // R_ARM_PREL32 / REL32
        case 10: return RelKind::ArmThmCall;    // R_ARM_THM_CALL (BL/BLX)
        case 28: return RelKind::ArmCall;       // R_ARM_CALL
        case 29: return RelKind::ArmCall;       // R_ARM_JUMP24 (B)
        case 30: return RelKind::ArmThmCall;    // R_ARM_THM_JUMP24 (B.W)
        case 43: return RelKind::ArmMovwAbs;    // R_ARM_MOVW_ABS_NC
        case 44: return RelKind::ArmMovwAbs;    // R_ARM_MOVT_ABS
        case 47: return RelKind::ArmThmMovwAbs; // R_ARM_THM_MOVW_ABS_NC
        case 48: return RelKind::ArmThmMovwAbs; // R_ARM_THM_MOVT_ABS
        default: return RelKind::None;
    }
}

bool readElfObject(const std::vector<uint8_t>& b, Object& out, const ElfFile& h) {
    const uint64_t shentsize = h.shentsize ? h.shentsize : (h.is64 ? 64 : 40);
    if (h.shnum == 0) { out.error = "ELF has no sections"; return false; }
    const uint64_t shBase = h.shoff;

    auto shOff = [&](uint16_t i) -> uint64_t { return shBase + (uint64_t)i * shentsize; };
    auto shName = [&](uint16_t i) -> uint32_t { return rd32(b, (size_t)(shOff(i) + shNameOff(h.is64))); };

    // .shstrtab contents for section names.
    StrArena shstrArena;
    if (h.shstrndx < h.shnum) {
        uint64_t so = shOff(h.shstrndx);
        uint64_t off = readField(b, so + shOffsetOff(h.is64), h.is64);
        uint64_t sz = readField(b, so + shSizeOff(h.is64), h.is64);
        appendTo(shstrArena.data, b, (size_t)off, (size_t)sz);
    }

    std::vector<std::string> secNames;
    std::vector<uint32_t> secTypes;
    std::vector<uint64_t> secFlags, secOffs, secSizes, secAligns, secEntsizes;
    std::vector<uint32_t> secLinks, secInfos;
    for (uint16_t i = 0; i < h.shnum; i++) {
        uint64_t so = shOff(i);
        uint32_t nm = rd32(b, (size_t)(so));
        secNames.push_back(shstrArena.at(nm));
        secTypes.push_back(rd32(b, (size_t)(so + shTypeOff(h.is64))));
        secFlags.push_back(readField(b, so + shFlagsOff(h.is64), h.is64));
        secOffs.push_back(readField(b, so + shOffsetOff(h.is64), h.is64));
        secSizes.push_back(readField(b, so + shSizeOff(h.is64), h.is64));
        secLinks.push_back(rd32(b, (size_t)(so + shLinkOff(h.is64))));
        secInfos.push_back(rd32(b, (size_t)(so + shInfoOff(h.is64))));
        secAligns.push_back(readField(b, so + shAlignOff(h.is64), h.is64));
        secEntsizes.push_back(readField(b, so + shEntsizeOff(h.is64), h.is64));
    }

    // Machine -> arch.
    switch (h.machine) {
        case 0x3e: out.arch = Arch::X86_64; break;
        case 0x03: out.arch = Arch::X86_32; break;
        case 0x28: out.arch = Arch::ARM32; break;
        case 0xb7: out.arch = Arch::ARM64; break;
        default: out.error = "unsupported ELF machine"; return false;
    }

    // Materialize allocatable sections (PROGBITS / NOBITS / INIT_ARRAY only).
    out.sections.resize(h.shnum);
    for (uint16_t i = 0; i < h.shnum; i++) {
        Section& s = out.sections[i];
        s.name = secNames[i];
        s.type = secTypes[i];
        s.flags = secFlags[i];
        s.info = secInfos[i];
        s.link = secLinks[i];
        s.addrAlign = secAligns[i] ? secAligns[i] : 1;
        if (secTypes[i] == 8) { // SHT_NOBITS
            s.noBits = true;
            s.bytes.assign((size_t)secSizes[i], 0);
            continue;
        }
        if (secTypes[i] != 1 && secTypes[i] != 14) continue; // PROGBITS / INIT_ARRAY
        uint64_t off = secOffs[i], sz = secSizes[i];
        if (off >= b.size() || sz == 0) continue;
        if (sz > b.size() - off) sz = b.size() - off;
        s.bytes.assign(b.begin() + (ptrdiff_t)off, b.begin() + (ptrdiff_t)(off + sz));
    }

    // Symbol table.
    int symIdx = -1;
    for (uint16_t i = 0; i < h.shnum; i++) if (secTypes[i] == 2) { symIdx = i; break; }
    StrArena strArena;
    if (symIdx >= 0 && secLinks[symIdx] < h.shnum) {
        uint16_t st = (uint16_t)secLinks[symIdx];
        uint64_t off = secOffs[st], sz = secSizes[st];
        appendTo(strArena.data, b, (size_t)off, (size_t)sz);
    }

    if (symIdx >= 0) {
        bool w64 = h.is64;
        size_t symEnt = w64 ? 24 : 16;
        uint64_t so = secOffs[symIdx], sz = secSizes[symIdx];
        size_t count = (size_t)(sz / symEnt);
        for (size_t k = 0; k < count; k++) {
            uint64_t o = so + k * symEnt;
            uint32_t nm = rd32(b, (size_t)o);
            Symbol sym;
            sym.name = strArena.at(nm);
            sym.value = readField(b, o + (w64 ? 8 : 4), w64);
            uint8_t info = b[o + 4];
            sym.bind = (uint8_t)(info >> 4);
            sym.type = (uint8_t)(info & 0x0F);
            int16_t sh = (int16_t)rd16(b, (size_t)(o + 6));
            if (sh > 0) sym.section = sh;   // sections vector is indexed by ELF shndx (null at [0])
            else if (sh == 0) sym.section = -2;
            else if (sh == -1) sym.section = -1;
            else sym.section = -2;
            sym.weak = (sym.bind == 2);
            if (sym.type == 3 && sh > 0 && sym.name.empty())
                sym.name = secNames[sh - 1];
            if (sym.type == 3) sym.isSectionSym = true;
            out.symbols.push_back(sym);
        }
    }

    // Relocations.
    if (h.is64) {
        for (uint16_t i = 0; i < h.shnum; i++) {
            if (secTypes[i] != 4 && secTypes[i] != 9) continue;
            bool rela = (secTypes[i] == 4);
            int target = (int)secInfos[i];
            if (target < 0 || target >= (int)h.shnum) continue;
            uint64_t so = secOffs[i], sz = secSizes[i];
            size_t ent = rela ? 24 : 16;
            size_t count = (size_t)(sz / ent);
            for (size_t k = 0; k < count; k++) {
                uint64_t o = so + k * ent;
                uint64_t rOff = rd64(b, (size_t)o);
                uint64_t rInfo = rd64(b, (size_t)(o + 8));
                uint64_t symIdx2 = (rInfo >> 32) & 0xFFFFFFFFu;
                uint32_t rType = (uint32_t)(rInfo & 0xFFFFFFFFu);
                int64_t rAdd = rela ? (int64_t)rd64(b, (size_t)(o + 16)) : 0;
                Reloc rc;
                rc.section = target;
                rc.offset = rOff;
                rc.rawType = rType;
                rc.symbolIndex = (int64_t)symIdx2;
                if (symIdx2 < out.symbols.size()) {
                    const Symbol& sym = out.symbols[symIdx2];
                    rc.targetName = sym.isSectionSym ? "" : sym.name;
                    rc.targetSection = sym.section;
                }
                if (rela) { rc.explicitAddend = true; rc.addend = rAdd; }
                rc.kind = (h.machine == 0x3e) ? elf64RelKind(rType) :
                          (h.machine == 0xb7) ? elfA64RelKind(rType) : RelKind::None;
                out.relocs.push_back(rc);
            }
        }
    } else {
        for (uint16_t i = 0; i < h.shnum; i++) {
            if (secTypes[i] != 4 && secTypes[i] != 9) continue;
            bool rela = (secTypes[i] == 4);
            int target = (int)secInfos[i];
            if (target < 0 || target >= (int)h.shnum) continue;
            uint64_t so = secOffs[i], sz = secSizes[i];
            size_t ent = rela ? 12 : 8;
            size_t count = (size_t)(sz / ent);
            for (size_t k = 0; k < count; k++) {
                uint64_t o = so + k * ent;
                uint64_t rOff = rd32(b, (size_t)o);
                uint32_t rInfo = rd32(b, (size_t)(o + 4));
                uint64_t symIdx2 = (rInfo >> 8) & 0xFFFFFFu;
                uint32_t rType = rInfo & 0xFFu;
                int64_t rAdd = rela ? (int64_t)(int32_t)rd32(b, (size_t)(o + 8)) : 0;
                Reloc rc;
                rc.section = target;
                rc.offset = rOff;
                rc.rawType = rType;
                rc.symbolIndex = (int64_t)symIdx2;
                if (symIdx2 < out.symbols.size()) {
                    const Symbol& sym = out.symbols[symIdx2];
                    rc.targetName = sym.isSectionSym ? "" : sym.name;
                    rc.targetSection = sym.section;
                }
                if (rela) { rc.explicitAddend = true; rc.addend = rAdd; }
                rc.kind = (h.machine == 0x28) ? elfArmRelKind(rType) : RelKind::None;
                out.relocs.push_back(rc);
            }
        }
    }

    out.valid = true;
    return true;
}

// ============================================================================
// COFF object files
// ============================================================================

struct CoffFile {
    uint16_t machine = 0;
    uint16_t nsec = 0;
    uint32_t symOff = 0;
    uint32_t nSyms = 0;
    uint16_t optSize = 0;
};

bool parseCoffHeader(const std::vector<uint8_t>& b, CoffFile& h) {
    if (b.size() < 20) return false;
    h.machine = rd16(b, 0);
    h.nsec = rd16(b, 2);
    h.symOff = rd32(b, 8);
    h.nSyms = rd32(b, 12);
    h.optSize = rd16(b, 16);
    return true;
}

bool readCoffObject(const std::vector<uint8_t>& b, Object& out, const CoffFile& h) {
    out.arch = (h.machine == 0x14c) ? Arch::X86_32 : Arch::X86_64;
    out.isCoff = true;
    uint64_t secBase = 20 + h.optSize;
    if (secBase + (uint64_t)h.nsec * 40 > b.size()) { out.error = "COFF: section headers overflow"; return false; }

    const uint32_t IMAGE_SCN_CNT_CODE = 0x20;
    const uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40;
    const uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80;
    const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    const uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
    const uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

    // String table (indexed by /nnn names).
    StrArena strArena;
    {
        uint64_t stOff = (uint64_t)h.symOff + (uint64_t)h.nSyms * 18;
        if (stOff + 4 <= b.size()) {
            uint32_t len = rd32(b, (size_t)stOff);
            if (len > 4 && stOff + len <= b.size())
                strArena.data.assign(b.begin() + (ptrdiff_t)(stOff + 4), b.begin() + (ptrdiff_t)(stOff + len));
        }
    }

    auto secNameStr = [&](const char* nm8) -> std::string {
        if (nm8[0] == '/') {
            char buf[12];
            size_t i = 1, j = 0;
            while (i < 8 && isdigit((unsigned char)nm8[i]) && j + 1 < sizeof(buf)) buf[j++] = nm8[i++];
            buf[j] = 0;
            return strArena.at((size_t)atol(buf));
        }
        size_t len = 0;
        while (len < 8 && nm8[len]) len++;
        return std::string(nm8, len);
    };

    struct RawSec {
        std::string name;
        uint32_t chars;
        uint32_t rawPtr;
        uint32_t rawSize;
        uint32_t relocPtr;
        uint16_t nreloc;
    };
    std::vector<RawSec> raws;
    out.sections.resize(h.nsec);
    for (uint16_t i = 0; i < h.nsec; i++) {
        uint64_t o = secBase + (uint64_t)i * 40;
        RawSec rs;
        rs.name = secNameStr((const char*)&b[o]);
        rs.rawSize = rd32(b, o + 16);
        rs.rawPtr = rd32(b, o + 20);
        rs.relocPtr = rd32(b, o + 24);
        rs.nreloc = rd16(b, o + 32);
        rs.chars = rd32(b, o + 36);
        raws.push_back(rs);

        Section& s = out.sections[i];
        s.name = rs.name;
        s.flags = rs.chars;
        s.addrAlign = 1;
        if (rs.name == ".text" || rs.name.find(".text") == 0) s.addrAlign = 16;
        else if (rs.name.find(".data") == 0 || rs.name.find(".rdata") == 0) s.addrAlign = 16;
        if (rs.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            s.noBits = true;
            s.bytes.assign(rs.rawSize, 0);
        } else if (rs.rawPtr < b.size() && rs.rawSize <= b.size() - rs.rawPtr) {
            s.bytes.assign(b.begin() + rs.rawPtr, b.begin() + rs.rawPtr + rs.rawSize);
        }
    }

    // Symbol table.
    uint64_t symBase = h.symOff;
    size_t symEnt = 18;
    // COFF symbol-table indices count auxiliary records too; keep a mapping
    // from raw record index -> compressed out.symbols index (-1 = aux record).
    std::vector<int> recToSym((size_t)h.nSyms, -1);
    for (uint32_t k = 0; k < h.nSyms; k++) {
        uint64_t o = symBase + (uint64_t)k * symEnt;
        if (o + symEnt > b.size()) break;
        char nm8[9] = {0};
        memcpy(nm8, &b[o], 8);
        std::string name;
        if (nm8[0] == '/') name = strArena.at((size_t)atol(nm8 + 1));
        else name = secNameStr(nm8);
        uint32_t value = rd32(b, o + 8);
        int16_t secNum = (int16_t)rd16(b, o + 12);
        uint8_t storage = b[o + 16];
        uint8_t naux = b[o + 17];

        recToSym[k] = (int)out.symbols.size();
        for (int a = 1; a <= (int)naux; a++)
            if (k + (uint32_t)a < h.nSyms) recToSym[k + (uint32_t)a] = -1;

        Symbol sym;
        sym.name = name;
        sym.value = value;
        if (storage == 2) sym.bind = 1; // EXTERNAL
        else sym.bind = 0;
        if ((secNum & 0x7FFF) == 0) sym.section = -2;   // UNDEF
        else if (secNum == -1) sym.section = -1;        // ABS
        else sym.section = secNum - 1;
        sym.weak = false;
        // COFF type: the derived type (high nibble at offset +14) maps to ELF
        // STT_FUNC (2 = IMAGE_SYM_DTYPE_FUNCTION) so our codegen routing can
        // use a unified type==2 test for "this is a function symbol".
        sym.type = (b[o + 14] >> 4) & 0x0F;
        if (secNum > 0 && (name.empty() || name == raws[secNum - 1].name)) {
            sym.name = raws[secNum - 1].name;
            sym.isSectionSym = true;
        }
        out.symbols.push_back(sym);
        k += naux; // skip aux records
    }

    // Relocations.
    for (uint16_t i = 0; i < h.nsec; i++) {
        if (raws[i].nreloc == 0 || raws[i].relocPtr == 0) continue;
        uint64_t base = raws[i].relocPtr;
        for (uint16_t r = 0; r < raws[i].nreloc; r++) {
            uint64_t o = base + (uint64_t)r * 10;
            if (o + 10 > b.size()) break;
            Reloc rc;
            rc.section = i;
            rc.offset = rd32(b, o);
            uint32_t symIdx2 = rd32(b, o + 4);
            uint16_t rtype = rd16(b, o + 8);
            rc.rawType = rtype;
            rc.symbolIndex = symIdx2;
            rc.kind = coffRelKind(h.machine, rtype);
            if (symIdx2 < recToSym.size()) {
                int csi = recToSym[symIdx2];
                if (csi >= 0 && (size_t)csi < out.symbols.size()) {
                    rc.targetName = out.symbols[csi].isSectionSym ? "" : out.symbols[csi].name;
                    rc.targetSection = out.symbols[csi].section;
                }
            }
            out.relocs.push_back(rc);
        }
    }

    out.valid = true;
    return true;
}

} // namespace

bool readObjectFile(const std::string& path, Object& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) { out.error = "cannot open object file: " + path; return false; }
    std::streamoff sz = f.tellg();
    if (sz < 0 || sz > (std::streamoff)(1u << 31)) { out.error = "bad object size"; return false; }
    std::vector<uint8_t> b((size_t)sz);
    f.seekg(0, std::ios::beg);
    if (!b.empty()) f.read((char*)b.data(), (std::streamsize)sz);
    f.close();

    if (b.size() < 4) { out.error = "object too small"; return false; }
    if (b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        ElfFile h;
        if (!parseElfHeader(b, h)) { out.error = "bad ELF header"; return false; }
        if (!readElfObject(b, out, h)) return false;
        return true;
    }
    if (b[0] == 'M' && b[1] == 'Z') { out.error = "expected a relocatable object, got a PE image"; return false; }
    CoffFile h;
    if (!parseCoffHeader(b, h)) { out.error = "bad COFF header"; return false; }
    if (h.machine != 0x8664 && h.machine != 0x14c) { out.error = "unsupported COFF machine"; return false; }
    return readCoffObject(b, out, h);
}

} // namespace mixobj