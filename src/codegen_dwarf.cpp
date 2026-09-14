#include "codegen.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>

// ============================================================================
// DWARF debug-symbol generator.
//
// Produces a GNU-style *separate debug file*: a minimal ELF64 container holding
// only the .debug_info / .debug_abbrev / .debug_line / .debug_str /
// .debug_aranges sections (DWARF 4 encoding). It is written next to the main
// output as "<output>.debug" and the main binary is left byte-for-byte
// unchanged, so firmware/boot images keep their exact size.
//
// All addresses are pre-linked: DW_AT_low_pc / the line table use the final
// load address (image base + .text RVA + code offset), so gdb maps them onto a
// non-PIE target directly. Usage:
//     gdb ./prog.elf -ex "symbol-file prog.elf.debug"
// or, after `set debug-file-directory <dir>`, gdb finds "prog.elf.debug"
// automatically (it looks for exactly "<exec>.debug").
// ============================================================================

namespace {

// ---- little-endian byte writers ----
void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x & 0xFF)); v.push_back((uint8_t)((x >> 8) & 0xFF));
}
void put32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
}
void put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
}

// ULEB128 / SLEB128 (DWARF).
void uleb128(std::vector<uint8_t>& v, uint64_t x) {
    do {
        uint8_t b = (uint8_t)(x & 0x7F);
        x >>= 7;
        if (x) b |= 0x80;
        v.push_back(b);
    } while (x);
}
void sleb128(std::vector<uint8_t>& v, int64_t x) {
    bool more = true;
    while (more) {
        uint8_t b = (uint8_t)(x & 0x7F);
        x >>= 7;
        // Done when the leading bits match the sign bit.
        if ((x == 0 && !(b & 0x40)) || (x == -1 && (b & 0x40))) more = false;
        else b |= 0x80;
        v.push_back(b);
    }
}

// Deduplicating .debug_str table. Offset 0 is the empty string.
struct StrTab {
    std::vector<uint8_t> bytes{0};
    std::map<std::string, uint32_t> off;
    uint32_t add(const std::string& s) {
        if (s.empty()) return 0;
        auto it = off.find(s);
        if (it != off.end()) return it->second;
        uint32_t o = (uint32_t)bytes.size();
        bytes.insert(bytes.end(), s.begin(), s.end());
        bytes.push_back(0);
        off[s] = o;
        return o;
    }
};

// ---- ELF64 constants for the debug container ----
constexpr uint8_t  EI_NIDENT = 16;
constexpr uint16_t ET_REL     = 1;
constexpr uint16_t EM_X86_64  = 62;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_STRTAB   = 3;

// ---- DWARF constants ----
constexpr uint8_t  DW_TAG_compile_unit = 0x11;
constexpr uint8_t  DW_TAG_subprogram   = 0x2E;
constexpr uint8_t  DW_CHILDREN_no      = 0x00;
constexpr uint8_t  DW_CHILDREN_yes     = 0x01;
constexpr uint16_t DW_AT_producer      = 0x25;
constexpr uint16_t DW_AT_language      = 0x13;
constexpr uint16_t DW_AT_name          = 0x03;
constexpr uint16_t DW_AT_comp_dir      = 0x1B;
constexpr uint16_t DW_AT_low_pc        = 0x11;
constexpr uint16_t DW_AT_high_pc       = 0x12;
constexpr uint16_t DW_AT_stmt_list     = 0x10;
constexpr uint16_t DW_AT_external      = 0x3F;
constexpr uint16_t DW_AT_decl_file     = 0x3A;
constexpr uint16_t DW_AT_decl_line     = 0x3B;
constexpr uint16_t DW_FORM_addr        = 0x01;
constexpr uint16_t DW_FORM_data4       = 0x06;
constexpr uint16_t DW_FORM_data8       = 0x07;
constexpr uint16_t DW_FORM_data1       = 0x0B;
constexpr uint16_t DW_FORM_flag        = 0x0C;
constexpr uint16_t DW_FORM_strp        = 0x0E;
constexpr uint16_t DW_FORM_data2       = 0x05;
constexpr uint8_t  DW_LNS_copy           = 0x01;
constexpr uint8_t  DW_LNS_advance_line   = 0x03;
constexpr uint8_t  DW_LNS_set_file       = 0x04;
constexpr uint8_t  DW_LNS_set_prologue_end = 0x0A;
constexpr uint8_t  DW_LNE_set_address    = 0x02;
constexpr uint8_t  DW_LNE_end_sequence   = 0x01;
constexpr uint16_t DW_LANG_C99           = 0x000C;

} // namespace

void Codegen::writeDebugInfo(uint64_t imageBase, const std::string& outputPath) {
    if (!emitDebugInfo) return;
    if (dbgSubprograms.empty() && dbgLines.empty()) return;

    // ----- source name / compile dir from the user-provided path -----
    std::string srcName = "zenith.z";
    std::string compDir = ".";
    if (!sourcePath.empty()) {
        std::filesystem::path sp(sourcePath);
        std::string base = sp.filename().string();
        if (!base.empty()) srcName = base;
        std::string parent = sp.parent_path().string();
        if (parent.empty()) parent = ".";
        compDir = parent;
    }

    // ----- string table -----
    StrTab strs;
    uint32_t prodStr = strs.add("Zenith 1.0 (DWARF debug info)");
    uint32_t nameStr = strs.add(srcName);
    uint32_t compDirStr = strs.add(compDir);
    std::map<std::string, uint32_t> funcStrOff;
    for (auto& f : dbgSubprograms)
        if (!f.name.empty()) funcStrOff[f.name] = strs.add(f.name);

    uint64_t textBase = imageBase + (uint64_t)textRVA;
    uint64_t codeSize = (uint64_t)code.size();

    // ----- .debug_abbrev -----
    std::vector<uint8_t> abbrev;
    uleb128(abbrev, 1);
    uleb128(abbrev, DW_TAG_compile_unit);
    uleb128(abbrev, DW_CHILDREN_yes);
    uleb128(abbrev, DW_AT_producer);   uleb128(abbrev, DW_FORM_strp);
    uleb128(abbrev, DW_AT_language);   uleb128(abbrev, DW_FORM_data2);
    uleb128(abbrev, DW_AT_name);       uleb128(abbrev, DW_FORM_strp);
    uleb128(abbrev, DW_AT_comp_dir);   uleb128(abbrev, DW_FORM_strp);
    uleb128(abbrev, DW_AT_low_pc);     uleb128(abbrev, DW_FORM_addr);
    uleb128(abbrev, DW_AT_high_pc);    uleb128(abbrev, DW_FORM_data8);
    uleb128(abbrev, DW_AT_stmt_list);  uleb128(abbrev, DW_FORM_data4);
    abbrev.push_back(DW_CHILDREN_no); abbrev.push_back(0);
    uleb128(abbrev, 2);
    uleb128(abbrev, DW_TAG_subprogram);
    uleb128(abbrev, DW_CHILDREN_no);
    uleb128(abbrev, DW_AT_external);   uleb128(abbrev, DW_FORM_flag);
    uleb128(abbrev, DW_AT_name);       uleb128(abbrev, DW_FORM_strp);
    uleb128(abbrev, DW_AT_low_pc);     uleb128(abbrev, DW_FORM_addr);
    uleb128(abbrev, DW_AT_high_pc);    uleb128(abbrev, DW_FORM_data8);
    uleb128(abbrev, DW_AT_decl_file);  uleb128(abbrev, DW_FORM_data1);
    uleb128(abbrev, DW_AT_decl_line);  uleb128(abbrev, DW_FORM_data2);
    abbrev.push_back(0); abbrev.push_back(0);   // attribute-list terminator
    abbrev.push_back(0);                        // end of abbreviation table
    std::vector<uint8_t> info;
    {
        std::vector<uint8_t> body;
        uleb128(body, 1);                             // CU DIE
        put32(body, prodStr);
        put16(body, DW_LANG_C99);
        put32(body, nameStr);
        put32(body, compDirStr);
        put64(body, textBase);                        // low_pc (absolute)
        put64(body, codeSize);                        // high_pc (offset)
        put32(body, 0);                               // stmt_list
        for (auto& f : dbgSubprograms) {
            if (f.end <= f.start) continue;
            uleb128(body, 2);                         // subprogram DIE
            body.push_back(1);                        // external
            put32(body, funcStrOff[f.name]);
            put64(body, textBase + (uint64_t)f.start);
            put64(body, (uint64_t)(f.end - f.start));
            body.push_back(1);                        // decl_file
            put16(body, (uint16_t)(f.line > 0 ? f.line : 0));
        }
        body.push_back(0);                            // DIE terminator
        put32(info, (uint32_t)(7 + body.size()));    // unit_length (version 2 + abbrev off 4 + addr size 1)
        put16(info, 4);                               // version
        put32(info, 0);                               // debug_abbrev_offset
        info.push_back(8);                            // address_size
        info.insert(info.end(), body.begin(), body.end());
    }

    // ----- .debug_line -----
    std::vector<DbgLineEntry> lines;
    for (auto& e : dbgLines) if (e.line > 0) lines.push_back(e);
    std::stable_sort(lines.begin(), lines.end(),
                     [](const DbgLineEntry& a, const DbgLineEntry& b) { return a.offset < b.offset; });
    lines.erase(std::unique(lines.begin(), lines.end(),
                            [](const DbgLineEntry& a, const DbgLineEntry& b) {
                                return a.offset == b.offset && a.line == b.line;
                            }),
                lines.end());
    if (lines.empty()) lines.push_back({0, 1});   // never leave a file without a row

    std::vector<uint8_t> program;
    int64_t regLine = 1;
    bool first = true;
    for (auto& e : lines) {
        if (first) {
            program.push_back(DW_LNS_set_file);   uleb128(program, 1);
            // extended op: set_address
            program.push_back(0); uleb128(program, 9); program.push_back(DW_LNE_set_address);
            put64(program, textBase + (uint64_t)e.offset);
            program.push_back(DW_LNS_set_prologue_end);
            first = false;
        } else {
            program.push_back(0); uleb128(program, 9); program.push_back(DW_LNE_set_address);
            put64(program, textBase + (uint64_t)e.offset);
        }
        int64_t delta = (int64_t)e.line - regLine;
        if (delta != 0) {
            program.push_back(DW_LNS_advance_line); sleb128(program, delta);
        }
        program.push_back(DW_LNS_copy);
        regLine = e.line;
    }
    program.push_back(0); uleb128(program, 1); program.push_back(DW_LNE_end_sequence);

    std::vector<uint8_t> line;
    {
        size_t hdrLen =
            1 + 1 + 1 + 1 + 1 + 1 + 12 +       // min_instr, max_ops, is_stmt, base, range, opcode_base
            + 1 +                              // include_directories (empty)
            srcName.size() + 1 + 1 + 1 + 1 + 1;   // name\0 + dir idx + mtime + size + terminator
        size_t totalTail = 2 + 4 + hdrLen + program.size();
        put32(line, (uint32_t)totalTail);
        put16(line, 4);
        put32(line, (uint32_t)hdrLen);
        line.push_back(1);                        // min_instruction_length
        line.push_back(1);                        // max_operations_per_instruction
        line.push_back(1);                        // default_is_stmt
        line.push_back((uint8_t)(int8_t)-5);      // line_base
        line.push_back(14);                       // line_range
        line.push_back(13);                       // opcode_base
        static const uint8_t stdLen[12] = {0,1,1,1,1,0,0,0,1,0,0,1};
        line.insert(line.end(), stdLen, stdLen + 12);
        line.push_back(0);                        // include_directories: none
        for (char c : srcName) line.push_back((uint8_t)c);
        line.push_back(0);                        // file name
        uleb128(line, 0);                         // dir index = 0 (compilation dir)
        uleb128(line, 0);                         // mtime
        uleb128(line, 0);                         // size
        line.push_back(0);                        // end of file_names
        line.insert(line.end(), program.begin(), program.end());
    }

    // ----- .debug_aranges -----
    std::vector<uint8_t> aranges;
    {
        std::vector<uint8_t> tail;
        tail.push_back(8);                        // address_size
        tail.push_back(0);                        // segment_size
        for (int i = 0; i < 4; i++) tail.push_back(0); // pad to 16-byte tuple alignment
        put64(tail, textBase);                    // CU range begins
        put64(tail, codeSize);
        put64(tail, 0);                           // terminator
        put64(tail, 0);
        put32(aranges, (uint32_t)(2 + 4 + tail.size()));
        put16(aranges, 2);
        put32(aranges, 0);                        // debug_info_offset
        aranges.insert(aranges.end(), tail.begin(), tail.end());
    }

    // ----- Assemble the sidecar ELF64 -----
    const char* names[] = { ".debug_info", ".debug_abbrev", ".debug_line",
                            ".debug_str", ".debug_aranges", ".shstrtab" };
    const int numSections = 1 + 6;                // null + 6
    std::vector<std::vector<uint8_t>> secData = { {}, info, abbrev, line, strs.bytes, aranges };

    std::vector<uint8_t> shstr(1, 0);
    std::vector<uint32_t> nameOff;
    for (int i = 0; i < 6; i++) {
        nameOff.push_back((uint32_t)shstr.size());
        for (const char* p = names[i]; *p; p++) shstr.push_back((uint8_t)*p);
        shstr.push_back(0);
    }

    uint64_t off = 64;
    std::vector<uint64_t> secOff(numSections, 0);
    std::vector<uint64_t> secSize(numSections, 0);
    for (int i = 1; i <= 5; i++) {
        secOff[i] = off;
        secSize[i] = secData[i].size();
        off += secSize[i];
    }
    secOff[6] = off; secSize[6] = shstr.size(); off += shstr.size();
    uint64_t shoff = (off + 7) & ~7ull;

    std::vector<uint8_t> out;
    out.reserve((size_t)(shoff + (size_t)numSections * 64));
    out.push_back(0x7F); out.push_back('E'); out.push_back('L'); out.push_back('F');
    out.push_back(2);           // ELFCLASS64
    out.push_back(1);           // ELFDATA2LSB
    out.push_back(1);           // EV_CURRENT
    out.push_back(0);           // ELFOSABI_SYSV
    for (int i = 8; i < 16; i++) out.push_back(0);
    put16(out, ET_REL);
    put16(out, EM_X86_64);
    put32(out, 1);              // e_version
    put64(out, 0); put64(out, 0);              // e_entry, e_phoff
    put64(out, shoff);                          // e_shoff
    put32(out, 0);              // e_flags
    put16(out, 64);             // e_ehsize
    put16(out, 0);              // e_phentsize
    put16(out, 0);              // e_phnum
    put16(out, 64);             // e_shentsize
    put16(out, numSections);    // e_shnum
    put16(out, 6);              // e_shstrndx

    for (int i = 1; i <= 5; i++)
        out.insert(out.end(), secData[i].begin(), secData[i].end());
    out.insert(out.end(), shstr.begin(), shstr.end());
    while (out.size() < shoff) out.push_back(0);

    auto writeShdr = [&](uint32_t n, uint32_t type, uint64_t offset, uint64_t size, uint64_t align) {
        put32(out, n);
        put32(out, type);
        put64(out, 0);
        put64(out, 0);
        put64(out, offset);
        put64(out, size);
        put32(out, 0);
        put32(out, 0);
        put64(out, align);
        put64(out, 0);
    };
    for (int i = 0; i < 64; i++) out.push_back(0);   // null section header
    writeShdr(nameOff[0], SHT_PROGBITS, secOff[1], secSize[1], 8);
    writeShdr(nameOff[1], SHT_PROGBITS, secOff[2], secSize[2], 1);
    writeShdr(nameOff[2], SHT_PROGBITS, secOff[3], secSize[3], 8);
    writeShdr(nameOff[3], SHT_PROGBITS, secOff[4], secSize[4], 1);
    writeShdr(nameOff[4], SHT_PROGBITS, secOff[5], secSize[5], 8);
    writeShdr(nameOff[5], SHT_STRTAB, secOff[6], secSize[6], 1);

    std::string dbgPath = outputPath + ".debug";
    {
        std::ofstream f(dbgPath, std::ios::binary);
        if (!f) {
            std::cerr << "Error: cannot write debug file '" << dbgPath << "'" << std::endl;
            return;
        }
        f.write((const char*)out.data(), (std::streamsize)out.size());
        f.close();
    }
    std::cout << "Debug info: " << dbgPath << " (" << out.size() << " B, main binary byte-identical)\n";
}