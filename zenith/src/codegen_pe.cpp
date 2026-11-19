#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include "font5x7.h"
#include "font8x16_cyr.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <iterator>
#include <set>
#include <cmath>

using namespace std;

// Forward-declare Windows API to avoid windows.h conflicts with custom PE structs
#ifdef _WIN32
extern "C" {
    __declspec(dllimport) int __stdcall MultiByteToWideChar(unsigned int cp, unsigned long flags, const char* str, int len, wchar_t* wstr, int wlen);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned int cp, unsigned long flags, const wchar_t* wstr, int wlen, char* str, int len, const char* def, int* used);
    __declspec(dllimport) int __stdcall GetModuleFileNameW(void* hMod, wchar_t* path, unsigned long size);
    __declspec(dllimport) void* __stdcall GetModuleHandleW(const wchar_t* name);
    __declspec(dllimport) unsigned int __stdcall GetSystemDirectoryW(wchar_t* path, unsigned int size);
}

static std::filesystem::path safeNarrowToPath(const std::string& s) {
    int wlen = MultiByteToWideChar(0 /*CP_ACP*/, 0, s.c_str(), -1, nullptr, 0);
    if (wlen > 0) {
        std::wstring ws(static_cast<size_t>(wlen), L'\0');
        if (MultiByteToWideChar(0, 0, s.c_str(), -1, ws.data(), wlen) == 0) {
            return std::filesystem::path(s);
        }
        ws.resize(static_cast<size_t>(wlen - 1));
        return std::filesystem::path(ws);
    }
    return std::filesystem::path(s);
}
#else
static std::filesystem::path safeNarrowToPath(const std::string& s) {
    return std::filesystem::path(s);
}
#endif

#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic = 0x5A4D;
    uint16_t e_cblp = 0x90;
    uint16_t e_cp = 3;
    uint16_t e_crlc = 0;
    uint16_t e_cparhdr = 4;
    uint16_t e_minalloc = 0;
    uint16_t e_maxalloc = 0xFFFF;
    uint16_t e_ss = 0;
    uint16_t e_sp = 0xB8;
    uint16_t e_csum = 0;
    uint16_t e_ip = 0;
    uint16_t e_cs = 0;
    uint16_t e_lfarlc = 0x40;
    uint16_t e_ovno = 0;
    uint16_t e_res[4] = {0};
    uint16_t e_oemid = 0;
    uint16_t e_oeminfo = 0;
    uint16_t e_res2[10] = {0};
    uint32_t e_lfanew = 0x80;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine = 0x8664;
    uint16_t NumberOfSections = 3;
    uint32_t TimeDateStamp = 0;
    uint32_t PointerToSymbolTable = 0;
    uint32_t NumberOfSymbols = 0;
    uint16_t SizeOfOptionalHeader = 240;
    uint16_t Characteristics = 0x0023;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic = 0x020B;
    uint8_t MajorLinkerVersion = 0;
    uint8_t MinorLinkerVersion = 0;
    uint32_t SizeOfCode = 0;
    uint32_t SizeOfInitializedData = 0;
    uint32_t SizeOfUninitializedData = 0;
    uint32_t AddressOfEntryPoint = 0;
    uint32_t BaseOfCode = 0x1000;
    uint64_t ImageBase = 0x140000000;
    uint32_t SectionAlignment = 0x1000;
    uint32_t FileAlignment = 0x200;
    uint16_t MajorOperatingSystemVersion = 6;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion = 0;
    uint16_t MinorImageVersion = 0;
    uint16_t MajorSubsystemVersion = 6;
    uint16_t MinorSubsystemVersion = 0;
    uint32_t Win32VersionValue = 0;
    uint32_t SizeOfImage = 0x4000;
    uint32_t SizeOfHeaders = 0x200;
    uint32_t CheckSum = 0;
    uint16_t Subsystem = 0;
    uint16_t DllCharacteristics = 0x0160;
    uint64_t SizeOfStackReserve = 0x100000;
    uint64_t SizeOfStackCommit = 0x1000;
    uint64_t SizeOfHeapReserve = 0x100000;
    uint64_t SizeOfHeapCommit = 0x1000;
    uint32_t LoaderFlags = 0;
    uint32_t NumberOfRvaAndSizes = 16;
    IMAGE_DATA_DIRECTORY DataDirectory[16] = {};
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic = 0x010B;
    uint8_t MajorLinkerVersion = 0;
    uint8_t MinorLinkerVersion = 0;
    uint32_t SizeOfCode = 0;
    uint32_t SizeOfInitializedData = 0;
    uint32_t SizeOfUninitializedData = 0;
    uint32_t AddressOfEntryPoint = 0;
    uint32_t BaseOfCode = 0x1000;
    uint32_t BaseOfData = 0;
    uint32_t ImageBase = 0x00400000;
    uint32_t SectionAlignment = 0x1000;
    uint32_t FileAlignment = 0x200;
    uint16_t MajorOperatingSystemVersion = 6;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion = 0;
    uint16_t MinorImageVersion = 0;
    uint16_t MajorSubsystemVersion = 6;
    uint16_t MinorSubsystemVersion = 0;
    uint32_t Win32VersionValue = 0;
    uint32_t SizeOfImage = 0x4000;
    uint32_t SizeOfHeaders = 0x200;
    uint32_t CheckSum = 0;
    uint16_t Subsystem = 0;
    uint16_t DllCharacteristics = 0x0160;
    uint32_t SizeOfStackReserve = 0x100000;
    uint32_t SizeOfStackCommit = 0x1000;
    uint32_t SizeOfHeapReserve = 0x100000;
    uint32_t SizeOfHeapCommit = 0x1000;
    uint32_t LoaderFlags = 0;
    uint32_t NumberOfRvaAndSizes = 16;
    IMAGE_DATA_DIRECTORY DataDirectory[16] = {};
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations = 0;
    uint32_t PointerToLinenumbers = 0;
    uint16_t NumberOfRelocations = 0;
    uint16_t NumberOfLinenumbers = 0;
    uint32_t Characteristics;
};

#pragma pack(pop)

// ============== String Collection ==============

void Codegen::collectExprStrings(Expr* expr) {
    if (auto str = dynamic_cast<StringExpr*>(expr)) {
        for (auto& s : stringPool) {
            if (s == str->value) return;
        }
        stringPool.push_back(str->value);
    } else if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        collectExprStrings(bin->left.get());
        collectExprStrings(bin->right.get());
    } else if (auto call = dynamic_cast<CallExpr*>(expr)) {
        for (auto& arg : call->args) collectExprStrings(arg.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        collectExprStrings(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        collectExprStrings(arr->array.get());
        collectExprStrings(arr->index.get());
    }
}

void Codegen::collectStmtStrings(Stmt* stmt) {
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        if (ret->value) collectExprStrings(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        collectExprStrings(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        collectExprStrings(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        if (varDecl->init) collectExprStrings(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        collectExprStrings(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) collectStmtStrings(s.get());
        for (auto& s : ifs->elseBlock.stmts) collectStmtStrings(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        collectExprStrings(wh->condition.get());
        for (auto& s : wh->body.stmts) collectStmtStrings(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) collectStmtStrings(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        collectExprStrings(sw->condition.get());
        for (auto& sc : sw->cases) {
            collectExprStrings(sc.condition.get());
            for (auto& s : sc.body.stmts) collectStmtStrings(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        collectExprStrings(fs->start.get());
        collectExprStrings(fs->end.get());
        if (fs->step) collectExprStrings(fs->step.get());
        for (auto& s : fs->body.stmts) collectStmtStrings(s.get());
    }
}

// ============== Network Usage Detection ==============
// Scans the AST for http_get/http_last_error/http_download* calls so the
// wininet.dll imports, the .data state slots and the .bss response buffer are
// only added when the network builtins are actually used (buildImportData runs
// before codegen emits the builtin bodies, so this must be detected up front).

void Codegen::detectNetworkExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name == "http_get" || call->name == "http_last_error" ||
            call->name == "http_json" || call->name == "http_download" ||
            call->name == "http_download_ask" || call->name == "http_download_speed") {
            httpGetUsed = true;
        }
        for (auto& arg : call->args) detectNetworkExprUsage(arg.get());
    } else if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectNetworkExprUsage(bin->left.get());
        detectNetworkExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectNetworkExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectNetworkExprUsage(arr->array.get());
        detectNetworkExprUsage(arr->index.get());
    }
}

void Codegen::detectNetworkStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectNetworkExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectNetworkExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectNetworkExprUsage(assign->indexExpr.get());
        detectNetworkExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectNetworkExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectNetworkExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectNetworkStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectNetworkStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectNetworkExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectNetworkStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectNetworkStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectNetworkExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectNetworkExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectNetworkStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectNetworkExprUsage(fs->start.get());
        detectNetworkExprUsage(fs->end.get());
        if (fs->step) detectNetworkExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectNetworkStmtUsage(s.get());
    }
}

void Codegen::detectNetworkUsage() {
    httpGetUsed = false;
    for (auto& func : prog.functions) {
        if (!func->isExtern) {
            for (auto& stmt : func->body.stmts) detectNetworkStmtUsage(stmt.get());
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectNetworkExprUsage(g->init.get());
    }
}

void Codegen::collectStrings() {
    for (auto& func : prog.functions) {
        if (!func->isExtern) {
            for (auto& stmt : func->body.stmts) collectStmtStrings(stmt.get());
        }
    }

    // Strings used in global variable initializers
    for (auto& g : prog.globals) {
        if (g->init) collectExprStrings(g->init.get());
    }

    // Pre-add DX11 IID bytes to stringPool so they have valid stringOffsets
    if (prog.renderType == RenderType::DX11) {
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        bool found = false;
        for (auto& s : stringPool) { if (s == iidBytes) { found = true; break; } }
        if (!found) stringPool.push_back(iidBytes);

        // Shader builtins add strings to stringPool at codegen time (after
        // stringOffsets is built). Pre-add them here so stringOffsets stay valid.
        static const char* dxShaderStrings[] = { "main", "vs_5_0", "ps_5_0", "POSITION" };
        for (const char* s : dxShaderStrings) {
            bool strFound = false;
            for (auto& p : stringPool) { if (p == s) { strFound = true; break; } }
            if (!strFound) stringPool.push_back(s);
        }

        // Diagnostic builtins (dxProbeGPU/dxDumpState/dxClearGPU) add their
        // file-path strings and IID bytes to stringPool at codegen time, which
        // is AFTER stringOffsets is built. Pre-add them here so the
        // stringOffsets indices stay valid (otherwise the emitted lea targets
        // garbage and the file writes silently never happen).
        //
        // The names come from Codegen::kDxDiagFiles — the same array the
        // emitters in codegen_dx11_shaders.cpp build their paths from — so
        // the two lists cannot drift apart when a diagnostic file is added.
        for (int i = 0; i < kDxDiagFileCount; i++) {
            std::string ds = dxDiagPath(kDxDiagFiles[i]);
            bool strFound = false;
            for (auto& p : stringPool) { if (p == ds) { strFound = true; break; } }
            if (!strFound) stringPool.push_back(ds);
        }
        }
}

// ============== Fixup Resolution ==============

// Two records for the same codePos = one disp32 field patched twice, last writer
// wins, and which one that is depends on the order the lists happen to be walked.
// The symptom is a program that runs partway and then quietly stops (exit code
// 0, no compile error) because the surviving displacement points somewhere else.
// Every list that writes into `code` takes part, and a collision fails the build
// with both list names so the emitter that produced it can be found.
void Codegen::checkFixupOverlaps(const char* builder) const {
    struct Site { size_t codePos; const char* list; };
    std::vector<Site> sites;
    auto add = [&](const char* name, auto& v) {
        for (auto& f : v) sites.push_back({f.codePos, name});
    };
    add("call", callFixups);
    add("funcRef", funcRefFixups);
    add("jmp", jmpFixups);
    add("str", strFixups);
    add("importCall", importCallFixups);
    add("heap", heapFixups);
    add("global", globalFixups);
    add("net", netFixups);
    add("sock", sockFixups);
    add("tls", tlsFixups);
    add("js", jsFixups);
    add("sound", soundFixups);
    add("elfImport", elfImportFixups);
    add("efiStr", efiStrFixups);

    std::sort(sites.begin(), sites.end(),
              [](const Site& a, const Site& b) { return a.codePos < b.codePos; });

    size_t bad = 0;
    for (size_t i = 1; i < sites.size(); i++) {
        if (sites[i].codePos != sites[i - 1].codePos) continue;
        if (bad == 0) {
            std::cerr << "Error: overlapping fixups in " << builder << " at code offset 0x"
                      << std::hex << sites[i].codePos << std::dec << " ("
                      << sites[i - 1].list << " and " << sites[i].list;
            for (size_t j = i + 1; j < sites.size() && sites[j].codePos == sites[i].codePos; j++)
                std::cerr << ", " << sites[j].list;
            std::cerr << ")\n";
        }
        bad++;
    }
    if (bad > 0) {
        std::cerr << "Error: " << bad << " fixup collision(s); the affected disp32 fields "
                     "would be written more than once\n";
        throw std::runtime_error("overlapping fixups");
    }
}

void Codegen::resolveFixups() {
    // An unresolved target used to print an error, `continue`, and leave the
    // displacement at 0 — so the call jumped to wherever happened to be at that
    // offset and the binary segfaulted, while the compiler still exited 0 and
    // wrote the file. A target can legitimately be absent only if it is an
    // import, and those are declared with `extern func` and routed through
    // importCallFixups / elfImportFixups instead of this list. Anything left
    // here is a call to a function that does not exist, so fail the build.
    // Names are collected and reported together rather than one per pass.
    std::vector<std::string> unresolvedCalls, unresolvedRefs;
    for (auto& f : callFixups) {
        auto it = funcOffsets.find(f.target);
        if (it == funcOffsets.end()) {
            unresolvedCalls.push_back(f.target);
            continue;
        }
        int64_t rel = (int64_t)it->second - (int64_t)(f.codePos + 4);
        code[f.codePos]     = (uint8_t)(rel & 0xFF);
        code[f.codePos + 1] = (uint8_t)((rel >> 8) & 0xFF);
        code[f.codePos + 2] = (uint8_t)((rel >> 16) & 0xFF);
        code[f.codePos + 3] = (uint8_t)((rel >> 24) & 0xFF);
    }
    for (auto& f : funcRefFixups) {
        auto it = funcOffsets.find(f.target);
        if (it == funcOffsets.end()) {
            unresolvedRefs.push_back(f.target);
            continue;
        }
        int64_t rel = (int64_t)it->second - (int64_t)(f.codePos + 4);
        code[f.codePos]     = (uint8_t)(rel & 0xFF);
        code[f.codePos + 1] = (uint8_t)((rel >> 8) & 0xFF);
        code[f.codePos + 2] = (uint8_t)((rel >> 16) & 0xFF);
        code[f.codePos + 3] = (uint8_t)((rel >> 24) & 0xFF);
    }
    if (unresolvedCalls.empty() && unresolvedRefs.empty()) return;
    auto quote = [](const std::vector<std::string>& v) {
        std::string s;
        for (size_t i = 0; i < v.size(); i++) {
            if (i) s += ", ";
            s += "'" + v[i] + "'";
        }
        return s;
    };
    std::string msg = "call to undefined function";
    if (!unresolvedCalls.empty()) msg += ": " + quote(unresolvedCalls);
    if (!unresolvedRefs.empty()) {
        msg += unresolvedCalls.empty() ? "reference" : "; undefined function reference";
        msg += ": " + quote(unresolvedRefs);
    }
    throw std::runtime_error(msg);
}

void Codegen::resolveJmpFixups() {
    for (auto& f : jmpFixups) {
        int target = (f.targetPos < (int)labelPositions.size()) ? labelPositions[f.targetPos] : -1;
        if (target < 0) continue;
        int64_t rel = (int64_t)target - (int64_t)(f.codePos + 4);
        code[f.codePos]     = (uint8_t)(rel & 0xFF);
        code[f.codePos + 1] = (uint8_t)((rel >> 8) & 0xFF);
        code[f.codePos + 2] = (uint8_t)((rel >> 16) & 0xFF);
        code[f.codePos + 3] = (uint8_t)((rel >> 24) & 0xFF);
    }
}

// ============== Section RVA Computation ==============

void Codegen::computeSectionRVAs() {
    rdataRVA = textRVA + 0x1000;
    dataRVA = rdataRVA + 0x1000;
}

uint32_t Codegen::estimateRdataSize() {
    uint32_t total = 0;

    bool isEfi = (prog.appType == AppType::EFI);

    // Import descriptors (skip for EFI)
    if (!isEfi) {
        uint32_t dllCount = 0;
        std::unordered_map<std::string, std::vector<std::string>> dllFuncMap;
        dllFuncMap["kernel32.dll"] = {"ExitProcess", "GetStdHandle", "WriteFile", "GetModuleHandleA", "Sleep", "GetTickCount", "Beep", "ReadFile", "CreateFileA", "CloseHandle", "GetProcessHeap", "HeapAlloc", "HeapFree", "GetFileSizeEx", "CreateProcessA", "FindFirstFileA", "FindNextFileA", "FindClose", "SetCurrentDirectoryA"};
        if (prog.appType == AppType::GUI) {
            dllFuncMap["kernel32.dll"].push_back("AddVectoredExceptionHandler");
            dllFuncMap["user32.dll"] = {"CreateWindowExA", "DefWindowProcA", "RegisterClassExA",
                "DestroyWindow", "GetDC", "ReleaseDC", "PeekMessageA", "TranslateMessage",
                "DispatchMessageA", "GetAsyncKeyState", "PostQuitMessage", "BeginPaint",
                "EndPaint", "GetMessageA", "LoadCursorA", "GetCursorPos", "ScreenToClient"};
            if (prog.renderType == RenderType::DX11) {
                dllFuncMap["d3d11.dll"] = {"D3D11CreateDeviceAndSwapChain", "D3D11CreateDevice"};
            } else if (prog.renderType != RenderType::Vulkan) {
                dllFuncMap["gdi32.dll"] = {"CreateDIBSection", "BitBlt", "SelectObject",
                    "DeleteObject", "DeleteDC", "CreateCompatibleDC"};
            }
        }

        for (auto& func : prog.functions) {
            if (func->isExtern) {
                auto mapFuncToDll = [](const std::string& fn) -> std::string {
                    if (fn == "ExitProcess" || fn == "GetStdHandle" || fn == "WriteFile" ||
                        fn == "ReadFile" || fn == "HeapAlloc" || fn == "HeapFree" ||
                        fn == "GetProcessHeap" || fn == "GetModuleHandleA" ||
                        fn == "Sleep") return "kernel32.dll";
                    if (fn.find("CreateWindowEx") == 0 || fn.find("DefWindowProc") == 0 ||
                        fn.find("RegisterClass") == 0 || fn.find("DestroyWindow") == 0 ||
                        fn.find("GetDC") == 0 || fn.find("PeekMessageA") == 0 ||
                        fn.find("TranslateMessage") == 0 || fn.find("DispatchMessageA") == 0 ||
                        fn.find("GetAsyncKeyState") == 0 || fn.find("PostQuitMessage") == 0 ||
                        fn.find("LoadCursorA") == 0) return "user32.dll";
                    if (fn.find("CreateDIBSection") == 0 || fn.find("BitBlt") == 0 ||
                        fn.find("SelectObject") == 0 || fn.find("DeleteObject") == 0 ||
                        fn.find("CreateCompatibleDC") == 0) return "gdi32.dll";
                    return "kernel32.dll";
                };
                std::string dll = func->dllName.empty() ? mapFuncToDll(func->name) : func->dllName;
                dllFuncMap[dll].push_back(func->name);
            }
        }

        // Descriptor size
        dllCount = (uint32_t)dllFuncMap.size();
        total += (dllCount + 1) * 20;

        // DLL names
        for (auto& [dll, _] : dllFuncMap)
            total += (uint32_t)dll.size() + 1;
        total = (total + 3) & ~3;

        // Hint/name entries
        for (auto& [_, funcs] : dllFuncMap) {
            for (auto& fn : funcs)
                total += (uint32_t)(2 + fn.size() + 1);
        }
        total = (total + 7) & ~7;
    }

    // String pool
    for (auto& s : stringPool)
        total += (uint32_t)s.size() + 1;
    total = (total + 15) & ~15;

    // Class name
    if (prog.appType == AppType::GUI) {
        total += 10; // "ZenithWnd\0"
        total = (total + 15) & ~15;
        total += 95 * 7; // 5x7 font blob
        total = (total + 15) & ~15;
    }

    // Embedded DLL strings (approximate: DLL paths + function names)
    for (auto& imp : prog.imports) {
        if (imp.dllName == "libs.dll" && !imp.module.empty()) {
            total += 64; // approximate per embedded DLL (path + func names)
        }
    }

    // Embedded DLL strings from extern func declarations (non-system DLLs)
    for (auto& func : prog.functions) {
        if (func->isExtern && !func->dllName.empty()) {
            std::string dll = func->dllName;
            if (dll != "kernel32.dll" && dll != "user32.dll" && dll != "gdi32.dll" && dll != "ntdll.dll") {
                total += 64; // approximate per embedded DLL
            }
        }
    }

    // Embedded DLL blob sizes (each DLL binary + pointer slots for functions)
    for (auto& imp : prog.imports) {
        if (imp.dllName == "libs.dll") {
            total += 256; // approximate for embedded DLL data slots
        }
    }

    return total;
}

uint32_t Codegen::estimateDataSize() {
    if (prog.appType == AppType::EFI) {
        return 0x100; // Minimal data section for EFI
    }
    // ILT + IAT for each DLL, globals, heap offset
    uint32_t total = 0x400; // IAT/ILT entries
    total += 8;  // heap offset
    // heap area is in .bss (no .data space needed)
    if (prog.appType == AppType::GUI) {
        total += (prog.renderType == RenderType::DX11) ? 128 : 64; // win32 globals
    }
    return total + 0x2000; // safety margin
}

void Codegen::fixupSectionRVAs() {
    uint32_t textSize = (uint32_t)code.size();
    uint32_t rdataSize = (uint32_t)rdata.size();
    uint32_t dataSize = (uint32_t)data.size();

    uint32_t alignedText = (textSize + 0xFFF) & ~0xFFF;
    uint32_t alignedRdata = (rdataSize + 0xFFF) & ~0xFFF;

    uint32_t newRdataRVA = textRVA + alignedText;
    uint32_t newDataRVA = newRdataRVA + alignedRdata;

    int32_t dRdata = (int32_t)(newRdataRVA - rdataRVA);
    int32_t dData = (int32_t)(newDataRVA - dataRVA);

    if (dRdata == 0 && dData == 0) return;

    // Helper lambdas for reading/writing DWORDS/QWORDS in byte vectors
    auto rdDW = [](const std::vector<uint8_t>& buf, size_t off) -> uint32_t {
        return (uint32_t)buf[off] | ((uint32_t)buf[off+1] << 8) | ((uint32_t)buf[off+2] << 16) | ((uint32_t)buf[off+3] << 24);
    };
    auto wrDW = [](std::vector<uint8_t>& buf, size_t off, uint32_t val) {
        buf[off] = val & 0xFF; buf[off+1] = (val >> 8) & 0xFF;
        buf[off+2] = (val >> 16) & 0xFF; buf[off+3] = (val >> 24) & 0xFF;
    };
    auto rdDQ = [](const std::vector<uint8_t>& buf, size_t off) -> uint64_t {
        return (uint64_t)buf[off] | ((uint64_t)buf[off+1] << 8) | ((uint64_t)buf[off+2] << 16) |
               ((uint64_t)buf[off+3] << 24) | ((uint64_t)buf[off+4] << 32) |
               ((uint64_t)buf[off+5] << 40) | ((uint64_t)buf[off+6] << 48) | ((uint64_t)buf[off+7] << 56);
    };
    auto wrDQ = [](std::vector<uint8_t>& buf, size_t off, uint64_t val) {
        buf[off] = val & 0xFF; buf[off+1] = (val >> 8) & 0xFF;
        buf[off+2] = (val >> 16) & 0xFF; buf[off+3] = (val >> 24) & 0xFF;
        buf[off+4] = (val >> 32) & 0xFF; buf[off+5] = (val >> 40) & 0xFF;
        buf[off+6] = (val >> 48) & 0xFF; buf[off+7] = (val >> 56) & 0xFF;
    };

    uint32_t oldRdataRVA = newRdataRVA - dRdata;
    uint32_t oldDataRVA = newDataRVA - dData;

    // 1. Fix import descriptors in .rdata
    // Each descriptor: [ILT RVA(4)][timestamp(4)][fwd(4)][Name RVA(4)][IAT RVA(4)]
    if (prog.appType != AppType::EFI && prog.appType != AppType::Bare) {
        for (uint32_t i = 0; i < importDescCount; i++) {
            size_t base = i * 20;
            uint32_t ilt = rdDW(rdata, base);
            wrDW(rdata, base, ilt + dData);
            uint32_t name = rdDW(rdata, base + 12);
            wrDW(rdata, base + 12, name + dRdata);
            uint32_t iat = rdDW(rdata, base + 16);
            wrDW(rdata, base + 16, iat + dData);
        }

        // 3. Fix ILT/IAT entries in .data (8-byte RVAs to hint/name entries in .rdata)
        for (uint32_t i = 0; i < importDataSize; i += 8) {
            uint64_t val = rdDQ(data, i);
            if (val != 0) {
                wrDQ(data, i, val + dRdata);
            }
        }

        // 3. Fix externFuncMap IAT entries
        for (auto& [name, pair] : externFuncMap) {
            if (pair.second != 0) {
                pair.second += dData;
            }
        }
    }

    // 4. Fix heap fixups target RVAs
    // Heap fixups always target .data slots (heap state, win32 globals) or .bss,
    // never .rdata strings. Their provisional RVAs sit in the .data tail, which
    // numerically overlaps the old .rdata byte range, so the oldDataRVA check
    // MUST come first — otherwise they get shifted by dRdata and land in .rdata.
    for (auto& hf : heapFixups) {
        if (hf.targetRVA >= oldDataRVA && hf.targetRVA <= oldDataRVA + dataSize) {
            hf.targetRVA += dData;
        } else if (hf.targetRVA >= oldRdataRVA && hf.targetRVA < oldRdataRVA + rdataSize) {
            hf.targetRVA += dRdata;
        }
    }

    // 4b. Fix user global fixups target RVAs (globals live in .data; builtin
    // string/blob references like the Wayland backend's wlXdgRVA live in .rdata)
    for (auto& gf : globalFixups) {
        if (gf.targetRVA >= oldRdataRVA && gf.targetRVA < oldRdataRVA + rdataSize) {
            gf.targetRVA += dRdata;
        } else if (gf.targetRVA >= oldDataRVA && gf.targetRVA <= oldDataRVA + dataSize) {
            gf.targetRVA += dData;
        }
    }
    if (globalsSize > 0) {
        globalsRVA += dData;
    }

    // 5. Fix scalar RVAs
    stringRVA += dRdata;
    if (prog.appType == AppType::GUI) {
        classNameRVA += dRdata;
        fontRVA += dRdata;
    }
    if (prog.appType == AppType::EFI) {
        fontCyrRVA += dRdata;
    }
    heapOffsetRVA += dData;
    heapFreeHeadRVA += dData;
    heapAreaRVA += dData;
    randSeedRVA += dData;
    netStatusRVA += dData;
    netStatusLenRVA += dData;
    netBytesReadRVA += dData;
    netLenRVA += dData;
    netErrRVA += dData;
    netHdrLenRVA += dData;
    sockWsaStartedRVA += dData;
    sockWsadataRVA += dData;
    sockPeerRVA += dData;
    sockPeerLenRVA += dData;
    soundOpenedRVA += dData;
    soundHwoRVA += dData;
    soundFmtRVA += dData;
    soundBpfRVA += dData;
    soundHdrRVA += dData;
    soundSeedRVA += dData;
    soundLutRVA += dData;
    if (prog.appType == AppType::GUI || prog.appType == AppType::EFI) {
        win32GlobalsRVA += dData;
    }

    // 5b. Fix embedded DLL RVAs
    embeddedFullPathRVA += dData;
    embeddedHFileRVA += dData;
    embeddedHModuleRVA += dData;
    embeddedWrittenRVA += dData;
    for (auto& emb : embeddedDLLs) {
        emb.blobRVA += dData;
        emb.dllPathStrRVA += dRdata;
        for (auto& fRVA : emb.funcNameRVAs) fRVA += dRdata;
        for (auto& pRVA : emb.funcPtrRVAs) pRVA += dData;
    }

    // 5c. Fix embedded loader lea/mov RIP-relative displacements in emitted code
    // These were computed at emit time using old (unadjusted) RVAs.
    // Since .text doesn't move, each displacement needs +dRdata or +dData.
    for (auto& elf : embeddedLEAFixups) {
        int32_t oldDisp = (int32_t)rdDW(code, elf.codePos);
        int32_t adjustment = elf.isRdata ? (int32_t)dRdata : (int32_t)dData;
        int32_t newDisp = oldDisp + adjustment;
        wrDW(code, elf.codePos, (uint32_t)newDisp);
    }

    // 6. Update section RVAs
    rdataRVA = newRdataRVA;
    dataRVA = newDataRVA;
}

// ============== DLL Export Parsing (static) ==============

static std::vector<std::string> parseDllExports(const std::vector<uint8_t>& bytes) {
    std::vector<std::string> result;
    if (bytes.size() < 64) return result;
    if (bytes[0] != 'M' || bytes[1] != 'Z') return result;

    uint32_t peOff;
    memcpy(&peOff, &bytes[0x3C], sizeof(peOff));
    if (static_cast<size_t>(peOff) + 24 >= bytes.size()) return result;
    if (bytes[peOff] != 'P' || bytes[peOff+1] != 'E') return result;

    uint16_t numSections = *(uint16_t*)&bytes[peOff + 6];
    uint16_t optHdrSize = *(uint16_t*)&bytes[peOff + 20];
    uint32_t optStart = peOff + 24;

    uint32_t exportRVA = 0, exportSize = 0;
    (void)exportSize;
    // DataDirectory[0] (export) starts at +0x60 in a PE32 optional header and
    // at +0x70 in PE32+. The old fixed read of +0x70 returned 0 for every
    // PE32 DLL (that slot is Base Relocation there), so auto-import only ever
    // worked for 64-bit embedded DLLs. Verified against real i686/x86_64
    // mingw DLLs: PE32 export = (28672, 62) at +0x60, PE32+ = (32768, 62) at +0x70.
    uint16_t optMagic = 0;
    if (optStart + 2 <= bytes.size()) optMagic = *(uint16_t*)&bytes[optStart];
    const size_t ddOff = (optMagic == 0x20B) ? 112 : 96;
    if (optStart + ddOff + 8 <= bytes.size()) {
        exportRVA = *(uint32_t*)&bytes[optStart + ddOff];
        exportSize = *(uint32_t*)&bytes[optStart + ddOff + 4];
    }
    if (exportRVA == 0) return result;

    // Parse sections to find rva->offset mapping
    uint32_t secStart = optStart + optHdrSize;
    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        for (uint32_t i = 0; i < numSections; i++) {
            uint32_t s = secStart + i * 40;
            if (s + 40 > bytes.size()) break;
            uint32_t va = *(uint32_t*)&bytes[s + 12];
            uint32_t vs = *(uint32_t*)&bytes[s + 8];
            uint32_t ro = *(uint32_t*)&bytes[s + 20];
            if (rva >= va && rva < va + vs) return ro + (rva - va);
        }
        return 0;
    };

    uint32_t dirOff = rvaToOff(exportRVA);
    if (dirOff == 0 || dirOff + 40 > bytes.size()) return result;

    uint32_t numFuncs = *(uint32_t*)&bytes[dirOff + 20];
    uint32_t numNames = *(uint32_t*)&bytes[dirOff + 24];
    uint32_t addrFuncs = *(uint32_t*)&bytes[dirOff + 28];
    uint32_t addrNames = *(uint32_t*)&bytes[dirOff + 32];
    uint32_t addrOrds = *(uint32_t*)&bytes[dirOff + 36];

    uint32_t funcTableOff = rvaToOff(addrFuncs);
    uint32_t nameTableOff = rvaToOff(addrNames);
    uint32_t ordTableOff = rvaToOff(addrOrds);

    if (numNames == 0 || funcTableOff == 0 || nameTableOff == 0) return result;

    // Collect all function RVAs to detect by-ordinal-only exports
    std::set<uint32_t> namedFuncRVAs;

    for (uint32_t i = 0; i < numNames && i < 256; i++) {
        uint32_t namePtrRVA = *(uint32_t*)&bytes[nameTableOff + i * 4];
        uint16_t ord = *(uint16_t*)&bytes[ordTableOff + i * 2];
        uint32_t nameOff2 = rvaToOff(namePtrRVA);
        if (nameOff2 == 0 || nameOff2 >= bytes.size()) continue;

        // Read null-terminated name
        std::string fname;
        for (uint32_t j = 0; j < 256 && nameOff2 + j < bytes.size(); j++) {
            char c = (char)bytes[nameOff2 + j];
            if (c == '\0') break;
            fname += c;
        }
        if (!fname.empty() && ord < numFuncs) {
            result.push_back(fname);
            uint32_t funcRVA = *(uint32_t*)&bytes[funcTableOff + ord * 4];
            namedFuncRVAs.insert(funcRVA);
        }
    }

    return result;
}

// ============== Embedded Library Loading ==============

void Codegen::readEmbeddedLibs() {
#ifndef _WIN32
    // Embedded DLL loading (parse libs.dll container + scan Windows\System32)
    // is a PE-only feature. On POSIX there are no DLLs to embed.
    (void)embeddedDLLs;
    return;
#else
    // Check if any DLL needs embedding — either @import or extern func from
    bool hasEmbeddedImports = false;
    std::set<std::string> neededDLLs;

    // From @import directives
    for (auto& imp : prog.imports) {
        if (imp.dllName == "libs.dll" && !imp.module.empty()) {
            neededDLLs.insert("libs_" + imp.module + ".dll");
            hasEmbeddedImports = true;
        } else if (imp.dllName == "libs.dll" && imp.module.empty()) {
            neededDLLs.insert("libs_thread.dll");
            neededDLLs.insert("libs_mutex.dll");
            neededDLLs.insert("libs_async.dll");
            neededDLLs.insert("libs_threadpool.dll");
            neededDLLs.insert("libs_network.dll");
            hasEmbeddedImports = true;
        }
    }

    // From extern func from "xxx.dll" — collect non-system DLLs (or all if embedDLLs)
    for (auto& func : prog.functions) {
        if (func->isExtern && !func->dllName.empty()) {
            std::string dll = func->dllName;
            if (embedDLLs || (dll != "kernel32.dll" && dll != "user32.dll" && dll != "gdi32.dll" && dll != "ntdll.dll")) {
                neededDLLs.insert(dll);
                hasEmbeddedImports = true;
            }
        }
    }

    // Expand transitive dependencies: libs_async.dll and libs_threadpool.dll
    // import libs_thread.dll + libs_mutex.dll (same mapping as buildImportData)
    if (neededDLLs.count("libs_async.dll")) {
        neededDLLs.insert("libs_thread.dll");
        neededDLLs.insert("libs_mutex.dll");
    }
    if (neededDLLs.count("libs_threadpool.dll")) {
        neededDLLs.insert("libs_thread.dll");
        neededDLLs.insert("libs_mutex.dll");
    }

    if (!hasEmbeddedImports) return;

    std::set<std::string> foundDLLs;

    // === Phase 1: Try to read from libs.dll container ===
    std::filesystem::path libsPath;
    if (!compilerDir.empty()) {
        libsPath = compilerDir / "libs" / "libs.dll";
    }
    if (!std::filesystem::exists(libsPath) && !compilerDir.empty()) {
        libsPath = compilerDir / "libs.dll";
    }
    if (!std::filesystem::exists(libsPath) && !compilerDir.empty()) {
        libsPath = compilerDir / ".." / "libs" / "bin" / "libs.dll";
    }
    if (!std::filesystem::exists(libsPath) && !outputDir.empty()) {
        libsPath = outputDir / "libs.dll";
    }

    if (std::filesystem::exists(libsPath)) {
        std::ifstream f(std::filesystem::path(libsPath), std::ios::binary);
        if (f.is_open()) {
            char magic[8] = {};
            f.read(magic, 8);
            if (memcmp(magic, "ZLIBS", 5) == 0) {
                uint32_t count = 0;
                f.read((char*)&count, 4);

                for (uint32_t i = 0; i < count; i++) {
                    uint32_t nameLen = 0;
                    f.read((char*)&nameLen, 4);
                    if (nameLen > 256) break;
                    std::string name(nameLen, '\0');
                    f.read(&name[0], nameLen);
                    uint32_t dataLen = 0;
                    f.read((char*)&dataLen, 4);
                    if (dataLen > 10 * 1024 * 1024) break;
                    std::vector<uint8_t> data(dataLen);
                    f.read((char*)data.data(), dataLen);

                    if (neededDLLs.count(name)) {
                        EmbeddedDLL emb;
                        emb.dllName = name;
                        std::string prefix = "libs_";
                        std::string suffix = ".dll";
                        if (name.find(prefix) == 0 && name.size() > prefix.size() + suffix.size()) {
                            emb.moduleName = name.substr(prefix.size(), name.size() - prefix.size() - suffix.size());
                        }
                        emb.bytes = std::move(data);
                        emb.blobSize = dataLen;
                        embeddedDLLs.push_back(std::move(emb));
                        foundDLLs.insert(name);
                        std::cout << "Embedded: " << name << " (" << dataLen << " bytes)" << std::endl;
                    }
                }
            }
        }
    }

    // === Phase 2: For DLLs not found in container, read individual files ===
    for (auto& dll : neededDLLs) {
        if (foundDLLs.count(dll)) continue;

        std::filesystem::path dllPath;
        if (!outputDir.empty()) {
            dllPath = outputDir / dll;
        }
        if (dllPath.empty() || !std::filesystem::exists(dllPath)) {
            if (!compilerDir.empty()) {
                dllPath = compilerDir / ".." / "libs" / "bin" / dll;
            }
        }
        if (dllPath.empty() || !std::filesystem::exists(dllPath)) {
            if (!compilerDir.empty()) {
                dllPath = compilerDir / dll;
            }
        }
        if (dllPath.empty() || !std::filesystem::exists(dllPath)) {
            dllPath = std::filesystem::current_path() / dll;
        }
        if (dllPath.empty() || !std::filesystem::exists(dllPath)) {
            // Try current directory directly
            dllPath = dll;
        }
        // Try Windows\System32 for system DLLs
        if (!std::filesystem::exists(dllPath) && embedDLLs) {
            wchar_t sysDir[260] = {0};
            GetSystemDirectoryW(sysDir, 260);
            dllPath = std::filesystem::path(sysDir) / dll;
        }
        if (!std::filesystem::exists(dllPath)) continue;

        std::ifstream f(std::filesystem::path(dllPath), std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;

        std::streamsize size = f.tellg();
        if (size <= 0) continue;
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> data(size);
        f.read((char*)data.data(), size);
        if (data.empty()) continue;

        EmbeddedDLL emb;
        emb.dllName = dll;
        emb.bytes = std::move(data);
        emb.blobSize = (uint32_t)size;
        embeddedDLLs.push_back(std::move(emb));
        foundDLLs.insert(dll);
        std::cout << "Embedded: " << dll << " (" << size << " bytes)" << std::endl;
    }

    // Reorder embedded DLLs so dependencies are written+loaded before dependents.
    // libs_async.dll / libs_threadpool.dll import libs_thread.dll + libs_mutex.dll,
    // so thread/mutex must be LoadLibrary'd first (Windows resolves DLL imports
    // against already-loaded modules).
    auto depRank = [](const std::string& n) -> int {
        if (n == "libs_thread.dll" || n == "libs_mutex.dll") return 0;
        if (n == "libs_async.dll" || n == "libs_threadpool.dll") return 1;
        return 2;
    };
    std::stable_sort(embeddedDLLs.begin(), embeddedDLLs.end(),
        [&](const EmbeddedDLL& a, const EmbeddedDLL& b) {
            return depRank(a.dllName) < depRank(b.dllName);
        });
#endif
}

// ============== Import Data Builder ==============

void Codegen::printStructs() {
    // Placeholder: prints import table info for debugging
    for (auto& db : importDLLs) {
        std::cout << "Import DLL: " << db.dllName << "\n";
        for (auto& e : db.entries) {
            std::cout << "  " << e.funcName << " hint=0x" << std::hex << e.hintNameRVA
                      << " iat=0x" << e.iatRVA << std::dec << "\n";
        }
    }
}

void Codegen::buildImportData() {
    rdata.clear();
    data.clear();
    importDLLs.clear();
    externFuncMap.clear();
    // The string offsets are rebuilt from stringPool below (and again by
    // writeBareFlatImage/writeBiosFlatImage/buildPE). Without this clear a
    // second pass appends a duplicate batch and every strFixup index shifts.
    stringOffsets.clear();

    // Linux target (app linux): no PE import table. buildLinuxImportData
    // (codegen_elf.cpp) fills .rdata/.data with the string pool, win32/Linux
    // globals, heap state, and socket/sound/net/tls slots using the same RVA
    // conventions, but without any DLL import descriptors.
    if (isLinux) {
        buildLinuxImportData();
        return;
    }

    auto writeDW = [](std::vector<uint8_t>& buf, uint32_t val) {
        buf.push_back(val & 0xFF);
        buf.push_back((val >> 8) & 0xFF);
        buf.push_back((val >> 16) & 0xFF);
        buf.push_back((val >> 24) & 0xFF);
    };
    auto writeDQ = [](std::vector<uint8_t>& buf, uint64_t val) {
        buf.push_back(val & 0xFF);
        buf.push_back((val >> 8) & 0xFF);
        buf.push_back((val >> 16) & 0xFF);
        buf.push_back((val >> 24) & 0xFF);
        buf.push_back((val >> 32) & 0xFF);
        buf.push_back((val >> 40) & 0xFF);
        buf.push_back((val >> 48) & 0xFF);
        buf.push_back((val >> 56) & 0xFF);
    };

    // Collect extern functions grouped by DLL
    std::unordered_map<std::string, std::vector<std::string>> dllFuncMap;

    // Auto-map function names to DLLs
    auto mapFuncToDll = [](const std::string& funcName) -> std::string {
        if (funcName == "ExitProcess" || funcName == "GetStdHandle" ||
            funcName == "WriteFile" || funcName == "ReadFile" ||
            funcName == "HeapAlloc" || funcName == "HeapFree" ||
            funcName == "GetProcessHeap" || funcName == "GetModuleHandleA" ||
            funcName == "Sleep") {
            return "kernel32.dll";
        }
        if (funcName.find("CreateWindowExA") == 0 || funcName.find("DefWindowProcA") == 0 ||
            funcName.find("RegisterClassExA") == 0 || funcName.find("DestroyWindow") == 0 ||
            funcName.find("GetDC") == 0 || funcName.find("ReleaseDC") == 0 ||
            funcName.find("PeekMessageA") == 0 || funcName.find("TranslateMessage") == 0 ||
            funcName.find("DispatchMessageA") == 0 || funcName.find("GetAsyncKeyState") == 0 ||
            funcName.find("PostQuitMessage") == 0 || funcName.find("BeginPaint") == 0 ||
            funcName.find("EndPaint") == 0 || funcName.find("LoadCursorA") == 0 ||
            funcName.find("MessageBoxA") == 0 || funcName.find("MessageBoxW") == 0 ||
            funcName.find("MessageBox") == 0 ||
            funcName.find("CreateWindowEx") == 0 || funcName.find("DefWindowProc") == 0 ||
            funcName.find("RegisterClass") == 0) {
            return "user32.dll";
        }
        if (funcName.find("CreateDIBSection") == 0 || funcName.find("BitBlt") == 0 ||
            funcName.find("DeleteObject") == 0 || funcName.find("SelectObject") == 0 ||
            funcName.find("DeleteDC") == 0 || funcName.find("CreateCompatibleDC") == 0) {
            return "gdi32.dll";
        }

        // Libs DLL functions
        if (funcName.find("thread") == 0 || funcName.find("Thread") == 0) return "libs_thread.dll";
        if (funcName.find("mutex") == 0 || funcName.find("Mutex") == 0 ||
            funcName.find("condvar") == 0 || funcName.find("Condvar") == 0) return "libs_mutex.dll";
        if (funcName.find("future") == 0 || funcName.find("Future") == 0 ||
            funcName.find("promise") == 0 || funcName.find("Promise") == 0) return "libs_async.dll";
        if (funcName.find("pool") == 0 || funcName.find("Pool") == 0 ||
            funcName.find("PoolWorker") == 0) return "libs_threadpool.dll";
        if (funcName.find("net_") == 0 || funcName.find("tcp_") == 0 ||
            funcName.find("udp_") == 0 || funcName == "htons" ||
            funcName == "ip4" || funcName == "make_sockaddr_in") return "libs_network.dll";

        return "kernel32.dll";
    };

    // Always add kernel32 functions used by built-in features
    dllFuncMap["kernel32.dll"].push_back("ExitProcess");
    dllFuncMap["kernel32.dll"].push_back("GetStdHandle");
    dllFuncMap["kernel32.dll"].push_back("WriteFile");
    dllFuncMap["kernel32.dll"].push_back("ReadFile");
    dllFuncMap["kernel32.dll"].push_back("GetModuleHandleA");
    dllFuncMap["kernel32.dll"].push_back("Sleep");
    dllFuncMap["kernel32.dll"].push_back("GetTickCount");
    dllFuncMap["kernel32.dll"].push_back("Beep");
    dllFuncMap["kernel32.dll"].push_back("CreateFileA");
    dllFuncMap["kernel32.dll"].push_back("CloseHandle");
    dllFuncMap["kernel32.dll"].push_back("GetProcessHeap");
    dllFuncMap["kernel32.dll"].push_back("HeapAlloc");
    dllFuncMap["kernel32.dll"].push_back("HeapFree");
    dllFuncMap["kernel32.dll"].push_back("GetFileSizeEx");
    dllFuncMap["kernel32.dll"].push_back("CreateProcessA");
    dllFuncMap["kernel32.dll"].push_back("FindFirstFileA");
    dllFuncMap["kernel32.dll"].push_back("FindNextFileA");
    dllFuncMap["kernel32.dll"].push_back("FindClose");
    dllFuncMap["kernel32.dll"].push_back("SetCurrentDirectoryA");

    // Network builtins (http_get/http_last_error): wininet.dll + GetLastError.
    // Only added when the builtins are actually used.
    if (httpGetUsed) {
        dllFuncMap["kernel32.dll"].push_back("GetLastError");
        dllFuncMap["wininet.dll"] = {"InternetOpenA", "InternetOpenUrlA",
            "InternetReadFile", "InternetCloseHandle", "HttpQueryInfoA"};
    }

    // Socket builtins (net_* TCP/UDP server/client): Winsock2 (ws2_32.dll).
    if (netSocksUsed) {
        dllFuncMap["ws2_32.dll"] = {"WSAStartup", "WSAGetLastError", "socket",
            "bind", "listen", "accept", "connect", "send", "recv", "sendto",
            "recvfrom", "closesocket", "gethostbyname", "inet_ntoa", "ioctlsocket"};
    }

    // TLS builtins (tls_*): raw socket I/O on the connected socket lives inside the
    // embedded crypto blob; it needs send/recv/closesocket passed through the IAT.
    if (tlsUsed) {
        auto& ws = dllFuncMap["ws2_32.dll"];
        std::vector<const char*> need = {"send", "recv", "closesocket"};
        for (auto& f : need) {
            if (std::find(ws.begin(), ws.end(), f) == ws.end()) ws.push_back(f);
        }
    }

    // Embedded JS engine (js_* builtins): the auto-installed host-callback table
    // (fs/net/tls/print stubs in codegen_js.cpp) drives real I/O through the IAT.
    // The kernel32 fs/print imports (CreateFileA/ReadFile/WriteFile/CloseHandle/
    // GetStdHandle) are already part of the static list above; the rest is only
    // referenced by js-emitted import fixups and must be present in the table.
    if (jsUsed) {
        dllFuncMap["kernel32.dll"].push_back("GetCurrentDirectoryA");
        auto& ws = dllFuncMap["ws2_32.dll"];
        std::vector<const char*> need = {"WSAStartup", "socket", "connect",
            "send", "recv", "closesocket", "gethostbyname"};
        for (auto& f : need) {
            if (std::find(ws.begin(), ws.end(), f) == ws.end()) ws.push_back(f);
        }
    }

    // Sound builtins (sound_* PCM generation + playback): winmm.dll waveOut.
    if (soundUsed) {
        dllFuncMap["winmm.dll"] = {"waveOutOpen", "waveOutPrepareHeader",
            "waveOutWrite", "waveOutUnprepareHeader", "waveOutReset", "waveOutClose"};
    }

    // GUI apps: register Vectored Exception Handler to suppress D3D11/DXGI cleanup exceptions
    if (prog.appType == AppType::GUI) {
        dllFuncMap["kernel32.dll"].push_back("AddVectoredExceptionHandler");
    }

    // Pre-add user32.dll and gdi32.dll functions only for GUI applications
    if (prog.appType == AppType::GUI) {
        dllFuncMap["user32.dll"].push_back("CreateWindowExA");
        dllFuncMap["user32.dll"].push_back("DefWindowProcA");
        dllFuncMap["user32.dll"].push_back("RegisterClassExA");
        dllFuncMap["user32.dll"].push_back("DestroyWindow");
        dllFuncMap["user32.dll"].push_back("GetDC");
        dllFuncMap["user32.dll"].push_back("ReleaseDC");
        dllFuncMap["user32.dll"].push_back("PeekMessageA");
        dllFuncMap["user32.dll"].push_back("TranslateMessage");
        dllFuncMap["user32.dll"].push_back("DispatchMessageA");
        dllFuncMap["user32.dll"].push_back("GetAsyncKeyState");
        dllFuncMap["user32.dll"].push_back("PostQuitMessage");
        dllFuncMap["user32.dll"].push_back("BeginPaint");
        dllFuncMap["user32.dll"].push_back("EndPaint");
        dllFuncMap["user32.dll"].push_back("GetMessageA");
        dllFuncMap["user32.dll"].push_back("ShowWindow");
        dllFuncMap["user32.dll"].push_back("UpdateWindow");
        dllFuncMap["user32.dll"].push_back("LoadCursorA");
        dllFuncMap["user32.dll"].push_back("AdjustWindowRectEx");
        dllFuncMap["user32.dll"].push_back("GetCursorPos");
        dllFuncMap["user32.dll"].push_back("ScreenToClient");

        if (prog.renderType == RenderType::DX11) {
            // DX11 mode: import d3d11.dll for D3D11CreateDeviceAndSwapChain
            dllFuncMap["d3d11.dll"].push_back("D3D11CreateDeviceAndSwapChain");
            dllFuncMap["d3d11.dll"].push_back("D3D11CreateDevice");
            // Shader compilation via D3DCompile from the standalone D3D compiler DLL
            dllFuncMap["d3dcompiler_47.dll"].push_back("D3DCompile");
        } else if (prog.renderType != RenderType::Vulkan) {
            // Software mode: GDI functions
            dllFuncMap["gdi32.dll"].push_back("CreateDIBSection");
            dllFuncMap["gdi32.dll"].push_back("BitBlt");
            dllFuncMap["gdi32.dll"].push_back("SelectObject");
            dllFuncMap["gdi32.dll"].push_back("DeleteObject");
            dllFuncMap["gdi32.dll"].push_back("DeleteDC");
            dllFuncMap["gdi32.dll"].push_back("CreateCompatibleDC");
        }
    }

    // Collect from extern functions
    // First pass: determine which @import modules provide DLL targets for unknown funcs
    std::string libsImportModule;  // if we have @import("libs.dll::X"), unknown funcs go to libs_X.dll
    for (auto& imp : prog.imports) {
        if (imp.dllName == "libs.dll" && !imp.module.empty()) {
            libsImportModule = imp.module;
            break;
        }
    }

    for (auto& func : prog.functions) {
        if (func->isExtern) {
            std::string dllName;
            if (!func->dllName.empty()) {
                dllName = func->dllName;
            } else {
                dllName = mapFuncToDll(func->name);
                // If the function wasn't recognized by mapFuncToDll and we have a libs @import,
                // route it to the embedded libs DLL instead of kernel32.dll
                if (dllName == "kernel32.dll" && !libsImportModule.empty()) {
                    // Check it's not a known system function
                    static const std::set<std::string> knownFuncs = {
                        "ExitProcess", "GetStdHandle", "WriteFile", "ReadFile",
                        "HeapAlloc", "HeapFree", "GetProcessHeap", "GetModuleHandleA", "Sleep"
                    };
                    if (knownFuncs.find(func->name) == knownFuncs.end()) {
                        dllName = "libs_" + libsImportModule + ".dll";
                    }
                }
            }
            dllFuncMap[dllName].push_back(func->name);
            externFuncMap[func->name] = {dllName, 0};
        }
    }

    // Collect from @import directives
    // Module mapping: "libs.dll::thread" -> libs_thread.dll, etc.
    // "libs.dll" (no ::) -> all sub-DLLs
    for (auto& imp : prog.imports) {
        if (imp.dllName == "libs.dll" && !imp.module.empty()) {
            // Selective import: libs.dll::thread -> libs_thread.dll + deps
            std::string mod = imp.module;
            std::string resolvedDll = "libs_" + mod + ".dll";

            auto ensureDll = [&](const std::string& dll) {
                if (dllFuncMap.find(dll) == dllFuncMap.end()) {
                    dllFuncMap[dll] = {};
                }
            };

            ensureDll(resolvedDll);

            // Add dependencies
            if (mod == "async" || mod == "pool") {
                ensureDll("libs_thread.dll");
                ensureDll("libs_mutex.dll");
            }
        } else if (imp.dllName == "libs.dll" && imp.module.empty()) {
            // Full import: libs.dll -> all sub-DLLs
            auto ensureDll = [&](const std::string& dll) {
                if (dllFuncMap.find(dll) == dllFuncMap.end()) {
                    dllFuncMap[dll] = {};
                }
            };
            ensureDll("libs_thread.dll");
            ensureDll("libs_mutex.dll");
            ensureDll("libs_async.dll");
            ensureDll("libs_threadpool.dll");
            ensureDll("libs_network.dll");
        } else {
            // Direct DLL import: @import("libs_thread.dll") or any other
            if (dllFuncMap.find(imp.dllName) == dllFuncMap.end()) {
                dllFuncMap[imp.dllName] = {};
            }
        }
    }

    // Remove duplicates from each DLL's function list
    for (auto& [dll, funcs] : dllFuncMap) {
        std::sort(funcs.begin(), funcs.end());
        funcs.erase(std::unique(funcs.begin(), funcs.end()), funcs.end());
    }

    // === EMBEDDED DLL HANDLING ===
    // Read libs.dll container and extract needed sub-DLLs
    readEmbeddedLibs();

    // Map embedded DLL functions and remove from IAT list
    std::set<std::string> embeddedDLLNames;
    for (auto& emb : embeddedDLLs) {
        embeddedDLLNames.insert(emb.dllName);
        auto it = dllFuncMap.find(emb.dllName);
        if (it != dllFuncMap.end()) {
            for (auto& fn : it->second) {
                emb.funcs.push_back({fn});
            }
            dllFuncMap.erase(it);
        }
        // Auto-declare: if no extern funcs were declared for this DLL,
        // parse its PE export table and add all exported functions
        if (emb.funcs.empty() && !emb.bytes.empty()) {
            std::vector<std::string> exports = parseDllExports(emb.bytes);
            for (auto& fname : exports) {
                emb.funcs.push_back({fname});
                externFuncMap[fname] = {"EMBEDDED_" + emb.dllName, 0};
            }
            if (!exports.empty()) {
                std::cout << "Auto-imported " << exports.size() << " functions from " << emb.dllName << std::endl;
            }
        }
    }

    // If we have embedded DLLs, add kernel32 imports needed by the loader
    if (!embeddedDLLs.empty()) {
        auto addK32 = [&](const std::string& fn) {
            auto& kf = dllFuncMap["kernel32.dll"];
            if (std::find(kf.begin(), kf.end(), fn) == kf.end())
                kf.push_back(fn);
        };
        addK32("GetTempPathA");
        addK32("lstrcatA");
        addK32("CreateFileA");
        addK32("WriteFile");
        addK32("CloseHandle");
        addK32("LoadLibraryA");
        addK32("GetProcAddress");
        addK32("DeleteFileA");
    }

    struct DLLBuild {
        std::string dllName;
        std::vector<std::string> funcs;
        std::vector<uint32_t> hintNameRVAs;
        uint32_t iltRVA = 0;
        uint32_t nameRVA = 0;
        uint32_t iatRVA_val = 0;
        uint32_t descriptorRVA = 0;
        uint32_t iltDataRVA = 0;
    };
    std::vector<DLLBuild> dllBuilds;

    importDescCount = (uint32_t)dllFuncMap.size();
    uint32_t descRVA = rdataRVA;
    (void)descRVA;

    for (auto& [dll, funcs] : dllFuncMap) {
        DLLBuild db;
        db.dllName = dll;
        db.funcs = funcs;
        dllBuilds.push_back(db);
    }

    // Build .rdata into newRdata with correct layout
    std::vector<uint8_t> newRdata;

    // Compute sizes upfront
    uint32_t descSize = (uint32_t)(dllBuilds.size() + 1) * 20;
    uint32_t namesTotal = 0;
    for (auto& db : dllBuilds) namesTotal += (uint32_t)db.dllName.size() + 1;
    uint32_t namesPadded = (namesTotal + 3) & ~3;
    uint32_t hintsTotal = 0;
    std::vector<uint32_t> funcCounts;
    for (auto& db : dllBuilds) {
        funcCounts.push_back((uint32_t)db.funcs.size());
        for (auto& fn : db.funcs) hintsTotal += (uint32_t)(2 + fn.size() + 1);
    }
    uint32_t hintsPadded = (hintsTotal + 7) & ~7;
    (void)hintsPadded;

    // Compute name RVAs
    std::vector<uint32_t> nameRVAs;
    uint32_t nameOff = descSize;
    for (auto& db : dllBuilds) {
        nameRVAs.push_back(rdataRVA + nameOff);
        nameOff += (uint32_t)db.dllName.size() + 1;
    }

    // Compute hint/name RVAs
    std::vector<std::vector<uint32_t>> hintRVAs;
    uint32_t hintOff = descSize + namesPadded;
    for (size_t d = 0; d < dllBuilds.size(); d++) {
        std::vector<uint32_t> hints;
        for (auto& fn : dllBuilds[d].funcs) {
            hints.push_back(rdataRVA + hintOff);
            hintOff += (uint32_t)(2 + fn.size() + 1);
        }
        hintRVAs.push_back(hints);
    }

    // Write descriptors and .data (ILT/IAT)
    for (size_t d = 0; d < dllBuilds.size(); d++) {
        auto& db = dllBuilds[d];
        uint32_t iltDataRVA = dataRVA + (uint32_t)data.size();

        // ILT in .data (8-byte entries for PE32+)
        for (size_t i = 0; i < db.funcs.size(); i++)
            writeDQ(data, hintRVAs[d][i]);
        writeDQ(data, 0);

        // IAT in .data (8-byte entries for PE32+)
        uint32_t iatAddrRVA = dataRVA + (uint32_t)data.size();
        for (size_t i = 0; i < db.funcs.size(); i++)
            writeDQ(data, hintRVAs[d][i]);
        writeDQ(data, 0);

        uint32_t iatStartRVA = iatAddrRVA;

        writeDW(newRdata, iltDataRVA);
        writeDW(newRdata, 0);
        writeDW(newRdata, 0);
        writeDW(newRdata, nameRVAs[d]);
        writeDW(newRdata, iatAddrRVA);

        for (size_t i = 0; i < db.funcs.size(); i++)
            externFuncMap[db.funcs[i]] = {db.dllName, iatStartRVA + (uint32_t)(i * 8)};
    }

    // Zero terminator descriptor
    for (int i = 0; i < 20; i++) newRdata.push_back(0);

    // DLL names
    for (auto& db : dllBuilds) {
        for (char c : db.dllName) newRdata.push_back((uint8_t)c);
        newRdata.push_back(0);
    }
    while (newRdata.size() % 4 != 0) newRdata.push_back(0);

    // Hint/Name entries
    for (auto& db : dllBuilds) {
        for (auto& fn : db.funcs) {
            newRdata.push_back(0); newRdata.push_back(0);
            for (char c : fn) newRdata.push_back((uint8_t)c);
            newRdata.push_back(0);
        }
    }
    while (newRdata.size() % 8 != 0) newRdata.push_back(0);

    // Ensure newline string is in the pool for print()
    bool hasCRLF = false;
    for (auto& s : stringPool) if (s == "\r\n") { hasCRLF = true; break; }
    if (!hasCRLF) stringPool.push_back("\r\n");

    // Ensure pause message is in the pool for pause()
    std::string pauseMsg = "Press any key to continue . . .\r\n";
    bool hasPause = false;
    for (auto& s : stringPool) if (s == pauseMsg) { hasPause = true; break; }
    if (!hasPause) stringPool.push_back(pauseMsg);

    // Network builtins: "Zenith" user-agent string must be in the pool before
    // stringOffsets is built (http_get emits its lea during function codegen).
    if (httpGetUsed) {
        bool hasAgent = false;
        for (auto& s : stringPool) if (s == "Zenith") { hasAgent = true; break; }
        if (!hasAgent) stringPool.push_back("Zenith");
    }

    // String pool — pool-relative offsets
    uint32_t stringPoolStart = (uint32_t)newRdata.size();
    stringRVA = rdataRVA + stringPoolStart;
    for (auto& s : stringPool) {
        stringOffsets.push_back((uint32_t)newRdata.size() - stringPoolStart);
        for (char c : s) newRdata.push_back((uint8_t)c);
        newRdata.push_back(0);
    }
    while (newRdata.size() % 16 != 0) newRdata.push_back(0);

    // Class name string for window creation (GUI only)
    if (prog.appType == AppType::GUI) {
        classNameRVA = rdataRVA + (uint32_t)newRdata.size();
        const char* className = "ZenithWnd";
        for (const char* p = className; *p; p++) newRdata.push_back((uint8_t)*p);
        newRdata.push_back(0);
        while (newRdata.size() % 16 != 0) newRdata.push_back(0);
    }

    // 5x7 font blob (GUI only) — 95 glyphs * 7 rows, used by drawText()
    if (prog.appType == AppType::GUI) {
        fontRVA = rdataRVA + (uint32_t)newRdata.size();
        for (int g = 0; g < 95; g++) {
            for (int r = 0; r < 7; r++)
                newRdata.push_back(font5x7[g][r]);
        }
        while (newRdata.size() % 16 != 0) newRdata.push_back(0);
    }

    // 8x16 Cyrillic font blob (EFI only) — 162 glyphs * 16 rows, used by gop_print()
    if (prog.appType == AppType::EFI) {
        fontCyrRVA = rdataRVA + (uint32_t)newRdata.size();
        for (int g = 0; g < 162; g++) {
            for (int r = 0; r < 16; r++)
                newRdata.push_back(font8x16_cyr[g][r]);
        }
        while (newRdata.size() % 16 != 0) newRdata.push_back(0);
    }

    rdata = std::move(newRdata);

    // === EMBEDDED DLL: rdata entries (DLL path strings, function name strings) ===
    if (!embeddedDLLs.empty()) {
        for (auto& emb : embeddedDLLs) {
            // DLL path string: "\\libs_math.dll"
            emb.dllPathStrRVA = rdataRVA + (uint32_t)rdata.size();
            rdata.push_back('\\');
            for (char c : emb.dllName) rdata.push_back((uint8_t)c);
            rdata.push_back(0);
            while (rdata.size() % 4 != 0) rdata.push_back(0);

            // Function name strings
            emb.funcNameRVAs.clear();
            for (auto& fn : emb.funcs) {
                uint32_t nameRVA = rdataRVA + (uint32_t)rdata.size();
                emb.funcNameRVAs.push_back(nameRVA);
                for (char c : fn.name) rdata.push_back((uint8_t)c);
                rdata.push_back(0);
            }
            while (rdata.size() % 4 != 0) rdata.push_back(0);
        }
    }

    importDataSize = (uint32_t)data.size();

    // Win32 globals for 2D graphics built-ins (GUI only)
    if (prog.appType == AppType::GUI) {
        win32GlobalsRVA = dataRVA + (uint32_t)data.size();
        if (prog.renderType == RenderType::DX11) {
            // DX11 globals: 128 bytes
            for (int k = 0; k < 128; k++) data.push_back(0);
        } else if (prog.renderType == RenderType::Vulkan) {
            // Vulkan: 256 bytes — user defines their own vtables/objects here
            // Layout: +0 initFlag(8), +8 hwnd(8), +32 width(4), +36 height(4),
            //         +40..+255 user-managed (vtables, device ptrs, etc.)
            for (int k = 0; k < 256; k++) data.push_back(0);
        } else {
            // Software globals: 56 bytes
            for (int k = 0; k < 56; k++) data.push_back(0);
        }
    } else if (prog.appType == AppType::EFI) {
        // EFI globals: ImageHandle (8) + SystemTable (8) + GOP info.
        // ImageHandle/SystemTable are populated by the EFI entry point from the
        // EfiMain parameters; the GOP info (+24..+48) is filled in by querying
        // the EFI_GRAPHICS_OUTPUT_PROTOCOL at startup (see emitEntryPoint).
        // Layout mirrors the fixed addresses used by bare-metal loaders:
        //   +24 = FrameBufferBase (u64)   == 0x8000
        //   +32 = Pitch (u32)             == 0x8008
        //   +36 = Width (u32)             == 0x800C
        //   +40 = Height (u32)            == 0x8010
        //   +44 = BPP (u32)               == 0x8014
        //   +48 = PixelFormat (u32)       == 0x8018
        win32GlobalsRVA = dataRVA + (uint32_t)data.size();
        // 128 bytes: base layout (+0..+55) plus extension slots used by
        // independent-mode kernels booted through the EFI stub:
        //   +64 = EFI_FILE_PROTOCOL* root (SimpleFileSystem volume)
        //   +72 = EFI_SIMPLE_POINTER_PROTOCOL*
        //   +80..+95 = cached mouse state (dx i32, dy i32, buttons u32)
        //   +96 = EFI_BLOCK_IO_PROTOCOL*
        //   +104 = MediaId (u32), +108 = BlockSize (u32)
        for (int k = 0; k < 128; k++) data.push_back(0);
    }

    // === EMBEDDED DLL: .data entries ===
    if (!embeddedDLLs.empty()) {
        embeddedFullPathRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 520; k++) data.push_back(0);
        embeddedHFileRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        embeddedHModuleRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        embeddedWrittenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);

        for (auto& emb : embeddedDLLs) {
            emb.blobRVA = dataRVA + (uint32_t)data.size();
            data.insert(data.end(), emb.bytes.begin(), emb.bytes.end());
            while (data.size() % 8 != 0) data.push_back(0);

            emb.funcPtrRVAs.clear();
            for (auto& _ : emb.funcs) {
                uint32_t slotRVA = dataRVA + (uint32_t)data.size();
                emb.funcPtrRVAs.push_back(slotRVA);
                for (int k = 0; k < 8; k++) data.push_back(0);
            }
        }

        for (auto& emb : embeddedDLLs) {
            for (size_t f = 0; f < emb.funcs.size(); f++) {
                externFuncMap[emb.funcs[f].name] = {"EMBEDDED_" + emb.dllName, emb.funcPtrRVAs[f]};
            }
        }
    }

    // Heap offset (8 bytes in .data) — bump allocator state
    heapOffsetRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);
    // Heap free list head (8 bytes in .data) — 0 = no free blocks
    heapFreeHeadRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);
    // Random seed (8 bytes in .data) — LCG state for rand() (GUI game apps)
    randSeedRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);

    // Network builtin state (only when http_get/http_last_error is used).
    // netBufRVA is placed in .bss by buildPE, so its fixup is resolved there.
    if (httpGetUsed) {
        netStatusRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);   // status (4) + pad
        netStatusLenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);   // statusLen (4) + pad
        netBytesReadRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        netLenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        netErrRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        netHdrLenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);   // raw-headers len (4) + pad
    }

    // Socket builtin state (net_* TCP/UDP): Winsock lifecycle + peer address.
    if (netSocksUsed) {
        sockWsaStartedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);   // WSAStartup guard flag + pad
        sockWsadataRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 416; k++) data.push_back(0); // WSADATA (WSADescriptor)
        sockPeerRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 16; k++) data.push_back(0);  // sockaddr_in (peer / bind addr)
        sockPeerLenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);   // addrlen (recvfrom) / FIONBIO arg
    }

    // TLS builtin state (tls_*): TLS_IO_DONE guard flag so the embedded blob's
    // io-slot table (send/recv/closesocket) is seeded exactly once.
    if (tlsUsed) {
        tlsIoDoneRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
    }

    // JS builtin state (js_*): out buffers for js_result()/js_error() strings.
    // The embedded JS blob writes the stringified last result here (512B each).
    if (jsUsed) {
        jsResultRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 512; k++) data.push_back(0);
        jsErrorRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 512; k++) data.push_back(0);
    }

    // Sound builtin state (sound_* PCM synthesis + waveOut playback).
    // Slot order and sizes MUST match enum SoundSlot in codegen.h.
    if (soundUsed) {
        // SND_OPENED: 1 once the waveOut device is open (lazy-open guard).
        soundOpenedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // SND_HWO: HWAVEOUT handle returned by waveOutOpen().
        soundHwoRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // SND_FMT: WAVEFORMATEX (18 bytes used + 6 pad).
        soundFmtRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 24; k++) data.push_back(0);
        // SND_BPF: bytes per frame (channels * bits/8) computed by sound_open.
        soundBpfRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // SND_HDR: WAVEHDR (48 bytes used + 8 pad); dwFlags lives at +24.
        soundHdrRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 56; k++) data.push_back(0);
        // SND_SEED: LCG seed for the noise waveform.
        soundSeedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // SND_LUT: 512 int16 sine entries ((-32768..32767) at full scale).
        soundLutRVA = dataRVA + (uint32_t)data.size();
        for (int i = 0; i < 512; i++) {
            double v = std::sin(2.0 * 3.14159265358979323846 * (double)i / 512.0);
            int16_t s = (int16_t)std::lround(v * 32767.0);
            data.push_back((uint8_t)(s & 0xFF));
            data.push_back((uint8_t)((s >> 8) & 0xFF));
        }
    }

    // Heap area RVA — points to .bss (zero-init at runtime, no file space)
    heapAreaRVA = dataRVA + (uint32_t)data.size();

    // Replace heap fixup sentinels with actual RVAs (fixups were emitted before RVAs were known)
    for (auto& hf : heapFixups) {
        if (hf.targetRVA == 0xFFFFFF00) hf.targetRVA = heapAreaRVA;
        else if (hf.targetRVA == 0xFFFFFE00) hf.targetRVA = heapFreeHeadRVA;
        else if (hf.targetRVA == 0xFFFFFD00) hf.targetRVA = heapOffsetRVA;
    }

    // User global variables: allocate zero-initialized slots in .data.
    // Every slot is a multiple of 8 bytes so 64-bit loads never read neighbors.
    if (!prog.globals.empty()) {
        globalOffsets.clear();
        int totalSize = 0;
        for (auto& g : prog.globals) {
            int fieldSize = 8;
            if (g->arraySize > 0) {
                int elemSize = arrayElemStride(g->type);
                fieldSize = elemSize * g->arraySize;
            } else if (g->type.kind == TypeKind::Struct) {
                auto it = structLayouts.find(g->type.structName);
                if (it != structLayouts.end()) fieldSize = it->second.totalSize;
            } else if (g->type.kind == TypeKind::Bool) {
                fieldSize = 4;
            } else if (g->type.kind == TypeKind::Float) {
                fieldSize = 4;
            } else if (g->type.kind == TypeKind::Vec2) {
                fieldSize = 8;
            } else if (g->type.kind == TypeKind::Vec3) {
                fieldSize = 12;
            } else if (g->type.kind == TypeKind::Color) {
                fieldSize = 16;
            }
            if (fieldSize % 8 != 0) fieldSize += 8 - (fieldSize % 8);
            if (globalOffsets.count(g->name) > 0) {
                std::cerr << "Error: duplicate global variable '" << g->name
                          << "' (a file-scope 'var' with this name already exists; "
                          << "duplicate declarations would alias one storage slot)\n";
                return;
            }
            globalOffsets[g->name] = totalSize;
            totalSize += fieldSize;
        }
        globalsSize = totalSize;
        globalsRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < globalsSize; k++) data.push_back(0);
    }
}

// ============== PE Builder ==============

void Codegen::buildPE(const std::string& outputPath) {
    bool isEfi = (prog.appType == AppType::EFI);

    checkFixupOverlaps("PE");

    // Patch ExitProcess call (EXE only, not EFI)
    if (!libOutput && !isEfi) {
        auto epIt = externFuncMap.find("ExitProcess");
        if (epIt != externFuncMap.end()) {
            uint32_t targetIATRVA = epIt->second.second;
            int64_t disp = (int64_t)targetIATRVA - (int64_t)(textRVA + entryExitProcessFixup + 4);
            code[entryExitProcessFixup]     = (uint8_t)(disp & 0xFF);
            code[entryExitProcessFixup + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[entryExitProcessFixup + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[entryExitProcessFixup + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // Patch import call fixups
    for (auto& icf : importCallFixups) {
        auto it = externFuncMap.find(icf.funcName);
        if (it != externFuncMap.end()) {
            uint32_t targetIATRVA = it->second.second;
            int64_t disp = (int64_t)targetIATRVA - (int64_t)(textRVA + icf.codePos + 4);
            code[icf.codePos]     = (uint8_t)(disp & 0xFF);
            code[icf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[icf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[icf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        } else {
            std::cerr << "Error: import call fixup not found in externFuncMap: '" << icf.funcName << "'\n";
        }
    }

    // Patch string fixups
    for (auto& sf : strFixups) {
        uint32_t strTargetRVA = stringRVA + stringOffsets[sf.stringIndex];
        int64_t disp = (int64_t)strTargetRVA - (int64_t)(textRVA + sf.codePos + 4);
        code[sf.codePos]     = (uint8_t)(disp & 0xFF);
        code[sf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[sf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[sf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    }

    // Heap area resides in .bss (zero bytes on disk, zero-initialized in memory).
    // Snap heapAreaRVA to .bss start and adjust fixups BEFORE patching code bytes.
    uint32_t rawDataEnd = dataRVA + (uint32_t)data.size();
    uint32_t bssSize = 64 * 1024 * 1024;
    uint32_t bssRVA = (rawDataEnd + 0xFFF) & ~0xFFF;
    if (heapAreaRVA != bssRVA) {
        int32_t bssDelta = (int32_t)(bssRVA - heapAreaRVA);
        for (auto& hf : heapFixups) {
            if (hf.targetRVA == heapAreaRVA) {
                hf.targetRVA += bssDelta;
            }
        }
        heapAreaRVA = bssRVA;
    }

    // Network response buffer sits right after the heap in .bss (zero-init,
    // no file space). Only reserved when http_get/http_last_error/http_json
    // is used. http_json additionally needs the raw-headers buffer and the
    // JSON record buffer.
    if (httpGetUsed) {
        netBufRVA = bssRVA + 64 * 1024 * 1024;
        netHdrRVA = netBufRVA + NET_BUFFER_SIZE;
        netJsonRVA = netHdrRVA + NET_HDR_SIZE;
        bssSize += (NET_BUFFER_SIZE + NET_HDR_SIZE + NET_JSON_RECORD_SIZE + 0xFFF) & ~0xFFF;
        // Resolve net fixups: .data state slots (known) + .bss buffers (just computed)
        uint32_t slotRVAs[9] = {
            netStatusRVA, netStatusLenRVA, netBytesReadRVA, netLenRVA,
            netErrRVA, netBufRVA, netHdrLenRVA, netHdrRVA, netJsonRVA
        };
        for (auto& nf : netFixups) {
            if (nf.slot >= 9) continue;
            uint32_t targetRVA = slotRVAs[nf.slot];
            int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + nf.codePos + 4);
            code[nf.codePos]     = (uint8_t)(disp & 0xFF);
            code[nf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[nf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[nf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // Socket fixups (net_* TCP/UDP): all sock slots are allocated in .data by
    // buildImportData, so they are already absolute RVAs here.
    if (netSocksUsed) {
        uint32_t sockRVAs[4] = {
            sockWsaStartedRVA, sockWsadataRVA, sockPeerRVA, sockPeerLenRVA
        };
        for (auto& sf : sockFixups) {
            if (sf.slot >= 4) continue;
            uint32_t targetRVA = sockRVAs[sf.slot];
            int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + sf.codePos + 4);
            code[sf.codePos]     = (uint8_t)(disp & 0xFF);
            code[sf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[sf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[sf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // TLS fixups (tls_* io-slot guard flag TLS_IO_DONE): allocated in .data by
    // buildImportData, so already absolute RVAs here.
    if (tlsUsed) {
        uint32_t tlsRVAs[1] = { tlsIoDoneRVA };
        for (auto& tf : tlsFixups) {
            if (tf.slot >= 1) continue;
            uint32_t targetRVA = tlsRVAs[tf.slot];
            int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + tf.codePos + 4);
            code[tf.codePos]     = (uint8_t)(disp & 0xFF);
            code[tf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[tf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[tf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // JS fixups (js_* result/error buffer pointers into .data): allocated by
    // buildImportData, so already absolute RVAs here.
    if (jsUsed) {
        uint32_t jsRVAs[2] = { jsResultRVA, jsErrorRVA };
        for (auto& jf : jsFixups) {
            if (jf.slot >= 2) continue;   // same guard the net/sock/tls/sound lists carry
            uint32_t targetRVA = jsRVAs[jf.slot];
            int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + jf.codePos + 4);
            code[jf.codePos]     = (uint8_t)(disp & 0xFF);
            code[jf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[jf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[jf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // Sound fixups (sound_* synthesis helper slot references): all sound slots
    // are allocated in .data by buildImportData (absolute RVAs here).
    if (soundUsed) {
        uint32_t soundRVAs[7] = {
            soundOpenedRVA, soundHwoRVA, soundFmtRVA, soundBpfRVA,
            soundHdrRVA, soundSeedRVA, soundLutRVA
        };
        for (auto& sf : soundFixups) {
            if (sf.slot >= 7) continue;
            uint32_t targetRVA = soundRVAs[sf.slot];
            int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + sf.codePos + 4);
            code[sf.codePos]     = (uint8_t)(disp & 0xFF);
            code[sf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
            code[sf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
            code[sf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
        }
    }

    // Independent-kernel memory-map scratch: 64 KiB zero-init tail of .bss.
    // The EFI entry stub (kernel_mode independent) passes this buffer to
    // GetMemoryMap before calling ExitBootServices. Referenced from code via
    // RIP-relative lea with a sentinel target resolved here, where the final
    // .bss layout (heap + optional net buffers) is known.
    if (isEfi && prog.kernelMode == KernelMode::Independent) {
        mmBufRVA = bssRVA + bssSize;
        bssSize += kMmBufCapacity;
        for (auto& hf : heapFixups) {
            if (hf.targetRVA == 0xFFFFFA00) hf.targetRVA = mmBufRVA;
        }
    }

    // Patch heap fixups
    for (auto& hf : heapFixups) {
        int64_t disp = (int64_t)hf.targetRVA - (int64_t)(textRVA + hf.codePos + 4);
        code[hf.codePos]     = (uint8_t)(disp & 0xFF);
        code[hf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[hf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[hf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    }

    // Patch user global fixups
    for (auto& gf : globalFixups) {
        int64_t disp = (int64_t)gf.targetRVA - (int64_t)(textRVA + gf.codePos + 4);
        code[gf.codePos]     = (uint8_t)(disp & 0xFF);
        code[gf.codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[gf.codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[gf.codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    }

    // ================================================================
    // Base relocations (.reloc) for EFI images.
    //
    // Strict vendor firmware (AMI/Insyde/Phoenix) refuses to load a PE at
    // any address other than its preferred ImageBase unless the image
    // declares valid relocation info. OVMF tolerates a missing .reloc,
    // which is exactly why QEMU boots fine while real machines black-screen.
    // Emit one minimal valid block: a single DIR64 entry aimed at the
    // reserved qword inside the EFI globals block (+120..+127, unused by
    // any builtin), so a loader that rebases us has something harmless to
    // patch instead of rejecting the image.
    // ================================================================
    uint32_t relocDirRVA = 0;
    uint32_t relocDirSize = 0;
    if (isEfi && win32GlobalsRVA != 0) {
        uint32_t relocTargetRVA = win32GlobalsRVA + 120;
        uint32_t pageRVA = relocTargetRVA & ~0xFFFu;
        size_t blockStart = rdata.size();
        auto pushU32r = [&](uint32_t v) {
            rdata.push_back((uint8_t)(v & 0xFF));
            rdata.push_back((uint8_t)((v >> 8) & 0xFF));
            rdata.push_back((uint8_t)((v >> 16) & 0xFF));
            rdata.push_back((uint8_t)((v >> 24) & 0xFF));
        };
        pushU32r(pageRVA);   // PageRVA
        pushU32r(12);        // BlockSize: 8-byte header + 2-byte entry + pad
        // Entry word layout: OFFSET = low 12 bits, TYPE = high 4 bits.
        // Type 10 = IMAGE_REL_BASED_DIR64.
        uint16_t relEntry = (uint16_t)(((relocTargetRVA - pageRVA) & 0xFFFu) | (10u << 12));
        rdata.push_back((uint8_t)(relEntry & 0xFF));
        rdata.push_back((uint8_t)((relEntry >> 8) & 0xFF));
        while (rdata.size() % 4 != 0) rdata.push_back(0);
        relocDirRVA = rdataRVA + (uint32_t)blockStart;
        relocDirSize = 12;
    }

    uint32_t textSize = (uint32_t)code.size();
    uint32_t rdataSize = (uint32_t)rdata.size();
    uint32_t dataSize = (uint32_t)data.size();

    // Validate no section overlap
    uint32_t actualTextEnd = textRVA + ((textSize + 0xFFF) & ~0xFFF);
    if (rdataRVA < actualTextEnd) {
        std::cerr << "ERROR: .text (end=0x" << std::hex << actualTextEnd
                  << ") overlaps .rdata (0x" << rdataRVA << std::dec << ")\n";
        throw std::runtime_error("Section overlap: .text overlaps .rdata");
    }
    uint32_t actualRdataEnd = rdataRVA + ((rdataSize + 0xFFF) & ~0xFFF);
    if (dataRVA < actualRdataEnd) {
        std::cerr << "ERROR: .rdata (end=0x" << std::hex << actualRdataEnd
                  << ") overlaps .data (0x" << dataRVA << std::dec << ")\n";
        throw std::runtime_error("Section overlap: .rdata overlaps .data");
    }

    uint32_t textRawSize = (textSize + 0x1FF) & ~0x1FF;
    uint32_t rdataRawSize = (rdataSize + 0x1FF) & ~0x1FF;
    uint32_t dataRawSize = (dataSize + 0x1FF) & ~0x1FF;

    DOSHeader dos;
    IMAGE_FILE_HEADER coff;

    bool is32bit = (prog.appType == AppType::BIOS) || 
                   (prog.appType == AppType::Bare && prog.kernelMode == KernelMode::Dependent && prog.arch == Arch::X86_32);

    IMAGE_OPTIONAL_HEADER64 opt64 = {};
    IMAGE_OPTIONAL_HEADER32 opt32 = {};
    void* opt = is32bit ? (void*)&opt32 : (void*)&opt64;
    uint16_t optSize = is32bit ? sizeof(opt32) : sizeof(opt64);

    if (isEfi) {
        // EDK2-convention preferred base well below 4 GB (BOOTX64.EFI built
        // by the reference toolchain uses 0x10000000). Vendor firmware can
        // almost always honour it without relocating; a valid .reloc is
        // emitted regardless for the cases where it must move us.
        opt64.ImageBase = 0x10000000;
        opt32.ImageBase = 0x10000000;
    }

    coff.Machine = is32bit ? 0x014C : 0x8664; // i386 : x86_64
    coff.NumberOfSections = 4;
    coff.SizeOfOptionalHeader = optSize;

    if (isEfi) {
        if (is32bit) {
            opt32.Subsystem = 10;  // EFI_APPLICATION
            opt32.DllCharacteristics = 0x0000; // match EDK2-built EFI images
        } else {
            opt64.Subsystem = 10;  // EFI_APPLICATION
            opt64.DllCharacteristics = 0x0000; // no DYNAMIC_BASE/HIGH_ENTROPY_VA:
                                               // strict AMI/Insyde loaders behave
                                               // unpredictably with them on EFI
        }
        coff.Characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    } else {
        if (is32bit) {
            opt32.Subsystem = (prog.appType == AppType::GUI) ? 2 : 3;
            opt32.DllCharacteristics = 0x0160;
            if (libOutput) {
                coff.Characteristics = 0x2022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
                opt32.Subsystem = 2; // GUI subsystem for DLL (works with DllMain)
            } else {
                coff.Characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            }
        } else {
            opt64.Subsystem = (prog.appType == AppType::GUI) ? 2 : 3;
            opt64.DllCharacteristics = 0x0160; // NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA
            if (libOutput) {
                coff.Characteristics = 0x2022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
                opt64.Subsystem = 2; // GUI subsystem for DLL (works with DllMain)
            } else {
                coff.Characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            }
        }
    }

    if (is32bit) {
        opt32.NumberOfRvaAndSizes = 16;
        opt32.SizeOfCode = textRawSize;
        opt32.SizeOfInitializedData = rdataRawSize + dataRawSize;
        opt32.AddressOfEntryPoint = textRVA + (uint32_t)entryPointCodeOffset;
    } else {
        opt64.NumberOfRvaAndSizes = 16;
        opt64.SizeOfCode = textRawSize;
        opt64.SizeOfInitializedData = rdataRawSize + dataRawSize;
        opt64.AddressOfEntryPoint = textRVA + (uint32_t)entryPointCodeOffset;
    }

    // Calculate sections end for SizeOfImage
    uint32_t textEnd = textRVA + ((textSize + 0xFFF) & ~0xFFF);
    uint32_t rdataEnd = rdataRVA + ((rdataSize + 0xFFF) & ~0xFFF);
    uint32_t dataEnd = dataRVA + ((dataSize + 0xFFF) & ~0xFFF);
    uint32_t bssEnd = bssRVA + ((bssSize + 0xFFF) & ~0xFFF);
    uint32_t lastSectionEnd = bssEnd;
    if (dataEnd > lastSectionEnd) lastSectionEnd = dataEnd;
    if (rdataEnd > lastSectionEnd) lastSectionEnd = rdataEnd;
    if (textEnd > lastSectionEnd) lastSectionEnd = textEnd;

    uint32_t headerRawSize;
    if (is32bit) {
        opt32.SizeOfImage = (lastSectionEnd + 0xFFF) & ~0xFFF;
        // Compute raw offsets after COFF/opt fields are populated
        headerRawSize = (dos.e_lfanew + 4 + sizeof(coff) + sizeof(opt32) + coff.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) + 0x1FF) & ~0x1FF;
        opt32.SizeOfHeaders = headerRawSize;
    } else {
        opt64.SizeOfImage = (lastSectionEnd + 0xFFF) & ~0xFFF;
        // Compute raw offsets after COFF/opt fields are populated
        headerRawSize = (dos.e_lfanew + 4 + sizeof(coff) + sizeof(opt64) + coff.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) + 0x1FF) & ~0x1FF;
        opt64.SizeOfHeaders = headerRawSize;
    }
    uint32_t textRawOfs = headerRawSize;
    uint32_t rdataRawOfs = textRawOfs + textRawSize;
    uint32_t dataRawOfs = rdataRawOfs + rdataRawSize;

    // Import directory entry — point to descriptors in .rdata
    // EFI has no imports, skip import directory
    uint32_t importDescSize = (importDescCount + 1) * 20;
    if (!isEfi) {
        if (is32bit) {
            opt32.DataDirectory[1].VirtualAddress = rdataRVA;
            opt32.DataDirectory[1].Size = importDescSize;
        } else {
            opt64.DataDirectory[1].VirtualAddress = rdataRVA;
            opt64.DataDirectory[1].Size = importDescSize;
        }
    }

    // Export directory entry for DLL mode
    if (libOutput && exportDirSize > 0) {
        if (is32bit) {
            opt32.DataDirectory[0].VirtualAddress = exportDirRVA;
            opt32.DataDirectory[0].Size = exportDirSize;
        } else {
            opt64.DataDirectory[0].VirtualAddress = exportDirRVA;
            opt64.DataDirectory[0].Size = exportDirSize;
        }
    }

    // Base relocation directory (EFI): allows firmware to load us anywhere.
    if (relocDirSize > 0) {
        if (is32bit) {
            opt32.DataDirectory[5].VirtualAddress = relocDirRVA;
            opt32.DataDirectory[5].Size = relocDirSize;
        } else {
            opt64.DataDirectory[5].VirtualAddress = relocDirRVA;
            opt64.DataDirectory[5].Size = relocDirSize;
        }
    }

    IMAGE_SECTION_HEADER textSec{}, rdataSec{}, dataSec{}, bssSec{};

    memcpy(textSec.Name, ".text", 6);
    textSec.VirtualSize = textSize;
    textSec.VirtualAddress = textRVA;
    textSec.SizeOfRawData = textRawSize;
    textSec.PointerToRawData = textRawOfs;
    // .text is read/execute normally; TLS apps need the .text-resident io-slot
    // table in the crypto blob to be writable so emitTlsIoInit can seed it.
    // jsUsed also needs RWX .text: the JS blob's 4 MiB arena lives in .text.
    textSec.Characteristics = (tlsUsed || jsUsed || disasmUsed) ? 0xE0000020 : 0x60000020;

    memcpy(rdataSec.Name, ".rdata", 7);
    rdataSec.VirtualSize = rdataSize;
    rdataSec.VirtualAddress = rdataRVA;
    rdataSec.SizeOfRawData = rdataRawSize;
    rdataSec.PointerToRawData = rdataRawOfs;
    rdataSec.Characteristics = 0x40000040;

    memcpy(dataSec.Name, ".data", 6);
    dataSec.VirtualSize = dataSize;
    dataSec.VirtualAddress = dataRVA;
    dataSec.SizeOfRawData = dataRawSize;
    dataSec.PointerToRawData = dataRawOfs;
    dataSec.Characteristics = 0xC0000040;

    memcpy(bssSec.Name, ".bss", 5);
    bssSec.VirtualSize = bssSize;
    bssSec.VirtualAddress = bssRVA;
    bssSec.SizeOfRawData = 0;
    bssSec.PointerToRawData = 0;
    bssSec.Characteristics = 0xC0000080;

    std::ofstream f{safeNarrowToPath(outputPath), std::ios::binary};
    if (!f) {
        cerr << "Error: cannot write '" << outputPath << "'" << endl;
        exit(1);
    }
    f.write((const char*)&dos, sizeof(dos));

    const char* stub = "This program cannot be run in DOS mode.\r\n";
    f.write(stub, (int)strlen(stub) + 1);
    size_t stubEnd = 0x40 + strlen(stub) + 1;
    while (stubEnd < dos.e_lfanew) { f.put(0); stubEnd++; }

    uint32_t peSig = 0x00004550;
    f.write((const char*)&peSig, 4);
    f.write((const char*)&coff, sizeof(coff));
    if (is32bit) {
        f.write((const char*)&opt32, sizeof(opt32));
    } else {
        f.write((const char*)&opt64, sizeof(opt64));
    }
    f.write((const char*)&textSec, sizeof(textSec));
    f.write((const char*)&rdataSec, sizeof(rdataSec));
    f.write((const char*)&dataSec, sizeof(dataSec));
    f.write((const char*)&bssSec, sizeof(bssSec));

    size_t hEnd = dos.e_lfanew + 4 + sizeof(coff) + (is32bit ? sizeof(opt32) : sizeof(opt64)) + sizeof(textSec) + sizeof(rdataSec) + sizeof(dataSec) + sizeof(bssSec);
    while (hEnd < textRawOfs) { f.put(0); hEnd++; }

    f.write((const char*)code.data(), code.size());
    for (uint32_t i = code.size(); i < textRawSize; i++) f.put(0);

    f.write((const char*)rdata.data(), rdata.size());
    for (uint32_t i = rdata.size(); i < rdataRawSize; i++) f.put(0);

    f.write((const char*)data.data(), data.size());
    for (uint32_t i = data.size(); i < dataRawSize; i++) f.put(0);

    // Zenith magic trailer: consumed by writeIso for bare/bios images only.
    // Never append it to EFI files — strict vendor firmware validates the
    // file size against the section table and rejects trailing bytes.
    if (!isEfi) f.write((const char*)kZenithMagic, 6);
    f.close();
    if (!f) {
        cerr << "Error: cannot write '" << outputPath << "'" << endl;
        exit(1);
    }
    std::cout << "Compiled: " << outputPath << " (" << textSize << " B code)\n";
}

// ============== Flat Raw Builder (app bare) ==============
// Produces a flat binary meant to be loaded at 0x100000 by a custom BIOS loader:
//   [code][pad to 16][string pool][pad to 16][win32 globals (56B)][user globals]
//   [heap offset (8)][heap free head (8)][rand seed (8)][heap area (64 KiB)]
//   [u32 entry offset]["Zenith"]
// RIP-relative fixups are patched as if the image base were 0 (file offset == RVA).
void Codegen::writeBareFlatImage(const std::string& path) {
    checkFixupOverlaps("bare flat image");

    // Build the string pool into a flat .rdata blob.
    stringOffsets.clear();
    std::vector<uint8_t> flatRdata;
    uint32_t flatRdataRVA = (uint32_t)code.size();
    for (auto& s : stringPool) {
        stringOffsets.push_back((uint32_t)flatRdata.size());
        for (char c : s) flatRdata.push_back((uint8_t)c);
        flatRdata.push_back(0);
    }
    while (flatRdata.size() % 16 != 0) flatRdata.push_back(0);
    uint32_t flatStringRVA = flatRdataRVA;

    // Flat .data blob: win32 globals + user globals + heap allocator state + reserved heap area.
    std::vector<uint8_t> flatData;
    uint32_t flatDataRVA = flatRdataRVA + (uint32_t)flatRdata.size();

    uint32_t flatWin32Globals = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 56; k++) flatData.push_back(0);

    uint32_t flatGlobals = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < globalsSize; k++) flatData.push_back(0);

    uint32_t flatHeapOffset = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatHeapFreeHead = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatRandSeed = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatHeapArea = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 0x10000; k++) flatData.push_back(0);

    // Patch RIP-relative fixups (image base = 0: disp = target - (codePos + 4)).
    auto patchDisp = [&](size_t codePos, uint32_t targetRVA) {
        int64_t disp = (int64_t)targetRVA - (int64_t)(codePos + 4);
        code[codePos]     = (uint8_t)(disp & 0xFF);
        code[codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    };

    for (auto& sf : strFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        patchDisp(sf.codePos, flatStringRVA + stringOffsets[sf.stringIndex]);
    }

    // buildImportData/fixupSectionRVAs already replaced the heap sentinels with the
    // (PE-layout) addresses, so re-map by comparing against those known addresses.
    for (auto& hf : heapFixups) {
        uint32_t t = hf.targetRVA;
        uint32_t flat;
        if (globalsSize > 0 && t >= globalsRVA && t < globalsRVA + (uint32_t)globalsSize) flat = flatGlobals + (t - globalsRVA);
        else if (t == heapAreaRVA) flat = flatHeapArea;
        else if (t == heapOffsetRVA) flat = flatHeapOffset;
        else if (t == heapFreeHeadRVA) flat = flatHeapFreeHead;
        else if (t == randSeedRVA) flat = flatRandSeed;
        else if (win32GlobalsRVA != 0 && t >= win32GlobalsRVA && t < win32GlobalsRVA + 56) flat = flatWin32Globals + (t - win32GlobalsRVA);
        else if (t < 56) flat = flatWin32Globals + t;  // bare: win32GlobalsRVA stays 0
        else flat = t;
        patchDisp(hf.codePos, flat);
    }

    for (auto& gf : globalFixups) {
        uint32_t off = (globalsRVA != 0) ? (gf.targetRVA - globalsRVA) : gf.targetRVA;
        patchDisp(gf.codePos, flatGlobals + off);
    }

    // Write flat image + trailer: [entry offset u32]["Zenith"].
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        cerr << "Error: cannot write '" << path << "'" << endl;
        exit(1);
    }
    f.write((const char*)code.data(), code.size());
    f.write((const char*)flatRdata.data(), flatRdata.size());
    f.write((const char*)flatData.data(), flatData.size());
    uint32_t entryOfs = (uint32_t)entryPointCodeOffset;
    f.write((const char*)&entryOfs, 4);
    f.write((const char*)kZenithMagic, 6);
    f.close();
    if (!f) {
        cerr << "Error: cannot write '" << path << "'" << endl;
        exit(1);
    }
    std::cout << "Compiled raw: " << path << " (" << code.size() << " B code, "
              << (code.size() + flatRdata.size() + flatData.size() + 10) << " B total, entry +0x"
              << std::hex << entryOfs << std::dec << ")\n";
}

// ============== Flat Raw Builder (app bios) ==============
// Produces a flat binary (no PE header) loaded at 0x100000 by the BIOS boot
// stub. Layout matches writeBareFlatImage:
//   [code][pad to 16][string pool][pad to 16][win32 globals (56B)][user globals]
//   [heap offset (8)][heap free head (8)][rand seed (8)][heap area (64 KiB)]
//   [u32 entry offset]["Zenith"]
// BIOS code is 32-bit and addresses strings/globals with absolute disp32, so
// fixups are patched with ABSOLUTE addresses (image base 0x100000), unlike the
// RIP-relative patching used by the 64-bit bare image.
void Codegen::writeBiosFlatImage(const std::string& path) {
    checkFixupOverlaps("bios flat image");

    const uint32_t kBase = 0x100000;

    stringOffsets.clear();
    std::vector<uint8_t> flatRdata;
    uint32_t flatRdataRVA = (uint32_t)code.size();
    for (auto& s : stringPool) {
        stringOffsets.push_back((uint32_t)flatRdata.size());
        for (char c : s) flatRdata.push_back((uint8_t)c);
        flatRdata.push_back(0);
    }
    while (flatRdata.size() % 16 != 0) flatRdata.push_back(0);
    uint32_t flatStringRVA = flatRdataRVA;

    std::vector<uint8_t> flatData;
    uint32_t flatDataRVA = flatRdataRVA + (uint32_t)flatRdata.size();

    uint32_t flatWin32Globals = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 56; k++) flatData.push_back(0);

    uint32_t flatGlobals = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < globalsSize; k++) flatData.push_back(0);

    uint32_t flatHeapOffset = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatHeapFreeHead = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatRandSeed = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 8; k++) flatData.push_back(0);
    uint32_t flatHeapArea = flatDataRVA + (uint32_t)flatData.size();
    for (int k = 0; k < 0x10000; k++) flatData.push_back(0);

    // Patch absolute disp32 fixups (image loaded at kBase).
    auto patchAbs = [&](size_t codePos, uint32_t flatAddr) {
        uint32_t abs = kBase + flatAddr;
        code[codePos]     = (uint8_t)(abs & 0xFF);
        code[codePos + 1] = (uint8_t)((abs >> 8) & 0xFF);
        code[codePos + 2] = (uint8_t)((abs >> 16) & 0xFF);
        code[codePos + 3] = (uint8_t)((abs >> 24) & 0xFF);
    };

    for (auto& sf : strFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        patchAbs(sf.codePos, flatStringRVA + stringOffsets[sf.stringIndex]);
    }

    for (auto& hf : heapFixups) {
        uint32_t t = hf.targetRVA;
        uint32_t flat;
        if (globalsSize > 0 && t >= globalsRVA && t < globalsRVA + (uint32_t)globalsSize) flat = flatGlobals + (t - globalsRVA);
        else if (t == heapAreaRVA) flat = flatHeapArea;
        else if (t == heapOffsetRVA) flat = flatHeapOffset;
        else if (t == heapFreeHeadRVA) flat = flatHeapFreeHead;
        else if (t == randSeedRVA) flat = flatRandSeed;
        else if (win32GlobalsRVA != 0 && t >= win32GlobalsRVA && t < win32GlobalsRVA + 56) flat = flatWin32Globals + (t - win32GlobalsRVA);
        else if (t < 56) flat = flatWin32Globals + t;
        else flat = t;
        patchAbs(hf.codePos, flat);
    }

    for (auto& gf : globalFixups) {
        uint32_t off = (globalsRVA != 0) ? (gf.targetRVA - globalsRVA) : gf.targetRVA;
        patchAbs(gf.codePos, flatGlobals + off);
    }

    // The 32-bit backend materialises `&func` as `mov eax, imm32`, which holds
    // an ABSOLUTE address. resolveFixups() already wrote a PC-relative
    // displacement into those bytes (the form the 64-bit `lea` needs), so the
    // final pass here overwrites it with kBase + offset. The 64-bit backend
    // keeps the relative form.
    if (prog.arch == Arch::X86_32) {
        for (auto& fr : funcRefFixups) {
            auto it = funcOffsets.find(fr.target);
            if (it == funcOffsets.end())
                throw std::runtime_error("unresolved function reference '" + fr.target + "'");
            patchAbs(fr.codePos, (uint32_t)it->second);
        }
    }

    std::ofstream f(path, std::ios::binary);
    if (!f) {
        cerr << "Error: cannot write '" << path << "'" << endl;
        exit(1);
    }
    f.write((const char*)code.data(), code.size());
    f.write((const char*)flatRdata.data(), flatRdata.size());
    f.write((const char*)flatData.data(), flatData.size());
    uint32_t entryOfs = (uint32_t)entryPointCodeOffset;
    f.write((const char*)&entryOfs, 4);
    f.write((const char*)kZenithMagic, 6);
    f.close();
    if (!f) {
        cerr << "Error: cannot write '" << path << "'" << endl;
        exit(1);
    }
    std::cout << "Compiled BIOS raw: " << path << " (" << code.size() << " B code, "
              << (code.size() + flatRdata.size() + flatData.size() + 10) << " B total, entry +0x"
              << std::hex << entryOfs << std::dec << ", base 0x100000)\n";
}

// ============== DLL Entry Point ==============

void Codegen::emitDllEntryPoint() {
    entryPointCodeOffset = code.size();
    // DllMain(hinstDLL, fdwReason, lpvReserved) — rcx, rdx, r8
    // Run global initializers once, on DLL_PROCESS_ATTACH (fdwReason == 1).
    emit8(0x83); emit8(0xFA); emit8(0x01);  // cmp edx, 1
    emit8(0x0F); emit8(0x85);               // jne skipInit (near)
    int jnePos = (int)code.size();
    emit32(0);
    emitGlobalInit();
    emitMixCrt0Call();
    int skipInit = newLabel();
    emitLabel(skipInit);
    int32_t disp = (int32_t)(code.size() - (jnePos + 4));
    code[jnePos]     = (uint8_t)(disp & 0xFF);
    code[jnePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
    code[jnePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
    code[jnePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    // return TRUE (1) — x64 uses caller-managed stack, plain ret
    emit8(0x33); emit8(0xC0);  // xor eax, eax
    emit8(0xFF); emit8(0xC0);  // inc eax
    emit8(0xC3);               // ret
}

// ============== Export Directory ==============

void Codegen::buildExportDir() {
    if (!libOutput || exportEntries.empty()) return;

    uint32_t N = (uint32_t)exportEntries.size();

    // DLL name string
    std::string dllBaseName = "zenithlib";
    uint32_t dllNameRVA = rdataRVA + (uint32_t)rdata.size();
    for (char c : dllBaseName) rdata.push_back((uint8_t)c);
    rdata.push_back(0);
    while (rdata.size() % 4 != 0) rdata.push_back(0);

    // Function name strings
    std::vector<uint32_t> nameStrRVAs;
    for (auto& ee : exportEntries) {
        nameStrRVAs.push_back(rdataRVA + (uint32_t)rdata.size());
        for (char c : ee.name) rdata.push_back((uint8_t)c);
        rdata.push_back(0);
    }
    while (rdata.size() % 4 != 0) rdata.push_back(0);

    exportDirRVA = rdataRVA + (uint32_t)rdata.size();

    uint32_t addrTableRVA = exportDirRVA + 40;
    uint32_t namePtrTableRVA = addrTableRVA + N * 4;
    uint32_t ordinalTableRVA = namePtrTableRVA + N * 4;

    auto writeAt = [&](uint32_t val) {
        rdata.push_back(val & 0xFF);
        rdata.push_back((val >> 8) & 0xFF);
        rdata.push_back((val >> 16) & 0xFF);
        rdata.push_back((val >> 24) & 0xFF);
    };

    writeAt(0);             // Characteristics
    writeAt(0);             // TimeDateStamp
    writeAt(0);             // MajorVersion + MinorVersion
    writeAt(dllNameRVA);    // Name
    writeAt(1);             // Base (ordinal base)
    writeAt(N);             // NumberOfFunctions
    writeAt(N);             // NumberOfNames
    writeAt(addrTableRVA);  // AddressOfFunctions
    writeAt(namePtrTableRVA); // AddressOfNames
    writeAt(ordinalTableRVA); // AddressOfNameOrdinals

    for (auto& ee : exportEntries) {
        writeAt(ee.funcRVA);
    }

    // PE spec requires Name Pointer Table sorted alphabetically for binary search
    std::vector<uint32_t> sortedIdx(N);
    for (uint32_t i = 0; i < N; i++) sortedIdx[i] = i;
    std::sort(sortedIdx.begin(), sortedIdx.end(), [&](uint32_t a, uint32_t b) {
        return exportEntries[a].name < exportEntries[b].name;
    });

    for (auto idx : sortedIdx) {
        writeAt(nameStrRVAs[idx]);
    }

    for (auto idx : sortedIdx) {
        rdata.push_back((uint8_t)(idx & 0xFF));
        rdata.push_back((uint8_t)((idx >> 8) & 0xFF));
    }

    exportDirSize = (uint32_t)(rdata.size() - (exportDirRVA - rdataRVA));
}

// ============== Embedded DLL Loader ==============

void Codegen::emitEmbeddedLoader() {
    if (embeddedDLLs.empty()) return;

    for (auto& emb : embeddedDLLs) {
        // 1. GetTempPathA(520, fullPath)
        emit8(0xB9); emit32(520);
        emit8(0x48); emit8(0x8D); emit8(0x15);
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedFullPathRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetTempPathA", "kernel32.dll"});
        emit32(0);

        // 2. lstrcatA(fullPath, "\\dllName")
        emit8(0x48); emit8(0x8D); emit8(0x0D);
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedFullPathRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0x48); emit8(0x8D); emit8(0x15);
        {
            size_t fp = code.size();
            int64_t d = (int64_t)emb.dllPathStrRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, true});
        }
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "lstrcatA", "kernel32.dll"});
        emit32(0);

        // 3. CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)
        emit8(0x48); emit8(0x8D); emit8(0x0D);
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedFullPathRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0xBA); emit32(0x40000000);        // mov edx, GENERIC_WRITE
        emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d
        emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
        // [rsp+0x20] = CREATE_ALWAYS (2)
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20);
        emit32(2);
        // [rsp+0x28] = 0 (flags)
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28);
        emit32(0);
        // [rsp+0x30] = 0 (template)
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30);
        emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);

        // Save hFile: mov [rip+hFile], rax
        emit8(0x48); emit8(0x89); emit8(0x05);
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedHFileRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }

        // 4. WriteFile(hFile, dllData, dllSize, &written, NULL)
        emit8(0x48); emit8(0x89); emit8(0xC1);  // mov rcx, rax (hFile)
        emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+blob]
        {
            size_t fp = code.size();
            int64_t d = (int64_t)emb.blobRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0x41); emit8(0xB8);                // mov r8d, imm32 (blobSize)
        emit32(emb.blobSize);
        emit8(0x4C); emit8(0x8D); emit8(0x0D);  // lea r9, [rip+written]
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedWrittenRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20);
        emit32(0);  // [rsp+0x20] = NULL
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);

        // 5. CloseHandle(hFile)
        emit8(0x48); emit8(0x8B); emit8(0x0D);  // mov rcx, [rip+hFile]
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedHFileRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);

        // 6. LoadLibraryA(fullPath)
        emit8(0x48); emit8(0x8D); emit8(0x0D);  // lea rcx, [rip+fullPath]
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedFullPathRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "LoadLibraryA", "kernel32.dll"});
        emit32(0);
        // Save hModule
        emit8(0x48); emit8(0x89); emit8(0x05);  // mov [rip+hModule], rax
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedHModuleRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }

        // 7. GetProcAddress(hModule, "funcName") for each function
        for (size_t f = 0; f < emb.funcs.size(); f++) {
            // mov rcx, [rip+hModule]
            emit8(0x48); emit8(0x8B); emit8(0x0D);
            {
                size_t fp = code.size();
                int64_t d = (int64_t)embeddedHModuleRVA - (int64_t)(textRVA + code.size() + 4);
                emit32((uint32_t)d);
                embeddedLEAFixups.push_back({fp, false});
            }
            // lea rdx, [rip+funcName]
            emit8(0x48); emit8(0x8D); emit8(0x15);
            {
                size_t fp = code.size();
                int64_t d = (int64_t)emb.funcNameRVAs[f] - (int64_t)(textRVA + code.size() + 4);
                emit32((uint32_t)d);
                embeddedLEAFixups.push_back({fp, true});
            }
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "GetProcAddress", "kernel32.dll"});
            emit32(0);
            // Store result: mov [rip+funcSlot], rax
            emit8(0x48); emit8(0x89); emit8(0x05);
            {
                size_t fp = code.size();
                int64_t d = (int64_t)emb.funcPtrRVAs[f] - (int64_t)(textRVA + code.size() + 4);
                emit32((uint32_t)d);
                embeddedLEAFixups.push_back({fp, false});
            }
        }

        // 8. DeleteFileA(fullPath)
        emit8(0x48); emit8(0x8D); emit8(0x0D);  // lea rcx, [rip+fullPath]
        {
            size_t fp = code.size();
            int64_t d = (int64_t)embeddedFullPathRVA - (int64_t)(textRVA + code.size() + 4);
            emit32((uint32_t)d);
            embeddedLEAFixups.push_back({fp, false});
        }
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "DeleteFileA", "kernel32.dll"});
        emit32(0);
    }
}

// ============== Win64 WinAPI Calling Convention Helper ==============

void Codegen::emitWin64WinAPI(int x64Convention, bool isFloat, const std::vector<std::pair<Type,int>>& args, int stackBytes) {
    (void)x64Convention;
    (void)isFloat;
    (void)stackBytes;
    // The body below was an unfinished stub: it only allocated and
    // immediately freed the Win64 shadow space without ever placing the call
    // or passing arguments, so a caller would have silently produced code
    // that drops every argument. There are no callers today; fail loudly
    // instead of letting one grow on top of the silent no-op.
    for (size_t i = 0; i < args.size(); i++) (void)args[i].first;
    throw std::runtime_error(
        "emitWin64WinAPI: Win64 API call lowering is not implemented "
        "(argument passing/shadow-space setup missing)");
}

// ============== ISO 9660 + El Torito boot image writer ==============

namespace {
void isoPutBoth16(vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off]     = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 8) & 0xFF;
    b[off + 3] = v & 0xFF;
}
void isoPutBoth32(vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off]     = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
    b[off + 4] = (v >> 24) & 0xFF;
    b[off + 5] = (v >> 16) & 0xFF;
    b[off + 6] = (v >> 8) & 0xFF;
    b[off + 7] = v & 0xFF;
}
void isoPutLE16(vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off]     = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
}
void isoPutBE16(vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off]     = (v >> 8) & 0xFF;
    b[off + 1] = v & 0xFF;
}
void isoPutLE32(vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off]     = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
}
void isoPutBE32(vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off]     = (v >> 24) & 0xFF;
    b[off + 1] = (v >> 16) & 0xFF;
    b[off + 2] = (v >> 8) & 0xFF;
    b[off + 3] = v & 0xFF;
}
// ISO 9660 fixed-width text fields (system/volume/application ids) must be
// padded to their full width with spaces, never zeros (ECMA-119).
void isoPutField(vector<uint8_t>& b, size_t off, size_t width, const string& s) {
    for (size_t i = 0; i < width; i++)
        b[off + i] = (i < s.size()) ? (uint8_t)s[i] : ' ';
}
// Appends one ISO 9660 directory record (returns record length incl. padding).
size_t isoDirRecord(vector<uint8_t>& out, const string& id, uint32_t extent,
                    uint32_t dataLen, uint8_t flags) {
    size_t base = out.size();
    out.push_back(0);                       // length (patched below)
    out.push_back(0);                       // extended attribute length
    size_t extOff = out.size(); out.resize(extOff + 8, 0);
    size_t dlenOff = out.size(); out.resize(dlenOff + 8, 0);
    size_t dateOff = out.size(); out.resize(dateOff + 7, 0);
    out.push_back(flags);                   // file flags
    out.push_back(0);                       // file unit size
    out.push_back(0);                       // interleave gap
    size_t vsOff = out.size(); out.resize(vsOff + 4, 0);
    out.push_back((uint8_t)id.size());
    for (char c : id) out.push_back((uint8_t)c);
    size_t len = out.size() - base;
    if (len % 2 != 0) { out.push_back(0); len++; }
    out[base] = (uint8_t)len;
    isoPutBoth32(out, extOff, extent);
    isoPutBoth32(out, dlenOff, dataLen);
    // Fixed recording date: 2026-08-07 00:00:00, GMT offset 0
    out[dateOff]     = 126;                 // year - 1900
    out[dateOff + 1] = 8;                   // month
    out[dateOff + 2] = 7;                   // day
    out[dateOff + 3] = 0;
    out[dateOff + 4] = 0;
    out[dateOff + 5] = 0;
    out[dateOff + 6] = 0;
    isoPutBoth16(out, vsOff, 1);            // volume sequence number
    return len;
}
// Appends one ISO 9660 path table entry (returns length incl. padding).
size_t isoPathEntry(vector<uint8_t>& out, const string& id, uint32_t extent,
                    uint16_t parent, bool bigEndian) {
    size_t start = out.size();
    out.push_back((uint8_t)id.size());      // directory identifier length
    out.push_back(0);                       // extended attribute record length
    size_t extOff = out.size();
    out.resize(extOff + 4, 0);              // extent (LBA)
    size_t parOff = out.size();
    out.resize(parOff + 2, 0);              // parent directory number
    if (bigEndian) isoPutBE32(out, extOff, extent);
    else isoPutLE32(out, extOff, extent);
    if (bigEndian) isoPutBE16(out, parOff, parent);
    else isoPutLE16(out, parOff, parent);
    for (char c : id) out.push_back((uint8_t)c);
    size_t len = out.size() - start;
    if (len % 2 != 0) { out.push_back(0); len++; }
    return len;
}
} // namespace

// ---------- BIOS boot stub (padded to 0x400) ----------
// 16-bit entry (loaded at 0x7C00) -> protected mode 32 -> identity paging (0..1GB)
// -> long mode -> jumps to the flat Zenith kernel copied at 0x100000.
static const unsigned char kBiosStubRaw[] = {
    0xfa, 0x31, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7a, 0x8e, 0xd8, 0x8e, 0xc0, 0xb2, 0x00, 0xb8, 0x00,
    0x00, 0xb9, 0x0e, 0x00, 0xc7, 0x06, 0x08, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x0a, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x0c, 0x70, 0x00, 0xc6, 0x06, 0x0d, 0x70, 0x9a, 0xc6, 0x06, 0x0e, 0x70, 0xcf, 0xc6,
    0x06, 0x0f, 0x70, 0x00, 0xc7, 0x06, 0x10, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x12, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x14, 0x70, 0x00, 0xc6, 0x06, 0x15, 0x70, 0x92, 0xc6, 0x06, 0x16, 0x70, 0xcf, 0xc6,
    0x06, 0x17, 0x70, 0x00, 0xc7, 0x06, 0x18, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x1a, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x1c, 0x70, 0x00, 0xc6, 0x06, 0x1d, 0x70, 0x9a, 0xc6, 0x06, 0x1e, 0x70, 0xcf, 0xc6,
    0x06, 0x1f, 0x70, 0x00, 0xc7, 0x06, 0x20, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x22, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x24, 0x70, 0x00, 0xc6, 0x06, 0x25, 0x70, 0x9a, 0xc6, 0x06, 0x26, 0x70, 0xaf, 0xc6,
    0x06, 0x27, 0x70, 0x00, 0xc7, 0x06, 0x00, 0x70, 0x27, 0x00, 0xc7, 0x06, 0x02, 0x70, 0x00, 0x70,
    0xc7, 0x06, 0x04, 0x70, 0x00, 0x00, 0xc7, 0x06, 0x06, 0x70, 0x00, 0x00, 0x0f, 0x01, 0x16, 0x00,
    0x70, 0xe4, 0x92, 0x0c, 0x02, 0xe6, 0x92, 0x0f, 0x20, 0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22,
    0xc0, 0x66, 0xea, 0xc9, 0x7c, 0x00, 0x00, 0x18, 0x00, 0x66, 0xb8, 0x10, 0x00, 0x8e, 0xd8, 0x8e,
    0xc0, 0x8e, 0xe0, 0x8e, 0xe8, 0x8e, 0xd0, 0xbc, 0x00, 0xf0, 0x9f, 0x00, 0xfc, 0xbe, 0x00, 0x7c,
    0x00, 0x00, 0xbf, 0x00, 0x00, 0x10, 0x00, 0x8b, 0x0d, 0xf8, 0x7f, 0x00, 0x00, 0xf3, 0xa4, 0xfc,
    0xbf, 0x00, 0x00, 0x20, 0x00, 0x31, 0xc0, 0xb9, 0x00, 0x10, 0x00, 0x00, 0xf3, 0xab, 0xc7, 0x05,
    0x00, 0x00, 0x20, 0x00, 0x03, 0x10, 0x20, 0x00, 0xc7, 0x05, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc7, 0x05, 0x00, 0x10, 0x20, 0x00, 0x03, 0x20, 0x20, 0x00, 0xc7, 0x05, 0x04, 0x10,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x20, 0x20, 0x00, 0xb8, 0x83, 0x00, 0x00, 0x00,
    0xb9, 0x00, 0x02, 0x00, 0x00, 0x89, 0x07, 0xc7, 0x47, 0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
    0x00, 0x20, 0x00, 0x83, 0xc7, 0x08, 0x49, 0x75, 0xec, 0x0f, 0x20, 0xe0, 0x83, 0xc8, 0x20, 0x0f,
    0x22, 0xe0, 0xb8, 0x00, 0x00, 0x20, 0x00, 0x0f, 0x22, 0xd8, 0xb9, 0x80, 0x00, 0x00, 0xc0, 0x0f,
    0x32, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x0f, 0x30, 0x0f, 0x20, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x80,
    0x0f, 0x22, 0xc0, 0xea, 0x7a, 0x7d, 0x00, 0x00, 0x20, 0x00, 0x8b, 0x04, 0x25, 0xfc, 0x7f, 0x00,
    0x00, 0x48, 0xbb, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0xc3, 0x48, 0xbc,
    0x00, 0xf0, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xed, 0xff, 0xe3, 0xf4, 0xeb, 0xdb, 0x90,
};
static const uint32_t kStubLen      = 0x400;  // padded boot stub size
static const uint32_t kStubPatchTotal = 0x3F8; // u32: stub + kernel length (bytes)
static const uint32_t kStubPatchEntry= 0x3FC;  // u32: kernel entry offset (relative to 0x100000)

static vector<uint8_t> buildBiosStub(uint32_t totalSize, uint32_t kernelEntry) {
    vector<uint8_t> stub(kStubLen, 0);
    memcpy(stub.data(), kBiosStubRaw, sizeof(kBiosStubRaw));
    // Patch the two compile-time fields (little-endian u32)
    const auto put32 = [&](uint32_t pos, uint32_t v) {
        stub[pos]     = (uint8_t)(v & 0xFF);
        stub[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
        stub[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
        stub[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
    };
    put32(kStubPatchTotal, totalSize);   // stub(0x400) + kernel length
    put32(kStubPatchEntry, kernelEntry + kStubLen); // entry offset within the copied 0x100000 image
    return stub;
}

// ---------- 32-bit protected-mode variant of the BIOS boot stub ----------
// Same 16-bit prefix as kBiosStubRaw (GDT at 0x7000, A20 gate, PE=1, far jump
// to selector 0x18), but the tail stays in 32-bit protected mode: it copies the
// whole record (stub + kernel) from 0x7C00 to 0xFFC00 (so the kernel body lands
// exactly at 0x100000, matching writeX8632Image's absolute base) and jumps to
// 0x100000 + [0x7FFC]. This is what a true 32-bit Zenith kernel expects; the
// long-mode tail of kBiosStubRaw would #UD in a 32-bit build.
static const unsigned char kBiosStub32Raw[] = {
    0xfa, 0x31, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7a, 0x8e, 0xd8, 0x8e, 0xc0, 0xb2, 0x00, 0xb8, 0x00,
    0x00, 0xb9, 0x0e, 0x00, 0xc7, 0x06, 0x08, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x0a, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x0c, 0x70, 0x00, 0xc6, 0x06, 0x0d, 0x70, 0x9a, 0xc6, 0x06, 0x0e, 0x70, 0xcf, 0xc6,
    0x06, 0x0f, 0x70, 0x00, 0xc7, 0x06, 0x10, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x12, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x14, 0x70, 0x00, 0xc6, 0x06, 0x15, 0x70, 0x92, 0xc6, 0x06, 0x16, 0x70, 0xcf, 0xc6,
    0x06, 0x17, 0x70, 0x00, 0xc7, 0x06, 0x18, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x1a, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x1c, 0x70, 0x00, 0xc6, 0x06, 0x1d, 0x70, 0x9a, 0xc6, 0x06, 0x1e, 0x70, 0xcf, 0xc6,
    0x06, 0x1f, 0x70, 0x00, 0xc7, 0x06, 0x20, 0x70, 0xff, 0xff, 0xc7, 0x06, 0x22, 0x70, 0x00, 0x00,
    0xc6, 0x06, 0x24, 0x70, 0x00, 0xc6, 0x06, 0x25, 0x70, 0x9a, 0xc6, 0x06, 0x26, 0x70, 0xaf, 0xc6,
    0x06, 0x27, 0x70, 0x00, 0xc7, 0x06, 0x00, 0x70, 0x27, 0x00, 0xc7, 0x06, 0x02, 0x70, 0x00, 0x70,
    0xc7, 0x06, 0x04, 0x70, 0x00, 0x00, 0xc7, 0x06, 0x06, 0x70, 0x00, 0x00, 0x0f, 0x01, 0x16, 0x00,
    0x70, 0xe4, 0x92, 0x0c, 0x02, 0xe6, 0x92, 0x0f, 0x20, 0xc0, 0x66, 0x83, 0xc8, 0x01, 0x0f, 0x22,
    0xc0, 0x66, 0xea, 0xc9, 0x7c, 0x00, 0x00, 0x18, 0x00, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8,
    0x8e, 0xc0, 0x8e, 0xe0, 0x8e, 0xe8, 0x8e, 0xd0, 0xbc, 0x00, 0xf0, 0x9f, 0x00, 0xfc, 0xbe, 0x00,
    0x7c, 0x00, 0x00, 0xbf, 0x00, 0xfc, 0x0f, 0x00, 0x8b, 0x0d, 0xf8, 0x7f, 0x00, 0x00, 0xf3, 0xa4,
    0xbb, 0x00, 0x00, 0x10, 0x00, 0x8b, 0x0d, 0xfc, 0x7f, 0x00, 0x00, 0x01, 0xcb, 0x31, 0xed, 0xff,
    0xe3,
};

static vector<uint8_t> buildBiosStub32(uint32_t totalSize, uint32_t kernelEntry) {
    vector<uint8_t> stub(kStubLen, 0);
    memcpy(stub.data(), kBiosStub32Raw, sizeof(kBiosStub32Raw));
    const auto put32 = [&](uint32_t pos, uint32_t v) {
        stub[pos]     = (uint8_t)(v & 0xFF);
        stub[pos + 1] = (uint8_t)((v >> 8) & 0xFF);
        stub[pos + 2] = (uint8_t)((v >> 16) & 0xFF);
        stub[pos + 3] = (uint8_t)((v >> 24) & 0xFF);
    };
    // The 32-bit tail copies the FULL record (stub + kernel) to 0xFFC00, so the
    // kernel body lands at exactly 0x100000. kernelEntry is therefore relative
    // to 0x100000 directly (no kStubLen offset).
    put32(kStubPatchTotal, totalSize);
    put32(kStubPatchEntry, kernelEntry);
    return stub;
}

// Builds a 1.44 MB FAT12 floppy image containing \EFI\BOOT\BOOTX64.EFI so UEFI
// firmware (OVMF) can mount it via the El Torito "no emulation" EFI boot entry.
static vector<uint8_t> buildFat12EfiImage(const vector<uint8_t>& efiFile) {
    const uint32_t BYTES = 512;
    const uint32_t RES = 1, NFATS = 2, ROOT_ENT = 224, FAT_SECS = 9, TOTAL = 2880;
    const uint32_t DATA_START = RES + NFATS * FAT_SECS + (ROOT_ENT * 32) / BYTES; // 33
    vector<uint8_t> img(TOTAL * BYTES, 0);

    // ---- FAT12 BPB (byte offsets per the Microsoft FAT spec) ----
    img[0] = 0xEB; img[1] = 0x3C; img[2] = 0x90;
    memcpy(&img[3], "MSWIN4.1", 8);
    img[11] = 0x00; img[12] = 0x02;                       // bytes/sector = 512 (LE)
    img[13] = 1;                                          // sectors/cluster
    img[14] = 1; img[15] = 0;                             // reserved sectors = 1 (LE)
    img[16] = 2;                                          // number of FATs
    img[17] = 0xE0; img[18] = 0x00;                       // root entries = 224 (LE)
    img[19] = 0x40; img[20] = 0x0B;                       // total sectors = 2880 (LE)
    img[21] = 0xF0;                                       // media descriptor
    img[22] = 9; img[23] = 0;                             // FAT size = 9 (LE)
    img[24] = 0x12; img[25] = 0x00;                       // sectors/track = 18 (LE)
    img[26] = 0x02; img[27] = 0x00;                       // heads = 2 (LE)
    img[36] = 0;                                          // drive number
    img[38] = 0x29;                                       // boot signature
    img[39] = 0x78; img[40] = 0x56; img[41] = 0x34; img[42] = 0x12; // volume id
    memcpy(&img[43], "NO NAME    ", 11);                  // volume label (0x2B)
    memcpy(&img[54], "FAT12   ", 8);                      // fs type (0x36)
    img[510] = 0x55; img[511] = 0xAA;

    // ---- FAT table (12-bit entries, packed) ----
    vector<uint8_t> fat(FAT_SECS * BYTES, 0);
    const auto setFat = [&](uint32_t n, uint16_t val) {
        const uint32_t off = (n * 3) / 2;
        if (n % 2 == 0) {
            uint32_t v = (uint32_t)fat[off] | ((uint32_t)fat[off + 1] << 8);
            v = (v & 0xF000) | (val & 0x0FFF);
            fat[off] = (uint8_t)(v & 0xFF);
            fat[off + 1] = (uint8_t)((v >> 8) & 0xFF);
        } else {
            uint32_t v = (uint32_t)fat[off] | ((uint32_t)fat[off + 1] << 8);
            v = (v & 0x000F) | ((uint32_t)(val & 0x0FFF) << 4);
            fat[off] = (uint8_t)(v & 0xFF);
            fat[off + 1] = (uint8_t)((v >> 8) & 0xFF);
        }
    };
    setFat(0, 0xFF0);
    setFat(1, 0xFFF);

    uint32_t nextCluster = 2;
    const auto allocChain = [&](uint32_t nsec) {
        const uint32_t start = nextCluster;
        for (uint32_t i = 0; i < nsec; i++) {
            const uint32_t cur = nextCluster;
            setFat(cur, (uint16_t)((i == nsec - 1) ? 0xFFF : cur + 1));
            nextCluster++;
        }
        return start;
    };

    const uint32_t efiCl  = allocChain(1);          // cluster 2
    const uint32_t bootCl = allocChain(1);          // cluster 3
    const uint32_t nsec   = (uint32_t)((efiFile.size() + BYTES - 1) / BYTES);
    const uint32_t fileCl = allocChain(nsec);       // file data

    // ---- 8.3 directory entry ----
    const auto dirent = [&](const char* name, const char* ext, uint8_t attr, uint16_t cluster, uint32_t size) {
        vector<uint8_t> e(32, 0);
        int i;
        for (i = 0; i < 8 && name[i]; i++) e[i] = (uint8_t)name[i];
        for (; i < 8; i++) e[i] = ' ';
        for (i = 0; i < 3 && ext[i]; i++) e[8 + i] = (uint8_t)ext[i];
        for (; i < 3; i++) e[8 + i] = ' ';
        e[11] = attr;
        e[22] = 0x00; e[23] = 0x60;                   // write time 12:00
        e[24] = 0x21; e[25] = 0x58;                   // write date 2024-01-01
        e[26] = (uint8_t)(cluster & 0xFF);            // low cluster
        e[27] = (uint8_t)((cluster >> 8) & 0xFF);
        e[28] = (uint8_t)(size & 0xFF);
        e[29] = (uint8_t)((size >> 8) & 0xFF);
        e[30] = (uint8_t)((size >> 16) & 0xFF);
        e[31] = (uint8_t)((size >> 24) & 0xFF);
        return e;
    };

    // ---- Root directory (sectors 19..32) ----
    vector<uint8_t> root(ROOT_ENT * 32, 0);
    {
        auto e = dirent("EFI", "", 0x10, (uint16_t)efiCl, 0);
        memcpy(&root[0], e.data(), 32);
    }
    memcpy(&img[(RES + NFATS * FAT_SECS) * BYTES], root.data(), root.size());

    // ---- EFI directory (cluster 2): ".", "..", BOOT ----
    {
        vector<uint8_t> d(BYTES, 0);
        auto d1 = dirent(".", "", 0x10, (uint16_t)efiCl, 0);
        auto d2 = dirent("..", "", 0x10, 0, 0);
        auto d3 = dirent("BOOT", "", 0x10, (uint16_t)bootCl, 0);
        memcpy(&d[0], d1.data(), 32);
        memcpy(&d[32], d2.data(), 32);
        memcpy(&d[64], d3.data(), 32);
        memcpy(&img[(DATA_START + efiCl - 2) * BYTES], d.data(), BYTES);
    }

    // ---- BOOT directory (cluster 3): ".", "..", BOOTX64.EFI ----
    {
        vector<uint8_t> d(BYTES, 0);
        auto d1 = dirent(".", "", 0x10, (uint16_t)bootCl, 0);
        auto d2 = dirent("..", "", 0x10, (uint16_t)efiCl, 0);
        auto d3 = dirent("BOOTX64", "EFI", 0x00, (uint16_t)fileCl, (uint32_t)efiFile.size());
        memcpy(&d[0], d1.data(), 32);
        memcpy(&d[32], d2.data(), 32);
        memcpy(&d[64], d3.data(), 32);
        memcpy(&img[(DATA_START + bootCl - 2) * BYTES], d.data(), BYTES);
    }

    // ---- File contents, then both FAT copies ----
    memcpy(&img[(DATA_START + fileCl - 2) * BYTES], efiFile.data(), efiFile.size());
    memcpy(&img[RES * BYTES], fat.data(), fat.size());
    memcpy(&img[(RES + FAT_SECS) * BYTES], fat.data(), fat.size());
    return img;
}

void Codegen::writeIso(const string& binaryPath, const string& isoPath) {
    // Read the already-compiled boot binary (.efi / .bin / .exe)
    ifstream in(safeNarrowToPath(binaryPath), ios::binary);
    if (!in) {
        cerr << "Error: cannot open '" << binaryPath << "' for ISO image" << endl;
        return;
    }
    vector<uint8_t> fileData((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    if (fileData.empty()) {
        cerr << "Error: boot image '" << binaryPath << "' is empty, cannot build ISO" << endl;
        return;
    }

    const bool isEfi = (prog.appType == AppType::EFI);
    const bool isBare = (prog.appType == AppType::Bare);
    const bool isBios = (prog.appType == AppType::BIOS);
    const uint32_t kSector = 2048;

    if (isBare) {
        // Wrap the bare flat kernel with the BIOS boot stub so the ISO also boots
        // in classic BIOS (El Torito / SeaBIOS). Entry lives in the kernel trailer.
        uint32_t entry = 0;
        if (fileData.size() >= 10 &&
            memcmp(&fileData[fileData.size() - 6], kZenithMagic, 6) == 0) {
            entry = (uint32_t)((uint32_t)fileData[fileData.size() - 10] |
                               ((uint32_t)fileData[fileData.size() - 9] << 8) |
                               ((uint32_t)fileData[fileData.size() - 8] << 16) |
                               ((uint32_t)fileData[fileData.size() - 7] << 24));
        }
        vector<uint8_t> boot = buildBiosStub((uint32_t)(kStubLen + fileData.size()), entry);
        boot.insert(boot.end(), fileData.begin(), fileData.end());
        fileData = std::move(boot);
    } else if (isBios) {
        // BIOS flat image (no PE header): entry lives in the same 10-byte trailer
        // as the bare image — [u32 entry offset]["Zenith"].
        uint32_t entry = 0;
        if (fileData.size() >= 10 &&
            memcmp(&fileData[fileData.size() - 6], kZenithMagic, 6) == 0) {
            entry = (uint32_t)((uint32_t)fileData[fileData.size() - 10] |
                               ((uint32_t)fileData[fileData.size() - 9] << 8) |
                               ((uint32_t)fileData[fileData.size() - 8] << 16) |
                               ((uint32_t)fileData[fileData.size() - 7] << 24));
        }
        // True 32-bit kernels need the protected-mode stub (the 64-bit stub would
        // attempt long-mode setup and fault).
        const bool x32 = (prog.arch == Arch::X86_32);
        vector<uint8_t> boot = x32
            ? buildBiosStub32((uint32_t)(kStubLen + fileData.size()), entry)
            : buildBiosStub((uint32_t)(kStubLen + fileData.size()), entry);
        boot.insert(boot.end(), fileData.begin(), fileData.end());
        fileData = std::move(boot);
    }

    const uint32_t fileSectors = (uint32_t)((fileData.size() + kSector - 1) / kSector);

    // For EFI the El Torito boot image must be a FAT filesystem with
    // \EFI\BOOT\BOOTX64.EFI (raw PE64 in the ISO tree won't mount in OVMF).
    vector<uint8_t> fatImg;
    if (isEfi) fatImg = buildFat12EfiImage(fileData);
    const uint32_t fatSectors = (isEfi) ? (uint32_t)(fatImg.size() / kSector) : 0;

    // LBA layout (sectors) — PVD/BootRecord/Terminator are hardcoded at 16/17/18.
    const uint32_t lbaCatalog    = 19;
    const uint32_t lbaLPath      = 20;
    const uint32_t lbaMPath      = 21;
    const uint32_t lbaRoot       = 22;
    const uint32_t lbaEfi        = isEfi ? 23 : 0;
    const uint32_t lbaBoot       = isEfi ? 24 : 0;
    const uint32_t lbaFile       = isEfi ? 25 : 23;
    const uint32_t lbaFat        = isEfi ? (25 + fileSectors) : 0;
    const uint32_t totalSectors  = (isEfi ? 25 : 23) + fileSectors + fatSectors;

    // ISO 9660 (Level 1) file identifier for the boot image
    string isoName;
    if (isEfi) {
        isoName = "BOOTX64.EFI";
    } else {
        string base = binaryPath;
        size_t slash = base.find_last_of("/\\");
        if (slash != string::npos) base = base.substr(slash + 1);
        string stem, ext;
        size_t dot = base.find_last_of('.');
        if (dot != string::npos) { stem = base.substr(0, dot); ext = base.substr(dot + 1); }
        else stem = base;
        for (auto& c : stem) c = (char)toupper((unsigned char)c);
        for (auto& c : ext)  c = (char)toupper((unsigned char)c);
        if (stem.size() > 8) stem = stem.substr(0, 8);
        if (ext.size() > 3)  ext  = ext.substr(0, 3);
        if (ext.empty())     ext  = "BIN";
        isoName = stem + "." + ext;
        if (isoName == "." || isoName.empty()) isoName = "BOOT.BIN";
    }

    // ----- Directory data blocks (each padded to a full sector) -----
    vector<uint8_t> rootData, efiData, bootData;
    isoDirRecord(rootData, string(1, (char)0x00), lbaRoot, kSector, 0x02); // "."
    isoDirRecord(rootData, string(1, (char)0x01), lbaRoot, kSector, 0x02); // ".."
    if (isEfi) {
        isoDirRecord(rootData, "EFI", lbaEfi, kSector, 0x02);
    } else {
        isoDirRecord(rootData, isoName, lbaFile, (uint32_t)fileData.size(), 0x00);
    }
    rootData.resize(kSector, 0);

    if (isEfi) {
        isoDirRecord(efiData, string(1, (char)0x00), lbaEfi, kSector, 0x02);
        isoDirRecord(efiData, string(1, (char)0x01), lbaRoot, kSector, 0x02);
        isoDirRecord(efiData, "BOOT", lbaBoot, kSector, 0x02);
        efiData.resize(kSector, 0);

        isoDirRecord(bootData, string(1, (char)0x00), lbaBoot, kSector, 0x02);
        isoDirRecord(bootData, string(1, (char)0x01), lbaEfi, kSector, 0x02);
        isoDirRecord(bootData, "BOOTX64.EFI", lbaFile, (uint32_t)fileData.size(), 0x00);
        bootData.resize(kSector, 0);
    }

    // ----- Path tables (L = little-endian, M = big-endian) -----
    vector<uint8_t> lpath, mpath;
    isoPathEntry(lpath, string(1, (char)0x00), lbaRoot, 1, false);
    isoPathEntry(mpath, string(1, (char)0x00), lbaRoot, 1, true);
    if (isEfi) {
        isoPathEntry(lpath, "EFI", lbaEfi, 1, false);
        isoPathEntry(mpath, "EFI", lbaEfi, 1, true);
        isoPathEntry(lpath, "BOOT", lbaBoot, 2, false);
        isoPathEntry(mpath, "BOOT", lbaBoot, 2, true);
    }
    uint32_t pathTableSize = (uint32_t)lpath.size();
    lpath.resize(kSector, 0);
    mpath.resize(kSector, 0);

    // ----- Primary Volume Descriptor (sector 16) -----
    vector<uint8_t> pvd(kSector, 0);
    pvd[0] = 1;
    memcpy(&pvd[1], "CD001", 5);
    pvd[6] = 1;
    isoPutField(pvd, 8, 32, "ZENITH");                              // system id (space-padded)
    isoPutField(pvd, 40, 32, "ZENITH_BOOT");                        // volume id (space-padded)
    isoPutBoth32(pvd, 80, totalSectors);                            // volume space size
    isoPutBoth16(pvd, 120, 1);                                      // volume set size
    isoPutBoth16(pvd, 124, 1);                                      // volume sequence
    isoPutBoth16(pvd, 128, kSector);                                // logical block size
    isoPutBoth32(pvd, 132, pathTableSize);                          // path table size
    isoPutLE32(pvd, 140, lbaLPath);                                 // L path table location
    isoPutLE32(pvd, 144, 0);                                        // optional L (none)
    isoPutBE32(pvd, 148, lbaMPath);                                 // M path table location
    isoPutBE32(pvd, 152, 0);                                        // optional M (none)
    // Root directory record inside the PVD (34 bytes)
    {
        vector<uint8_t> rec;
        isoDirRecord(rec, string(1, (char)0x00), lbaRoot, kSector, 0x02);
        if (rec.size() < 34) rec.resize(34, 0);
        memcpy(&pvd[156], rec.data(), 34);
    }
    isoPutField(pvd, 190, 128, "ZENITH");                           // volume set id
    isoPutField(pvd, 574, 128, "ZENITH");                           // application id
    const char* dt = "2026080700000000";                            // creation + modification
    memcpy(&pvd[813], dt, 16);
    pvd[829] = 0;
    memcpy(&pvd[830], dt, 16);
    pvd[846] = 0;
    pvd[881] = 1;                                                   // file structure version

    // ----- El Torito Boot Record (sector 17) -----
    vector<uint8_t> bootRec(kSector, 0);
    bootRec[0] = 0;
    memcpy(&bootRec[1], "CD001", 5);
    bootRec[6] = 1;
    const char* elTorito = "EL TORITO SPECIFICATION";
    // El Torito boot system id must stay zero-padded: 7-Zip and friends match
    // it with a fixed compare on "EL TORITO SPECIFICATION\0" (24 bytes).
    memcpy(&bootRec[7], elTorito, strlen(elTorito));
    memcpy(&bootRec[39], "ZENITH BOOT", 11);                        // boot id
    isoPutLE32(bootRec, 71, lbaCatalog);                            // boot catalog pointer

    // ----- Volume Descriptor Set Terminator (sector 18) -----
    vector<uint8_t> term(kSector, 0);
    term[0] = 255;
    memcpy(&term[1], "CD001", 5);
    term[6] = 1;

    // ----- El Torito Boot Catalog (sector 19) -----
    vector<uint8_t> cat(kSector, 0);
    cat[0] = 0x01;                                                  // header id (validation entry)
    cat[1] = isEfi ? 0xEF : 0x00;                                   // platform: EFI / x86
    memcpy(&cat[4], "ZENITH", 6);                                   // id string
    cat[30] = 0x55;
    cat[31] = 0xAA;
    // Checksum: the sum of all 16-bit little-endian words of the validation
    // entry (including the checksum word) must be 0x0000.  (Matches pycdlib /
    // 7-Zip / Windows; big-endian word order is rejected by these parsers.)
    uint32_t sum = 0;
    for (int i = 0; i < 32; i += 2) sum += ((uint16_t)cat[i]) | ((uint16_t)cat[i + 1] << 8);
    uint16_t chk = (uint16_t)(0x10000 - (sum & 0xFFFF));
    cat[28] = chk & 0xFF;
    cat[29] = (chk >> 8) & 0xFF;
    // Initial / default boot entry
    cat[32] = 0x88;                                                 // boot indicator
    cat[33] = 0x00;                                                 // no emulation
    cat[36] = 0;                                                    // system type
    cat[37] = 0;
    uint16_t sectorCount = (uint16_t)((fileData.size() + 511) / 512);
    uint32_t loadRba = lbaFile;
    if (isEfi) {                                                    // boot via FAT image (\EFI\BOOT\BOOTX64.EFI)
        sectorCount = 2880;                                         // 1.44 MB FAT12 in 512-byte units
        loadRba = lbaFat;
    }
    if (sectorCount == 0) sectorCount = 1;
    isoPutLE16(cat, 38, sectorCount);                               // sector count (512-byte units)
    isoPutLE32(cat, 40, loadRba);                                   // load RBA (2048-byte LBA, as SeaBIOS reads it)

    // ----- Assemble the image -----
    vector<uint8_t> img;
    img.reserve(totalSectors * kSector);
    img.insert(img.end(), 16 * kSector, 0);                         // system area
    auto appendSector = [&](const vector<uint8_t>& s) {
        img.insert(img.end(), s.begin(), s.end());
    };
    appendSector(pvd);
    appendSector(bootRec);
    appendSector(term);
    appendSector(cat);
    appendSector(lpath);
    appendSector(mpath);
    appendSector(rootData);
    if (isEfi) {
        appendSector(efiData);
        appendSector(bootData);
    }
    img.insert(img.end(), fileData.begin(), fileData.end());
    if (isEfi) {
        img.resize(lbaFat * kSector, 0);            // pad the raw .efi to its sector boundary
        img.insert(img.end(), fatImg.begin(), fatImg.end());
    }
    img.resize(totalSectors * kSector, 0);

    ofstream out(safeNarrowToPath(isoPath), ios::binary);
    if (!out) {
        cerr << "Error: cannot write ISO image '" << isoPath << "'" << endl;
        exit(1);
    }
    out.write((const char*)img.data(), img.size());
    out.close();
    if (!out) {
        cerr << "Error: cannot write ISO image '" << isoPath << "'" << endl;
        exit(1);
    }
    cout << "ISO image: " << isoPath << " (" << img.size() << " bytes, boot file " << isoName << ")" << endl;
}
