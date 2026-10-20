// srcprep — the source preparation the compiler's single-file path uses,
// copied so tools/pardump and tools/pardiff feed both front ends byte-identical
// text: read the file, splice `include "file.z"`, expand `use <module>`.
//
// Kept next to the tools (not shared with src/main.cpp) because the tools are
// standalone binaries and must not drag main.o in; the logic is a frozen
// snapshot of the compile path and only needs to stay in step with it for the
// files the two front ends are diffed on.
#pragma once
#include "../src/use_resolver.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>
namespace srcprep {

namespace fs = std::filesystem;

inline std::string readFile(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        std::cerr << "Error: cannot open file '" << path << "'" << std::endl;
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return ""; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return ""; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return ""; }
    std::string content((size_t)sz, '\0');
    if (sz > 0) {
        size_t read = fread(&content[0], 1, (size_t)sz, f);
        content.resize(read);
    }
    fclose(f);
    if (content.size() >= 3 &&
        (uint8_t)content[0] == 0xEF &&
        (uint8_t)content[1] == 0xBB &&
        (uint8_t)content[2] == 0xBF) {
        content = content.substr(3);
    }
    return content;
}

inline std::string stripHeaderDirectives(const std::string& content) {
    std::istringstream iss(content);
    std::string line, out;
    bool first = true;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        bool directive =
            (trimmed.rfind("app ", 0) == 0 || trimmed == "app" ||
             trimmed.rfind("kernel_mode", 0) == 0 ||
             trimmed.rfind("asm_word_size", 0) == 0 ||
             trimmed.rfind("@import", 0) == 0 ||
             trimmed.rfind("# [no_main]", 0) == 0);
        if (directive) continue;
        if (!first) out += "\n";
        out += line;
        first = false;
    }
    return out;
}

inline std::string preprocessIncludes(const std::string& source,
                                      const fs::path& dir,
                                      int depth,
                                      std::vector<std::string>& stack,
                                      std::set<std::string>& included) {
    if (depth > 16) {
        std::cerr << "Error: include nesting too deep (circular include?)" << std::endl;
        exit(1);
    }
    std::istringstream iss(source);
    std::string line, out;
    bool first = true;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        size_t s = trimmed.find_first_not_of(" \t");
        if (s != std::string::npos) trimmed = trimmed.substr(s);
        if (trimmed.rfind("include ", 0) == 0) {
            size_t q1 = trimmed.find('"');
            size_t q2 = trimmed.rfind('"');
            if (q1 == std::string::npos || q2 == std::string::npos || q2 <= q1) {
                std::cerr << "Error: bad include syntax (expected: include \"file.z\"): "
                          << trimmed << std::endl;
                exit(1);
            }
            std::string incPath = trimmed.substr(q1 + 1, q2 - q1 - 1);
            fs::path full = dir.empty() ? fs::path(incPath) : (dir / incPath);
            std::string cano = full.string();
            for (auto& p : stack) {
                if (p == cano) {
                    std::cerr << "Error: circular include of '" << cano << "'" << std::endl;
                    exit(1);
                }
            }
            std::string content = readFile(full.string());
            std::string cano2 = full.lexically_normal().string();
            if (included.count(cano2)) continue;
            stack.push_back(cano);
            std::string processed = preprocessIncludes(
                stripHeaderDirectives(content), full.parent_path(), depth + 1, stack, included);
            stack.pop_back();
            included.insert(cano2);
            if (!first) out += "\n";
            out += "# include: " + incPath + "\n" + processed;
            first = false;
            continue;
        }
        if (!first) out += "\n";
        out += line;
        first = false;
    }
    return out;
}

// Scan the source for the `app <type>` directive. `use` modules are resolved
// before parsing, and the module to pick depends on the app type, so this has
// to happen on raw text. Returns "" when there is no app directive.
inline std::string scanAppType(const std::string& src) {
    std::istringstream in(src);
    std::string line;
    while (std::getline(in, line)) {
        size_t i = line.find_first_not_of(" \t\r");
        if (i == std::string::npos) continue;
        std::string t = line.substr(i);
        if (t.rfind("app ", 0) != 0) continue;
        std::istringstream ls(t.substr(4));
        std::string type;
        ls >> type;
        return type;
    }
    return "";
}

// The exact text main.cpp hands to the front end for the single-file path.
inline std::string prepare(const std::string& inputFile) {
    std::string source = readFile(inputFile);
    {
        std::vector<std::string> incStack;
        incStack.push_back(fs::path(inputFile).string());
        std::set<std::string> included;
        source = preprocessIncludes(source, fs::path(inputFile).parent_path(), 0,
                                    incStack, included);
    }
    std::string useErr;
    std::string baseDir = fs::path(inputFile).parent_path().string();
    if (baseDir.empty()) baseDir = ".";
    if (!expandUseDirectives(source, baseDir, scanAppType(source), useErr)) {
        std::cerr << "Error: " << useErr << std::endl;
        exit(1);
    }
    return source;
}

} // namespace srcprep
