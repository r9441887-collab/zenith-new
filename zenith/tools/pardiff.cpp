// pardiff — the selfhost side of the front-end diff.
//
// Parses one .z file through parseZ (selfhost/parseobj.z linked in as
// parseobj.o), dumps the resulting Program with the same tools/progdump.h the
// golden side uses, and diffs it against selfhost/golden/*.dump.
//
// The golden files are produced by tools/pardump while the C++ front end was
// still the one linked into the build — the two front ends cannot share a
// binary (LEXOBJ vs PARSEROBJ symbol collision), so the reference had to be
// frozen first.
//
// Accepted divergence, intentionally NOT reported: CallExpr vtable pair order.
//
// Exit codes: 0 match, 1 mismatch, 2 the parse itself failed.
#include "progdump.h"
#include "srcprep.h"
#include "../src/parseembed.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: pardiff <file.z> <golden.dump>" << std::endl;
        return 1;
    }
    const std::string file = argv[1];
    const std::string goldenPath = argv[2];

    std::ifstream gf(goldenPath, std::ios::binary);
    if (!gf) {
        std::cerr << "pardiff: cannot read " << goldenPath << std::endl;
        return 1;
    }
    std::ostringstream gss;
    gss << gf.rdbuf();
    const std::string golden = gss.str();

    std::string source = srcprep::prepare(file);

    Program prog;
    std::string msg;
    long long line = 0;
    int rc = parseZ(source, prog, msg, line);
    if (rc != 0) {
        std::cerr << file << ": parseZ rc=" << rc << " line=" << line
                  << ": " << msg << std::endl;
        return 2;
    }

    std::string actual;
    progdump::dump(prog, actual);

    if (actual == golden) return 0;

    // Report the first divergence with a little context instead of dumping
    // both files: the dumps run to hundreds of kilobytes.
    std::istringstream a(actual), g(golden);
    std::string al, gl;
    int n = 0, first = 0;
    while (true) {
        bool haveA = (bool)std::getline(a, al);
        bool haveG = (bool)std::getline(g, gl);
        n++;
        if (!haveA && !haveG) break;
        if (!haveA || !haveG || al != gl) {
            first = n;
            break;
        }
    }
    if (first == 0) first = n;
    std::cerr << file << ": golden mismatch at line " << first << "\n"
              << "  golden: " << gl << "\n"
              << "  actual: " << al << std::endl;
    return 1;
}
