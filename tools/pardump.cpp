// pardump — the golden side of the front-end diff.
//
// Reads one .z file, runs the exact single-file preparation the compiler
// uses (srcprep), then the C++ front end (lexSource + Parser) and prints a
// deterministic textual dump of the resulting Program (tools/progdump.h).
//
// Run BEFORE the switch to parseZ: the two front ends cannot live in one
// binary (selfhost/parseobj.o carries the same lex*/zenith_obj_init symbols
// as tools/lexobj.o), so the golden dumps are frozen while the C++ front end
// is still the one linked in. tools/pardiff replays the same files through
// parseZ afterwards and diffs against selfhost/golden/*.dump.
//
// Exit codes: 0 = dumped, 2 = lexer error, 3 = parse error (message on
// stderr); either way the dump itself only ever goes to stdout on success.
#include "progdump.h"
#include "srcprep.h"
#include "../src/lexer.h"
#include "../src/parser.h"

#include <iostream>
#include <string>
#include <vector>

bool lexSource(const std::string& src, std::vector<Token>& out, std::string& err);

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: pardump <file.z>" << std::endl;
        return 2;
    }
    const std::string file = argv[1];
    std::string source = srcprep::prepare(file);

    std::vector<Token> tokens;
    std::string lexErr;
    if (!lexSource(source, tokens, lexErr)) {
        std::cerr << file << ": Lexer error: " << lexErr << std::endl;
        return 2;
    }
    for (auto& t : tokens) {
        if (t.kind == TokenKind::Error) {
            std::cerr << file << ": Lexer error at line " << t.line << ": " << t.text << std::endl;
            return 2;
        }
    }

    Program prog;
    try {
        Parser parser(tokens);
        prog = parser.parse();
    } catch (const std::exception& e) {
        std::cerr << file << ": Parser error: " << e.what() << std::endl;
        return 3;
    }

    std::string out;
    progdump::dump(prog, out);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}
