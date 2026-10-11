// Prints the exact text the compiler's single-file path hands to the front
// end (srcprep::prepare: read -> splice include -> expand use). Part of
// «часть 20»: tools/cgfront_check.py needs the spliced source both to feed
// the selfhost harness (parseRun does not expand `use`) and to prove the
// splice is the one the reference compiler used (byte-identical ELF).
//
//   build/linux/srcprep_dump selfhost/_astdrv.z > /tmp/spliced.z
#include "srcprep.h"
#include <cstdio>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: srcprep_dump <file.z>\n");
        return 2;
    }
    std::string src = srcprep::prepare(argv[1]);
    std::fwrite(src.data(), 1, src.size(), stdout);
    return 0;
}
