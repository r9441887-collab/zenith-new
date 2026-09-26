#include "use_resolver.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Trim leading whitespace so `use std` and `\tuse std` both match.
std::string ltrim(const std::string& s) {
    size_t i = s.find_first_not_of(" \t\r");
    return (i == std::string::npos) ? std::string() : s.substr(i);
}

std::string rtrim(const std::string& s) {
    size_t i = s.find_last_not_of(" \t\r");
    return (i == std::string::npos) ? std::string() : s.substr(0, i + 1);
}

bool readFileTo(const fs::path& p, std::string& out) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

// A module name may be given as a bare name (`std`) or as a path
// (`io/console`). A bare name maps to `<name>.z`.
std::string moduleFileName(const std::string& name) {
    std::string n = name;
    if (n.size() < 2 || n.substr(n.size() - 2) != ".z") n += ".z";
    return n;
}

}  // namespace

bool expandUseDirectives(std::string& source,
                         const std::string& baseDir,
                         const std::string& appType,
                         std::string& errorOut) {
    // Roots searched for a module, in priority order. The `include/` tree
    // holds the standard library, so it is searched alongside the including
    // file's own directory: a project can shadow a std module by shipping
    // its own `std.z` next to its sources.
    std::vector<fs::path> roots;
    if (!baseDir.empty()) roots.push_back(fs::path(baseDir));
    if (!baseDir.empty()) roots.push_back(fs::path(baseDir) / "include");
    roots.push_back(fs::path("include"));
    roots.push_back(fs::current_path());
    roots.push_back(fs::current_path() / "include");
    // The compiler binary may sit next to the sources (build/linux/zenith).
    {
        std::error_code ec;
        fs::path self = fs::read_symlink("/proc/self/exe", ec);
        if (!ec && self.has_parent_path()) {
            fs::path dir = self.parent_path();
            for (int up = 0; up < 3; up++) {
                roots.push_back(dir);
                roots.push_back(dir / "include");
                dir = dir.parent_path();
                if (dir.empty()) break;
            }
        }
    }

    // Guard against include cycles: a file already on the stack is an error.
    std::vector<fs::path> active;

    // Recursive worker. `src` is the text to rewrite; `dir` is the directory
    // the text came from, so relative module paths resolve next to it.
    std::function<bool(std::string&, const fs::path&, int)> expand =
        [&](std::string& src, const fs::path& dir, int depth) -> bool {
        if (depth > 32) {
            errorOut = "`use`: include nesting too deep (cycle?)";
            return false;
        }

        std::istringstream in(src);
        std::string line;
        std::string out;
        bool changed = false;

        while (std::getline(in, line)) {
            std::string t = ltrim(line);

            // Only a `use` at the start of a line is a directive. This keeps
            // `use` usable as an identifier elsewhere.
            if (t.rfind("use ", 0) == 0 || t == "use") {
                std::string name = rtrim(t.size() > 3 ? t.substr(4) : std::string());
                // Trim again: `use   std` leaves leading spaces behind.
                size_t s = name.find_first_not_of(" \t\r");
                name = (s == std::string::npos) ? std::string() : name.substr(s);
                // Strip a trailing comment.
                size_t c = name.find('#');
                if (c != std::string::npos) name = rtrim(name.substr(0, c));
                if (name.empty()) {
                    errorOut = "`use`: missing module name";
                    return false;
                }

                // Try, in order: <include>/<app>/<name>.z, <include>/<name>.z,
                // then the same two relative to the including file's dir.
                std::vector<fs::path> candidates;
                std::string file = moduleFileName(name);
                for (const fs::path& root : roots) {
                    if (!appType.empty()) candidates.push_back(root / appType / file);
                    candidates.push_back(root / file);
                }
                for (const fs::path& root : roots) {
                    if (!appType.empty()) candidates.push_back(dir / appType / file);
                    candidates.push_back(dir / file);
                }

                fs::path found;
                bool ok = false;
                for (const fs::path& c : candidates) {
                    std::error_code ec;
                    if (fs::is_regular_file(c, ec)) { found = c; ok = true; break; }
                }
                if (!ok) {
                    errorOut = "`use " + name + "`: module not found (looked for " +
                               file + " under " + (appType.empty() ? std::string("<no app>") : appType) + ")";
                    return false;
                }

                // Cycle check on the canonical path.
                std::error_code ec;
                fs::path canon = fs::weakly_canonical(found, ec);
                if (ec) canon = found;
                for (const fs::path& a : active) {
                    std::error_code ec2;
                    fs::path ca = fs::weakly_canonical(a, ec2);
                    if (ec2) ca = a;
                    if (ca == canon) {
                        errorOut = "`use " + name + "`: include cycle";
                        return false;
                    }
                }

                std::string modSrc;
                if (!readFileTo(found, modSrc)) {
                    errorOut = "`use " + name + "`: cannot read " + found.string();
                    return false;
                }

                // A module's own `app` directive would fight with the
                // including program's app type, so drop it: the including
                // file owns the target.
                std::istringstream min(modSrc);
                std::string mline;
                std::string cleaned;
                while (std::getline(min, mline)) {
                    std::string mt = ltrim(mline);
                    if (mt.rfind("app ", 0) == 0) continue;
                    if (!cleaned.empty()) cleaned += "\n";
                    cleaned += mline;
                }

                active.push_back(canon);
                fs::path modDir = found.parent_path();
                if (!expand(cleaned, modDir, depth + 1)) {
                    active.pop_back();
                    return false;
                }
                active.pop_back();

                if (!out.empty() || !changed) out += "\n";
                out += cleaned;
                if (out.empty() || out.back() != '\n') out += "\n";
                changed = true;
                continue;
            }

            if (!out.empty() || changed) out += "\n";
            out += line;
        }

        if (changed) src = out;
        return true;
    };

    return expand(source, fs::path(baseDir), 0);
}
