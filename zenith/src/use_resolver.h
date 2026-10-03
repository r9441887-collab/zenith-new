#pragma once
#include <set>
#include <string>

// Expands `use <module>` lines in Zenith source by splicing the module's
// source in place of the directive.
//
// A module is resolved against the `include/` directory next to the
// compiler, then next to the including file, and finally relative to the
// including file itself. That order lets a project shadow a std module with
// its own version.
//
// The module file is chosen by app type: `include/<app>/<module>.z` is
// preferred over `include/<module>.z`, so the same `use std` line picks the
// console, gui, efi, ... implementation automatically. This is what makes
// the standard library per-target while the call sites stay identical.
//
// Splicing happens before lexing, so a module is ordinary Zenith source and
// may itself contain `use` lines (included files are tracked to break
// include cycles).
//
// `seenModules` is optional and lets a caller compile several files as one
// program: a module already spliced by an earlier file is dropped instead of
// being spliced a second time, which would define its functions twice. Pass
// the same set to every call for one build. Empty by default, so the
// single-file path keeps its own behaviour.
//
// `errorOut` receives a human-readable message when a module cannot be
// found; the caller decides how to report it. Returns false on failure.
bool expandUseDirectives(std::string& source,
                         const std::string& baseDir,
                         const std::string& appType,
                         std::string& errorOut,
                         std::set<std::string>* seenModules = nullptr);
