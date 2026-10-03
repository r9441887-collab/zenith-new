#pragma once
#include "ast.h"
#include <functional>
#include <string>
#include <vector>

// Optional per-line file resolver for multi-file builds (combined line ->
// original file name). Used so findings point at the real source file.
using BugLineFileFn = std::function<std::string(int)>;

// Statically scans `prog` for bug patterns and appends one
// "Warning: <file>:<line>: [ZT-BUGxxx] ..." line per finding to `warnings`.
// Returns the number of findings added (duplicates are dropped).
int runBugFind(const Program& prog, const std::string& fileName,
               std::vector<std::string>& warnings,
               const BugLineFileFn& fileForLine = nullptr);
