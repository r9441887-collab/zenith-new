#pragma once
#include "ir.h"
#include <string>
#include <vector>

// Statically scans the generated IR for bug patterns and appends one
// "Warning: IR <func>:<idx>: [ZT-IRxxx] ..." line per finding to `warnings`.
// Returns the number of findings added.
//
// Analysis: per-function CFG built from labels/branches, forward dataflow of
// constant facts (meet = intersection) over the reachable blocks. The
// fixpoint runs without checks; a final pass over the converged facts does
// the reporting, so transient constants never produce a warning.
int runBugFindIR(const IRProgram& prog, std::vector<std::string>& warnings);
