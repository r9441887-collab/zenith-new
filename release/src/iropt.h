#pragma once
#include "ir.h"

// IROpt: optimizes the assembler-IR in place.
//
// Passes (in order):
//   1. Dead function elimination  (DFS from the entry point)
//   2. Block-local memory opts     (load-after-store, load CSE, store-store
//                                   dedup, copy propagation, jump threading)
//   3. Constant propagation + folding + strength reduction
//      (incl. signed div/mod by const power of two -> shifts, only with
//       speed=true; the sequence grows 4-6 instrs but avoids the idiv)
//   4. Dead code elimination      (use-count based, iterated to fixpoint)
//   5. Dead branch elimination    (const-condition branches)
//   6. Slot compaction            (rebases slot ids, keeps multi-slot runs contiguous)
//   7. Slot reuse                 (liveness-based merge of non-overlapping ranges)
//   8. Global removal             (globals never referenced)
//   9. String pool pruning        (unreferenced pool entries dropped)
//
// Stats are written into IRProgram / IRFunction for the report.
struct IROpt {
    static void run(IRProgram& ir, bool speed = false);
};
