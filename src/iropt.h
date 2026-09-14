#pragma once
#include "ir.h"

// IROpt: optimizes the assembler-IR in place.
//
// Passes (in order):
//   1. Dead function elimination  (DFS from the entry point)
//   2. Block-local memory opts     (load-after-store, load CSE, store-store
//                                   dedup, copy propagation (transitive),
//                                   jump threading)
//   3. Constant propagation + folding + strength reduction
//      (incl. signed div/mod by const power of two -> shifts and non-pow2
//       small-const mul -> shift+add/sub, only with speed=true; the
//       sequences grow 3-6 instrs but avoid idiv/software div/mul)
//   4. Dead code elimination      (use-count based, iterated to fixpoint)
//   5. Dead branch elimination    (const-condition branches)
//   6. Unreachable-code removal   (kills straight-line bytes after Ret/Br/Exit
//                                  until the next Label, feeding DCE)
//   7. Slot compaction            (rebases slot ids, keeps multi-slot runs contiguous)
//   8. Slot reuse                 (liveness-based merge of non-overlapping ranges)
//   9. Global removal             (globals never referenced)
//  10. String pool pruning        (unreferenced pool entries dropped)
//
// Also folds (x & m1) & m2 -> x & m1 when m1's bits are a subset of m2's.
// Stats are written into IRProgram / IRFunction for the report.
struct IROpt {
    static void run(IRProgram& ir, bool speed = false);
};
