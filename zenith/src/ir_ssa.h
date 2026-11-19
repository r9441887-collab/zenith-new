#pragma once
#include "ir.h"

// IRSSA: full Static-Single-Assignment optimization pass.
//
// Runs on a single function's assembler-IR *after* the classic block-local
// passes (fold/DCE/dead-branch/unreachable) and *before* slot compaction.
// The pass is self-contained:
//
//   1. Build the CFG  (basic blocks from Label markers + branch terminators).
//   2. Dominator tree (iterative dataflow) + dominance frontiers.
//   3. Insert phi nodes and rename every register write to a fresh SSA version
//      (memory operands of kind Slot are left untouched).
//   4. SSA optimizations:
//        - constant propagation + folding (including trivial-phi folding),
//        - global value numbering (dominance-checked) for pure computations,
//        - dead code elimination in SSA form (uses are tracked per version),
//        - loop-invariant code motion (LICM) into natural-loop preheaders.
//   5. De-SSA: parallel-copy resolution on edges (critical edges are split;
//      self / redundant copies are dropped; cycles broken with a temp slot).
//   6. Rebuild the linear instruction list in original block order.
//
// Register slots in this IR are physical frame slots, so every SSA version of
// a slot v is later collapsed back to slot v by de-SSA: the only real copies
// emitted are the ones that move a value between *different* slots, which is
// exactly the result of value forwarding/hoisting. This keeps the backend
// (IRAsm) unchanged and makes de-SSA almost free.
struct IRSSA {
    // Optimize a function in place. Returns true when anything changed.
    static bool optimize(IRFunction& fn);
};