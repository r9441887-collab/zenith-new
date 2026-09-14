#include "codegen.h"
#include "ast.h"

// =====================================================================
// Sound builtins — real PCM synthesis (8/16/24-bit) + waveOut playback.
//
// Two kinds of code generation are used here:
//
//   1. Synthesis (sound_gen / sound_mix).  Pure register code, no OS
//      calls.  The per-call site only stages its arguments and emits a
//      `call` into a position-independent helper routine that is emitted
//      once per program (exactly like the httpJson helper).  The helper
//      uses only Win64 volatile registers and preserves nothing, so the
//      call site needs no callee-saved pushes at all.
//
//   2. Playback (sound_open / sound_play / sound_busy / sound_wait /
//      sound_stop / sound_close).  Real calls into winmm.dll waveOut,
//      staged like the net_* handlers: values that must survive the
//      external calls live in callee-saved rdi/rsi/r12.
//
// Available builtins (Windows PE, `app console` and `app gui`):
//   sound_gen(buf, samples, rate, bits, wave, freq, vol)  -> 0
//       Generates `samples` PCM samples into `buf`.  bits 8|16|24.
//       wave 0=sin 1=square 2=triangle 3=saw 4=noise.
//       vol 0..100 (% of full scale).  freq 0 = silence.
//       The buffer must hold samples*bits/8 bytes.
//   sound_mix(target, src, samples)                      -> 0
//       16-bit layering for track composing: target[i] = target[i]+src[i]
//       with hard clipping.  target and src hold int16 samples.
//   sound_open(rate, bits, channels)                     -> handle|-1
//       Opens the default waveOut device with a real WAVEFORMATEX.
//   sound_play(handle, buf, samples)                     -> 0|-1|-2
//       Queues one buffer with waveOutWrite() (non-blocking).  -2 = a
//       previous buffer is still playing — call sound_wait() first, or
//       use several buffers.  The buffer must stay alive until done
//       (a global or alloc()'d array).
//   sound_busy(handle)                                   -> 1|0
//       1 while a queued buffer is still playing (polls WHDR_DONE).
//   sound_wait(handle)                                   -> 0
//       Blocks until playback of the queued buffer finishes.
//   sound_stop(handle)                                   -> 0
//       waveOutReset() — drops any pending playback immediately.
//   sound_close(handle)                                  -> 0
//       waveOutReset + waveOutUnprepareHeader + waveOutClose.
// =====================================================================

// ------------------------- use detection -------------------------

void Codegen::detectSoundExprUsage(Expr* expr) {
    if (!expr) return;
    if (auto call = dynamic_cast<CallExpr*>(expr)) {
        if (call->name.rfind("sound_", 0) == 0) soundUsed = true;
        for (auto& arg : call->args) detectSoundExprUsage(arg.get());
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(expr)) {
        detectSoundExprUsage(bin->left.get());
        detectSoundExprUsage(bin->right.get());
    } else if (auto memb = dynamic_cast<MemberExpr*>(expr)) {
        detectSoundExprUsage(memb->object.get());
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(expr)) {
        detectSoundExprUsage(arr->array.get());
        detectSoundExprUsage(arr->index.get());
    }
}

void Codegen::detectSoundStmtUsage(Stmt* stmt) {
    if (!stmt) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(stmt)) {
        detectSoundExprUsage(ret->value.get());
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(stmt)) {
        detectSoundExprUsage(exprStmt->expr.get());
    } else if (auto assign = dynamic_cast<AssignStmt*>(stmt)) {
        detectSoundExprUsage(assign->indexExpr.get());
        detectSoundExprUsage(assign->value.get());
    } else if (auto varDecl = dynamic_cast<VarDecl*>(stmt)) {
        detectSoundExprUsage(varDecl->init.get());
    } else if (auto ifs = dynamic_cast<IfStmt*>(stmt)) {
        detectSoundExprUsage(ifs->condition.get());
        for (auto& s : ifs->thenBlock.stmts) detectSoundStmtUsage(s.get());
        for (auto& s : ifs->elseBlock.stmts) detectSoundStmtUsage(s.get());
    } else if (auto wh = dynamic_cast<WhileStmt*>(stmt)) {
        detectSoundExprUsage(wh->condition.get());
        for (auto& s : wh->body.stmts) detectSoundStmtUsage(s.get());
    } else if (auto loop = dynamic_cast<LoopStmt*>(stmt)) {
        for (auto& s : loop->body.stmts) detectSoundStmtUsage(s.get());
    } else if (auto sw = dynamic_cast<SwitchStmt*>(stmt)) {
        detectSoundExprUsage(sw->condition.get());
        for (auto& sc : sw->cases) {
            detectSoundExprUsage(sc.condition.get());
            for (auto& s : sc.body.stmts) detectSoundStmtUsage(s.get());
        }
    } else if (auto fs = dynamic_cast<ForStmt*>(stmt)) {
        detectSoundExprUsage(fs->start.get());
        detectSoundExprUsage(fs->end.get());
        if (fs->step) detectSoundExprUsage(fs->step.get());
        for (auto& s : fs->body.stmts) detectSoundStmtUsage(s.get());
    }
}

void Codegen::detectSoundUsage() {
    if (!soundUsed) {
        for (auto& func : prog.functions) {
            if (func->isExtern) continue;
            for (auto& stmt : func->body.stmts) detectSoundStmtUsage(stmt.get());
            if (soundUsed) break;
        }
    }
    for (auto& g : prog.globals) {
        if (g->init) detectSoundExprUsage(g->init.get());
        if (soundUsed) break;
    }
}

// ---------------------------------------------------------------------
// The sound_gen helper.  Emitted once into .text; every sound_gen call
// site is a `call` into it.  Position independent: all slot references
// are RIP-relative lea/movsx with displacements patched by buildPE from
// soundFixups.
//
// ABI (Win64-volatile registers only):
//   rdi = buf, rsi = sampleCount, rdx = rate, rcx = bits (8/16/24),
//   r8  = wave (0..4), r9 = freq, r10 = vol (0..100)
// Returns 0 in eax.  Clobbers only volatile registers.
// ---------------------------------------------------------------------
void Codegen::emitSoundGenHelper() {
    int ret = newLabel();

    // samples <= 0 -> ret 0
    emit8(0x48); emit8(0x85); emit8(0xF6);      // test rsi, rsi
    emit8(0x0F); emit8(0x8E); jmpFixups.push_back({code.size(), ret}); emit32(0);  // jle ret

    // freq == 0 -> silent fill
    int silent = newLabel();
    emit8(0x45); emit8(0x85); emit8(0xC9);      // test r9d, r9d (freq)
    emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), silent}); emit32(0);  // jz silent

    // r9d = phase step = (freq * (512 << 16)) / rate
    emit8(0x4C); emit8(0x89); emit8(0xC8);      // mov rax, r9 (freq)
    emit8(0x48); emit8(0x69); emit8(0xC0); emit32(0x02000000);  // imul rax, rax, 512<<16
    emit8(0x4B); emit8(0x89); emit8(0xD3);      // mov r11, rdx (rate)
    emit8(0x31); emit8(0xD2);                   // xor edx, edx
    emit8(0x49); emit8(0xF7); emit8(0xF3);      // div r11
    emit8(0x41); emit8(0x89); emit8(0xC1);      // mov r9d, eax (step)

    // Dispatch on bit depth into three regions (8/16/24). Default = 24.
    int bits8 = newLabel(), bits16 = newLabel(), bits24 = newLabel();
    emit8(0x83); emit8(0xF9); emit8(8);         // cmp ecx, 8
    emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), bits8}); emit32(0);
    emit8(0x83); emit8(0xF9); emit8(16);        // cmp ecx, 16
    emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), bits16}); emit32(0);
    emitJmp(bits24);

    auto emitAddrLut  = [&] { emit8(0x4C); emit8(0x8D); emit8(0x1D); soundFixups.push_back({code.size(), SND_LUT}); emit32(0); };   // lea r11, &LUT
    auto emitAddrSeed = [&] { emit8(0x4C); emit8(0x8D); emit8(0x1D); soundFixups.push_back({code.size(), SND_SEED}); emit32(0); };  // lea r11, &SEED
    auto emitVolScale = [&] {
        emit8(0x41); emit8(0x0F); emit8(0xAF); emit8(0xC2);  // imul eax, r10d (vol)
        emit8(0x99);                                        // cdq
        emit8(0xB9); emit32(100);                           // mov ecx, 100
        emit8(0xF7); emit8(0xF9);                           // idiv ecx
    };
    auto emitIndex    = [&] {                                // ecx = (r8d >> 16) & 511
        emit8(0x41); emit8(0x8B); emit8(0xC8);              // mov ecx, r8d
        emit8(0xC1); emit8(0xE9); emit8(16);                // shr ecx, 16
        emit8(0x81); emit8(0xE1); emit32(511);              // and ecx, 511
    };

    // One self-contained loop per (bits, wave).  Wave dispatch happens at
    // runtime inside each bits region: 0=sin, 1=square, 2=triangle,
    // 3=saw, 4=noise.  Phase accumulator r8d advances by r9d each sample.
    auto emitWaveSeg = [&](int bpc, int wave, int entry) {
        int head = newLabel();
        int sqPlus = newLabel();
        emitLabel(entry);
        if (wave == 0 || wave == 2 || wave == 3) emitAddrLut();
        else if (wave == 4) emitAddrSeed();
        if (wave != 4) emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d (phase)
        emitLabel(head);

        // ---- waveform shape into eax [-32768..32767] ----
        if (wave == 0) {   // sine via 512-entry LUT
            emitIndex();
            emit8(0x49); emit8(0x0F); emit8(0xBF); emit8(0x04); emit8(0x4B);  // movsx eax, word [r11+rcx*2]
        } else if (wave == 1) {  // square (+peak / -peak)
            emitIndex();
            emit8(0xB8); emit32(32767);                 // mov eax, 32767
            emit8(0x81); emit8(0xF9); emit32(256);      // cmp ecx, 256
            emit8(0x0F); emit8(0x8C); jmpFixups.push_back({code.size(), sqPlus}); emit32(0);  // jl sqPlus
            emit8(0xB8); emit32((uint32_t)-32767);      // mov eax, -32767
            emitLabel(sqPlus);
        } else if (wave == 2) {  // triangle +peak..-peak..+peak
            emitIndex();
            emit8(0xB8); emit32(511);                   // mov eax, 511
            emit8(0x29); emit8(0xC8);                   // sub eax, ecx
            emit8(0x81); emit8(0xF9); emit32(256);      // cmp ecx, 256
            emit8(0x0F); emit8(0x4C); emit8(0xC1);      // cmovl eax, ecx  -> t in [0..255]
            emit8(0x01); emit8(0xC0);                   // add eax, eax (2t)
            emit8(0xB9); emit32(256);                   // mov ecx, 256
            emit8(0x29); emit8(0xC1);                   // sub ecx, eax (256-2t)
            emit8(0xC1); emit8(0xE1); emit8(7);         // shl ecx, 7
            emit8(0x89); emit8(0xC8);                   // mov eax, ecx
        } else if (wave == 3) {  // saw +peak..-peak
            emitIndex();
            emit8(0x8D); emit8(0x04); emit8(0x09);      // lea eax, [rcx+rcx]
            emit8(0xB9); emit32(512);                   // mov ecx, 512
            emit8(0x29); emit8(0xC1);                   // sub ecx, eax (512-2i)
            emit8(0xC1); emit8(0xE1); emit8(6);         // shl ecx, 6
            emit8(0x89); emit8(0xC8);                   // mov eax, ecx
        } else {  // wave == 4: noise via inline LCG
            emit8(0x41); emit8(0x8B); emit8(0x03);       // mov eax, [r11] (seed)
            emit8(0x69); emit8(0xC0); emit32(1103515245);  // imul eax, eax, LCG_A
            emit8(0x05); emit32(12345);                 // add eax, 12345
            emit8(0x41); emit8(0x89); emit8(0x03);       // mov [r11], eax (keep seed)
            emit8(0xC1); emit8(0xE8); emit8(16);        // shr eax, 16
            emit8(0xB9); emit32(32767);                 // mov ecx, 32767
            emit8(0x29); emit8(0xC1);                   // sub ecx, eax
            emit8(0x89); emit8(0xC8);                   // mov eax, ecx
        }

        // ---- apply volume: eax = (eax * vol) / 100 ----
        emitVolScale();

        // ---- phase advances for the pitched waves ----
        if (wave != 4) emit8(0x45); emit8(0x01); emit8(0xC8);  // add r8d, r9d (step, preserved)

        // ---- store bpc bytes and loop ----
        if (bpc == 1) {
            emit8(0xC1); emit8(0xF8); emit8(8);         // sar eax, 8
            emit8(0x05); emit32(128);                   // add eax, 128 (unsigned 8-bit offset)
            emit8(0x88); emit8(0x07);                   // mov byte [rdi], al
            emit8(0x48); emit8(0x83); emit8(0xC7); emit8(1);  // add rdi, 1
        } else if (bpc == 2) {
            emit8(0x66); emit8(0x89); emit8(0x07);      // mov word [rdi], ax
            emit8(0x48); emit8(0x83); emit8(0xC7); emit8(2);  // add rdi, 2
        } else {
            emit8(0x66); emit8(0x89); emit8(0x07);      // mov word [rdi], ax
            emit8(0xC1); emit8(0xE8); emit8(16);        // shr eax, 16
            emit8(0x88); emit8(0x47); emit8(0x02);      // mov byte [rdi+2], al
            emit8(0x48); emit8(0x83); emit8(0xC7); emit8(3);  // add rdi, 3
        }
        emit8(0x48); emit8(0xFF); emit8(0xCE);          // dec rsi
        emit8(0x0F); emit8(0x85); jmpFixups.push_back({code.size(), head}); emit32(0);  // jnz head
        emitJmp(ret);
    };

    // Emit a (bits, wave) dispatch into five segment labels and then the
    // segment bodies themselves.
    auto emitBitsRegion = [&](int bpc, int regionLabel) {
        int e0 = newLabel(), e1 = newLabel(), e2 = newLabel(), e3 = newLabel(), e4 = newLabel();
        emitLabel(regionLabel);
        emit8(0x41); emit8(0x83); emit8(0xF8); emit8(0);
        emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), e0}); emit32(0);
        emit8(0x41); emit8(0x83); emit8(0xF8); emit8(1);
        emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), e1}); emit32(0);
        emit8(0x41); emit8(0x83); emit8(0xF8); emit8(2);
        emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), e2}); emit32(0);
        emit8(0x41); emit8(0x83); emit8(0xF8); emit8(3);
        emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), e3}); emit32(0);
        emitJmp(e4);
        emitWaveSeg(bpc, 0, e0);
        emitWaveSeg(bpc, 1, e1);
        emitWaveSeg(bpc, 2, e2);
        emitWaveSeg(bpc, 3, e3);
        emitWaveSeg(bpc, 4, e4);
    };

    emitBitsRegion(1, bits8);
    emitBitsRegion(2, bits16);
    emitBitsRegion(3, bits24);

    // ---------- silent fill (freq == 0) ----------
    emitLabel(silent);
    int sil8 = newLabel(), sil16 = newLabel(), sil24 = newLabel();
    emit8(0x83); emit8(0xF9); emit8(8);
    emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), sil8}); emit32(0);
    emit8(0x83); emit8(0xF9); emit8(16);
    emit8(0x0F); emit8(0x84); jmpFixups.push_back({code.size(), sil16}); emit32(0);
    emitJmp(sil24);
    {
        int h = newLabel();
        emitLabel(sil8);
        emitLabel(h);
        emit8(0xC6); emit8(0x07); emit8(0x00);               // mov byte [rdi], 0
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(1);
        emit8(0x48); emit8(0xFF); emit8(0xCE);               // dec rsi
        emit8(0x0F); emit8(0x85); jmpFixups.push_back({code.size(), h}); emit32(0);
        emitJmp(ret);
    }
    {
        int h = newLabel();
        emitLabel(sil16);
        emitLabel(h);
        emit8(0x66); emit8(0xC7); emit8(0x07); emit16(0);    // mov word [rdi], 0
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(2);
        emit8(0x48); emit8(0xFF); emit8(0xCE);
        emit8(0x0F); emit8(0x85); jmpFixups.push_back({code.size(), h}); emit32(0);
        emitJmp(ret);
    }
    {
        int h = newLabel();
        emitLabel(sil24);
        emitLabel(h);
        emit8(0x66); emit8(0xC7); emit8(0x07); emit16(0);    // mov word [rdi], 0
        emit8(0xC6); emit8(0x47); emit8(0x02); emit8(0x00);  // mov byte [rdi+2], 0
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(3);
        emit8(0x48); emit8(0xFF); emit8(0xCE);
        emit8(0x0F); emit8(0x85); jmpFixups.push_back({code.size(), h}); emit32(0);
        emitJmp(ret);
    }

    emitLabel(ret);
    emit8(0x31); emit8(0xC0);   // xor eax, eax
    emit8(0xC3);                // ret
}

// ---------------------------------------------------------------------
// The sound_mix helper.  16-bit additive mix with hard clipping:
// target[i] += src[i]  ->  clip to [-32768, 32767].
// ABI: rdi = target, rsi = src, rdx = sampleCount.  Returns 0 in eax.
// ---------------------------------------------------------------------
void Codegen::emitSoundMixHelper() {
    int ret = newLabel(), head = newLabel(), hiOk = newLabel(), loOk = newLabel();

    emit8(0x48); emit8(0x85); emit8(0xD2);      // test rdx, rdx
    emit8(0x0F); emit8(0x8E); jmpFixups.push_back({code.size(), ret}); emit32(0);  // jle ret

    emitLabel(head);
    emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0x06);  // movsx eax, word [rsi]
    emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0x0F);  // movsx ecx, word [rdi]
    emit8(0x01); emit8(0xC8);                            // add eax, ecx
    emit8(0x3D); emit32(32767);                          // cmp eax, 32767
    emit8(0x0F); emit8(0x8E); jmpFixups.push_back({code.size(), hiOk}); emit32(0);  // jle hiOk
    emit8(0xB8); emit32(32767);                          // mov eax, 32767
    emitLabel(hiOk);
    emit8(0x3D); emit32((uint32_t)-32768);               // cmp eax, -32768
    emit8(0x0F); emit8(0x8D); jmpFixups.push_back({code.size(), loOk}); emit32(0);  // jge loOk
    emit8(0xB8); emit32((uint32_t)-32768);               // mov eax, -32768
    emitLabel(loOk);
    emit8(0x66); emit8(0x89); emit8(0x07);               // mov word [rdi], ax
    emit8(0x48); emit8(0x83); emit8(0xC6); emit8(2);     // add rsi, 2
    emit8(0x48); emit8(0x83); emit8(0xC7); emit8(2);     // add rdi, 2
    emit8(0x48); emit8(0xFF); emit8(0xCA);               // dec rdx
    emit8(0x0F); emit8(0x85); jmpFixups.push_back({code.size(), head}); emit32(0);  // jnz head

    emitLabel(ret);
    emit8(0x31); emit8(0xC0);                            // xor eax, eax
    emit8(0xC3);                                         // ret
}

// ---------------------------------------------------------------------
// trySoundCall — dispatch for all sound_* builtins.
// ---------------------------------------------------------------------
bool Codegen::trySoundCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isSynth = (name == "sound_gen" || name == "sound_mix");
    const bool isMm = (name == "sound_open" || name == "sound_play" || name == "sound_busy" ||
                       name == "sound_wait" || name == "sound_stop" || name == "sound_close");
    if (!isSynth && !isMm) return false;

    // Arity guards (mis-sized calls fall through to the generic dispatch).
    if (name == "sound_gen" && call->args.size() != 7) return false;
    if (name == "sound_mix" && call->args.size() != 3) return false;
    if (name == "sound_open" && call->args.size() != 3) return false;
    if (name == "sound_play" && call->args.size() != 3) return false;
    if ((name == "sound_busy" || name == "sound_wait" || name == "sound_stop" ||
         name == "sound_close") && call->args.size() != 1) return false;

    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    // Guard the allocator-backed staging registers after we move a value
    // into them so later argument expressions cannot clobber them.
    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7 ||
            wantReg == 1 || wantReg == 2) regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };
    // mov r12, regX  (49 89 C4 | X<<3), and the same for r8/r9/r10.
    auto movToR12 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC4 | (src << 3)));
    };
    auto movToR8 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC0 | (src << 3)));
    };
    auto movToR9 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC1 | (src << 3)));
    };
    auto movToR10 = [&](int src) {
        emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC2 | (src << 3)));
    };
    // push rdi / push rsi / push r12 — the handlers that call real DLL
    // functions follow the net_* convention exactly.
    auto pushCalleeSaved = [&] { emit8(0x57); emit8(0x56); emit8(0x41); emit8(0x54); };
    auto popCalleeSaved = [&] { emit8(0x41); emit8(0x5C); emit8(0x5E); emit8(0x5F); };

    auto importCall = [&](const char* func, const char* dll) {
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), func, dll});
        emit32(0);
    };

    int soundExit = newLabel();

    // ================= sound_gen(buf, samples, rate, bits, wave, freq, vol) =================
    if (name == "sound_gen" && call->args.size() == 7) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // buf -> rdi
        freeReg(a0); guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // samples -> rsi
        freeReg(a1); guard(6);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 2) emitMovReg(2, a2);               // rate -> rdx
        freeReg(a2); guard(2);
        int a3 = emitExpr(call->args[3].get());
        if (a3 != 1) emitMovReg(1, a3);               // bits -> rcx
        freeReg(a3); guard(1);
        int a4 = emitExpr(call->args[4].get());
        movToR8(a4);                                  // wave -> r8
        freeReg(a4);
        int a5 = emitExpr(call->args[5].get());
        movToR9(a5);                                  // freq -> r9
        freeReg(a5);
        int a6 = emitExpr(call->args[6].get());
        movToR10(a6);                                 // vol -> r10
        freeReg(a6);

        if (!soundGenHelperEmitted) {
            soundGenHelperEmitted = true;
            soundGenHelperLabel = newLabel();
            int afterHelper = newLabel();
            emitJmp(afterHelper);                     // never fall into the body
            emitLabel(soundGenHelperLabel);
            emitSoundGenHelper();
            emitLabel(afterHelper);
        }
        emit8(0xE8);                                  // call soundGenHelper
        jmpFixups.push_back({code.size(), soundGenHelperLabel});
        emit32(0);
        emitJmp(done);
        emitLabel(done);
        emitJmp(soundExit);
    }

    // ================= sound_mix(target, src, samples) =================
    if (name == "sound_mix" && call->args.size() == 3) {
        int done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // target -> rdi
        freeReg(a0); guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // src -> rsi
        freeReg(a1); guard(6);
        int a2 = emitExpr(call->args[2].get());
        if (a2 != 2) emitMovReg(2, a2);               // count -> rdx
        freeReg(a2); guard(2);

        if (!soundMixHelperEmitted) {
            soundMixHelperEmitted = true;
            soundMixHelperLabel = newLabel();
            int afterHelper = newLabel();
            emitJmp(afterHelper);
            emitLabel(soundMixHelperLabel);
            emitSoundMixHelper();
            emitLabel(afterHelper);
        }
        emit8(0xE8);                                  // call soundMixHelper
        jmpFixups.push_back({code.size(), soundMixHelperLabel});
        emit32(0);
        emitJmp(done);
        emitLabel(done);
        emitJmp(soundExit);
    }

    // ================= sound_open(rate, bits, channels) -> handle|-1 =================
    if (name == "sound_open" && call->args.size() == 3) {
        int done = newLabel();
        int already = newLabel(), openFail = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);               // rate -> rdi
        freeReg(a0); guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // bits -> rsi
        freeReg(a1); guard(6);
        int a2 = emitExpr(call->args[2].get());
        movToR12(a2);                                 // channels -> r12
        freeReg(a2);

        // Already open? reuse the handle.
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);        // cmp dword [rax], 0
        emitJcc("!=", already);

        // Build WAVEFORMATEX in .data.  rbx is a free volatile temp here
        // (no import calls happen until after this block), so it holds the
        // format pointer across the field stores.
        emit8(0x48); emit8(0x8D); emit8(0x1D); soundFixups.push_back({code.size(), SND_FMT}); emit32(0);
        emit8(0x66); emit8(0xC7); emit8(0x03); emit16(1);   // word [rbx] = WAVE_FORMAT_PCM
        emit8(0x66); emit8(0x44); emit8(0x89); emit8(0x63); emit8(0x02);  // word [rbx+2] = r12w (channels)
        emit8(0x89); emit8(0x7B); emit8(0x04);        // dword [rbx+4] = edi (rate)
        emit8(0x8B); emit8(0xCE);                     // mov ecx, esi (bits)
        emit8(0xC1); emit8(0xE9); emit8(0x03);        // shr ecx, 3 (bits/8)
        emit8(0x41); emit8(0x0F); emit8(0xAF); emit8(0xCC);  // imul ecx, r12d (bytes/frame)
        emit8(0x48); emit8(0x8D); emit8(0x15); soundFixups.push_back({code.size(), SND_BPF}); emit32(0);
        emit8(0x89); emit8(0x0A);                     // dword [rdx] = bpf
        emit8(0x8B); emit8(0xC7);                     // mov eax, edi (rate)
        emit8(0x0F); emit8(0xAF); emit8(0xC1);        // imul eax, ecx
        emit8(0x89); emit8(0x43); emit8(0x08);        // dword [rbx+8] = nAvgBytesPerSec
        emit8(0x66); emit8(0x89); emit8(0x4B); emit8(0x0C);  // word [rbx+12] = cx (nBlockAlign)
        emit8(0x66); emit8(0x89); emit8(0x73); emit8(0x0E);  // word [rbx+14] = si (wBitsPerSample)
        emit8(0x66); emit8(0xC7); emit8(0x43); emit8(0x10); emit16(0);  // word [rbx+16] = 0 (cbSize)

        // waveOutOpen(&SND_HWO, WAVE_MAPPER(-1), &SND_FMT, 0, 0, 0)
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0xBA); emit32(0xFFFFFFFF);              // edx = -1 (WAVE_MAPPER)
        emit8(0x4C); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_FMT}); emit32(0);
        emit8(0x45); emit8(0x31); emit8(0xC9);        // xor r9d, r9d (null callback)
        emit8(0x4C); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x20);  // [rsp+0x20] = 0
        emit8(0x4C); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x28);  // [rsp+0x28] = 0
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38);
        importCall("waveOutOpen", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38);
        emit8(0x85); emit8(0xC0);                     // test eax (=MMRESULT)
        emitJcc("!=", openFail);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0xC7); emit8(0x00); emit32(1);          // dword [opened] = 1
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x00);        // rax = handle
        emitJmp(done);
        emitLabel(openFail);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(already);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emitJmp(done);
        emitLabel(done);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= sound_play(handle, buf, samples) -> 0|-1|-2 =================
    if (name == "sound_play" && call->args.size() == 3) {
        int done = newLabel();
        int notOpened = newLabel(), busyLbl = newLabel(), playFail = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());       // handle (kept for API symmetry)
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0); guard(7);
        int a1 = emitExpr(call->args[1].get());
        if (a1 != 6) emitMovReg(6, a1);               // buf -> rsi
        freeReg(a1); guard(6);
        int a2 = emitExpr(call->args[2].get());
        movToR12(a2);                                 // samples -> r12
        freeReg(a2);

        // Must be open.
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);
        emitJcc("==", notOpened);
        // Must not be busy: WHDR_DONE must already be set on the header.
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x8B); emit8(0x40); emit8(0x18);        // mov eax, [rax+24] (dwFlags)
        emit8(0xA8); emit8(0x01);                     // test al, WHDR_DONE
        emitJcc("==", busyLbl);
        // Fill header: lpData = buf; dwBufferLength = samples * bpf.
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x30);        // mov [rax], rsi (lpData)
        emit8(0x4C); emit8(0x8D); emit8(0x1D); soundFixups.push_back({code.size(), SND_BPF}); emit32(0);
        emit8(0x41); emit8(0x8B); emit8(0xCC);        // mov ecx, r12d (samples)
        emit8(0x41); emit8(0x0F); emit8(0xAF); emit8(0x0B);  // imul ecx, dword [r11] (bpf)
        emit8(0x89); emit8(0x48); emit8(0x08);        // dword [rax+8] = ecx (dwBufferLength)
        emit8(0xC7); emit8(0x40); emit8(0x0C); emit32(0);   // dword [rax+12] = 0
        emit8(0xC7); emit8(0x40); emit8(0x18); emit32(0);   // dword [rax+24] = 0 (flags)
        // waveOutPrepareHeader(hwo, &hdr, sizeof(WAVEHDR))
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);        // mov rcx, [rcx] (hwo)
        emit8(0x48); emit8(0x8D); emit8(0x15); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x41); emit8(0xB8); emit32(48);         // r8d = sizeof(WAVEHDR)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutPrepareHeader", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", playFail);
        // waveOutWrite(hwo, &hdr, sizeof(WAVEHDR))  — async
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x8D); emit8(0x15); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x41); emit8(0xB8); emit32(48);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutWrite", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", playFail);
        emit8(0x31); emit8(0xC0);                     // 0 = queued OK
        emitJmp(done);
        emitLabel(playFail);
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x8D); emit8(0x15); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x41); emit8(0xB8); emit32(48);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutUnprepareHeader", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(busyLbl);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-2);
        emitJmp(done);
        emitLabel(notOpened);
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
        emitJmp(done);
        emitLabel(done);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= sound_busy(handle) -> 1|0 =================
    if (name == "sound_busy" && call->args.size() == 1) {
        int done = newLabel(), idleLbl = newLabel(), notOpened = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());
        freeReg(a0);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);
        emitJcc("==", notOpened);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x8B); emit8(0x40); emit8(0x18);        // dwFlags
        emit8(0xA8); emit8(0x01);                     // test al, WHDR_DONE
        emitJcc("!=", idleLbl);                       // WHDR_DONE set -> not busy
        emit8(0xB8); emit32(1);
        emitJmp(done);
        emitLabel(idleLbl);
        emit8(0x31); emit8(0xC0);
        emitJmp(done);
        emitLabel(notOpened);
        emit8(0x31); emit8(0xC0);
        emitJmp(done);
        emitLabel(done);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= sound_wait(handle) -> 0 (blocks) =================
    if (name == "sound_wait" && call->args.size() == 1) {
        int done = newLabel(), pollLbl = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());
        freeReg(a0);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);
        emitJcc("==", done);                          // never opened -> do nothing
        emitLabel(pollLbl);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x8B); emit8(0x40); emit8(0x18);        // dwFlags
        emit8(0xA8); emit8(0x01);
        emitJcc("!=", done);                          // WHDR_DONE -> finished
        emit8(0xB9); emit32(1);                       // Sleep(1)
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("Sleep", "kernel32.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitJmp(pollLbl);
        emitLabel(done);
        emit8(0x31); emit8(0xC0);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= sound_stop(handle) -> 0 (waveOutReset) =================
    if (name == "sound_stop" && call->args.size() == 1) {
        int done = newLabel(), skip = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());
        freeReg(a0);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);
        emitJcc("==", skip);
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutReset", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emitLabel(skip);
        emit8(0x31); emit8(0xC0);
        emitLabel(done);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= sound_close(handle) -> 0 =================
    if (name == "sound_close" && call->args.size() == 1) {
        int done = newLabel(), skip = newLabel();
        pushCalleeSaved();
        int a0 = emitExpr(call->args[0].get());
        freeReg(a0);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0x83); emit8(0x38); emit8(0x00);
        emitJcc("==", skip);
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutReset", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x8D); emit8(0x15); soundFixups.push_back({code.size(), SND_HDR}); emit32(0);
        emit8(0x41); emit8(0xB8); emit32(48);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutUnprepareHeader", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x0D); soundFixups.push_back({code.size(), SND_HWO}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x09);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
        importCall("waveOutClose", "winmm.dll");
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x05); soundFixups.push_back({code.size(), SND_OPENED}); emit32(0);
        emit8(0xC7); emit8(0x00); emit32(0);          // opened = 0
        emitLabel(skip);
        emit8(0x31); emit8(0xC0);
        emitLabel(done);
        popCalleeSaved();
        emitJmp(soundExit);
    }

    // ================= Common exit: restore the allocator view ================
    emitLabel(soundExit);
    // The result is in rax. Re-seat it in the register the allocator owns,
    // exactly like the net_* handlers and http_get do.
    regsUsed = 0;
    freeReg(1);
    freeReg(2);
    freeReg(3);
    int r = allocReg();
    if (r != 0) { emitMovReg(r, 0); freeReg(0); }
    regsUsed = (uint8_t)(saved & ~(1 << r));
    reloadRegs();
    regsUsed = (uint8_t)(saved | (1 << r));
    resultReg = r >= 0 ? r : 0;
    return true;
}