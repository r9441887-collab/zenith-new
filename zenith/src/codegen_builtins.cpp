#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include <iostream>
#include <cstring>
#include <algorithm>

using namespace std;

bool Codegen::tryBuiltinCall(CallExpr* call, int& resultReg) {
    if (call->name == "alloc" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sizeReg = emitExpr(call->args[0].get());
        if (sizeReg != 1) { emitMovReg(1, sizeReg); freeReg(sizeReg); sizeReg = 1; }
        // rcx = size
        // totalSize = ((size + 15) & ~15) + 16
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(15);  // add rcx, 15
        emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0); // and rcx, -16
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);  // add rcx, 16
        emit8(0x48); emit8(0x89); emit8(0xCB);  // mov rbx, rcx (save totalSize)

        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);  // rax = heapArea

        int bumpLabel = newLabel();
        int failLabel = newLabel();
        int doneLabel = newLabel();

        // Check free list
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);  // rdx = freeHead
        emit8(0x48); emit8(0x85); emit8(0xD2);  // test rdx, rdx
        emit8(0x0F); emit8(0x84);  // je bumpLabel
        jmpFixups.push_back({code.size(), bumpLabel}); emit32(0);

        emit8(0x48); emit8(0x8B); emit8(0x4A); emit8(8);  // mov rcx, [rdx+8] (blockSize)
        emit8(0x48); emit8(0x39); emit8(0xD9);  // cmp rcx, rbx
        emit8(0x0F); emit8(0x82);  // jb bumpLabel (blockSize < totalSize)
        jmpFixups.push_back({code.size(), bumpLabel}); emit32(0);

        // Use this free block — remove from free list
        emit8(0x48); emit8(0x8B); emit8(0x0A);  // mov rcx, [rdx] (nextFree)
        emit8(0x48); emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);  // freeHead = nextFree

        emit8(0x31); emit8(0xC9);  // xor ecx, ecx
        emit8(0x48); emit8(0x89); emit8(0x0A);  // mov [rdx], rcx (mark in-use)
        emit8(0x48); emit8(0x8D); emit8(0x42); emit8(0x10);  // lea rax, [rdx+16]
        emitJmp(doneLabel);

        // Bump allocate
        emitLabel(bumpLabel);
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);  // rdx = offset
        emit8(0x48); emit8(0x89); emit8(0xD1);  // mov rcx, rdx
        emit8(0x48); emit8(0x01); emit8(0xD9);  // add rcx, rbx (newOffset)
        emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
        emit8(0x0F); emit8(0x87);
        jmpFixups.push_back({code.size(), failLabel}); emit32(0);

        emit8(0x48); emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);  // store newOffset

        // Store totalSize at [heapArea + offset + 8]
        emit8(0x48); emit8(0x89); emit8(0x5C); emit8(0x10); emit8(8);  // mov [rax+rdx+8], rbx

        // Return heapArea + offset + 16
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16);  // lea rax, [rax+rdx+16]
        emitJmp(doneLabel);

        emitLabel(failLabel);
        emit8(0x48); emit8(0x31); emit8(0xC0);  // xor eax, eax
        emitLabel(doneLabel);
        freeReg(1); freeReg(2); freeReg(3);
        int r = allocReg(); if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }
    if (call->name == "free" && call->args.size() == 1) {
        int r = emitExpr(call->args[0].get());
        if (r != 1) { emitMovReg(1, r); freeReg(r); }
        regsUsed = 0;
        // rcx = ptr
        emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0);  // lea rax, [rcx-16] (blockStart)
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);  // rdx = old freeHead
        emit8(0x48); emit8(0x89); emit8(0x10);  // mov [rax], rdx (link to free list)
        emit8(0x48); emit8(0x89); emit8(0x05);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);  // freeHead = blockStart
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // ============== Arena Allocator Builtins ==============
    // Arena header: [capacity:8][used:8], data at handle+16

    auto emitHeapAlloc = [this](int sizeReg) {
        if (sizeReg != 1) { emitMovReg(1, sizeReg); freeReg(sizeReg); }
        // rcx = size
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(15);  // add rcx, 15
        emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0); // and rcx, -16
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);  // add rcx, 16 (header)
        // rcx = totalSize
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);  // rax = heapArea
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);  // rdx = offset
        emit8(0x49); emit8(0x89); emit8(0xC0); // r8 = rax (save heapArea)
        emit8(0x48); emit8(0x03); emit8(0xCA); // rcx = totalSize + offset = newOffset
        emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
        int fl = newLabel();
        emit8(0x0F); emit8(0x87); jmpFixups.push_back({code.size(), fl}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
        // rcx = newOffset, rdx = old_offset, r8 = heapArea
        emit8(0x48); emit8(0x29); emit8(0xD1); // sub rcx, rdx (totalSize = newOffset - oldOffset)
        emit8(0x49); emit8(0x89); emit8(0x4C); emit8(0x10); emit8(8); // mov [r8+rdx+8], rcx
        emit8(0x49); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [r8+rdx+16]
        int dl = newLabel(); emitJmp(dl);
        emitLabel(fl); emit8(0x48); emit8(0x31); emit8(0xC0); // xor rax, rax (fail=0)
        emitLabel(dl);
        freeReg(1); freeReg(2);
    };

    // arenaCreate(capacity) -> handle
    // Header: [capacity:8][used:8], data at handle+16
    if (call->name == "arenaCreate" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int capReg = emitExpr(call->args[0].get());
        // Save capacity in reg 3 (rbx) — safe across emitHeapAlloc
        if (capReg != 3) { emitMovReg(3, capReg); freeReg(capReg); }
        // rcx = capacity + 16 (total allocation size)
        emitMovReg(1, 3);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        emitHeapAlloc(1);  // rax = block pointer (or 0 on fail)
        // [rax+0] = capacity (from rbx)
        emitStoreQwordDisp8(3, 0, 0);
        // [rax+8] = 0 (used = 0)
        emitMovQwordDisp8Imm32(0, 8, 0);
        // rax = handle (return value)
        freeReg(3);
        int r = allocReg();
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

// arenaAlloc(arena, size) -> ptr
    // Header: [capacity:8][used:8], data at handle+16
    if (call->name == "arenaAlloc" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int aReg = emitExpr(call->args[0].get());
        int sReg = emitExpr(call->args[1].get());
        // Handle must be in rbx(3), size spilled to rcx(1); never live in rax
        if (aReg == 0) {
            if (sReg == 3) { emitMovReg(2, 3); sReg = 2; }
            emitMovReg(3, 0); aReg = 3;
        } else if (sReg == 3) {
            int tmp = (aReg == 1) ? 2 : 1;
            emitMovReg(tmp, 3); sReg = tmp;
            emitMovReg(3, aReg); freeReg(aReg); aReg = 3;
        } else if (sReg == 0) {
            int tmp = (aReg == 2) ? 1 : 2;
            emitMovReg(tmp, 0); sReg = tmp;
            if (aReg != 3) { emitMovReg(3, aReg); freeReg(aReg); }
            aReg = 3;
        } else {
            if (aReg != 3) { emitMovReg(3, aReg); freeReg(aReg); }
            aReg = 3;
        }
        // Force size into rcx(1) so rdx(2) is free for capacity
        if (sReg == 2) { emitMovReg(1, 2); sReg = 1; }

        int failLabel = newLabel();
        int doneLabel = newLabel();

        // Bounds check: rax = used[+8], rdx = capacity[+0]
        emitLoadQwordDisp8(2, 3, 0);   // rdx = [rbx+0] = capacity
        emitLoadQwordDisp8(0, 3, 8);   // rax = [rbx+8] = used
        emitAdd(0, sReg);              // rax = used + size (newUsed)
        // Guard 1: carry from (used + size) means overflow -> fail
        emit8(0x0F); emit8(0x82);      // jc rel32
        jmpFixups.push_back({code.size(), failLabel});
        emit32(0);
        // Guard 2: newUsed > capacity -> fail
        emit8(0x48); emit8(0x39); emit8(0xD0);  // cmp rax, rdx
        emit8(0x0F); emit8(0x87);      // ja rel32
        jmpFixups.push_back({code.size(), failLabel});
        emit32(0);

        // Success: [rbx+8] = newUsed, then rax = oldUsed + rbx + 16
        emitStoreQwordDisp8(0, 3, 8);              // [rbx+8] = newUsed
        emitSub(0, sReg);                          // rax -> oldUsed
        emitAdd(0, 3);                             // rax = oldUsed + handle
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(16); // rax += 16 (data offset)
        emitJmp(doneLabel);

        emitLabel(failLabel);
        emitMovRegImm(0, 0);   // return NULL
        emitLabel(doneLabel);

        freeReg(3); freeReg(1);
        regsUsed = 0;
        int r = allocReg();
        if (r < 0) r = 0;
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        // r now holds the result. Restore caller regs, but never reload r.
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r;
        return true;
    }

    // arenaReset(arena) -> void
    if (call->name == "arenaReset" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int a = emitExpr(call->args[0].get());
        emitMovQwordDisp8Imm32(a, 8, 0);
        freeReg(a);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // arenaDestroy(arena) -> void (free the arena block back to heap)
    if (call->name == "arenaDestroy" && call->args.size() == 1) {
        int r = emitExpr(call->args[0].get());
        if (r != 1) { emitMovReg(1, r); freeReg(r); }
        regsUsed = 0;
        emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0); // lea rax, [rcx-16] (blockStart)
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0); // rdx = old freeHead
        emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx (link to free list)
        emit8(0x48); emit8(0x89); emit8(0x05);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0); // freeHead = blockStart
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // ============== Pool Allocator Builtins ==============
    // Pool header: [blockSize:8][count:8][nextIdx:8][freeHead:8], data at handle+32
    // O(1) alloc from free list or nextIdx, poolFree recycles blocks, poolDestroy frees block to heap

    // poolCreate(blockSize, count) -> handle
    if (call->name == "poolCreate" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int bs = emitExpr(call->args[0].get());
        int cnt = emitExpr(call->args[1].get());
        if (bs != 3) { emitMovReg(3, bs); freeReg(bs); }
        if (cnt != 0) { emitMovReg(0, cnt); freeReg(cnt); }
        emit8(0x50); // push rax (count)
        emit8(0x58); // pop rcx (count in rcx)
        // rax = blockSize * count + 32
        emitMovReg(0, 3);
        emitImul(0, 1);  // rax *= rcx (count)
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emit8(0x51); // push rcx (count)
        emitHeapAlloc(0);  // rax = block pointer
        // Store header fields
        emitStoreQwordDisp8(3, 0, 0);  // [rax+0] = blockSize (rbx)
        emit8(0x59); // pop rcx (count)
        emitStoreQwordDisp8(1, 0, 8);  // [rax+8] = count (rcx)
        emitMovQwordDisp8Imm32(0, 16, 0); // [rax+16] = 0 (nextIdx)
        emitMovQwordDisp8Imm32(0, 24, -1); // [rax+24] = -1 (freeHead)
        freeReg(3);
        int r = allocReg();
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // poolAlloc(pool) -> ptr
    if (call->name == "poolAlloc" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pReg = emitExpr(call->args[0].get());
        if (pReg != 3) { emitMovReg(3, pReg); freeReg(pReg); }
        regsUsed |= (1 << 3);

        int freeListLabel = newLabel();
        int seqLabel = newLabel();
        int overflowLabel = newLabel();
        int doneLabel = newLabel();

        emitLoadQwordDisp8(0, 3, 24); // rax = freeHead
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8((uint8_t)(int8_t)-1); // cmp rax, -1
        emitJcc("!=", freeListLabel);
        emitJmp(seqLabel);

        emitLabel(freeListLabel);
        emit8(0x50); // push rax (idx)
        regsUsed |= (1 << 0); // keep rax (idx) out of the temp allocator
        int bsReg = allocReg();
        emitLoadQwordDisp8(bsReg, 3, 0);
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8((uint8_t)(0xC0 + bsReg));
        freeReg(bsReg);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emit8(0x48); emit8(0x8B); emit8(0x08); // rcx = [rax] (nextFree)
        emitStoreQwordDisp8(1, 3, 24); // [rbx+24] = nextFree
        emit8(0x58); // pop rax (idx)
        bsReg = allocReg();
        emitLoadQwordDisp8(bsReg, 3, 0);
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8((uint8_t)(0xC0 + bsReg));
        freeReg(bsReg);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        int ptrR = allocReg();
        if (ptrR != 0) { emitMovReg(ptrR, 0); freeReg(0); }
        emitJmp(doneLabel);

        emitLabel(seqLabel);
        emitLoadQwordDisp8(0, 3, 16); // rax = nextIdx
        regsUsed |= (1 << 0); // keep rax (nextIdx) out of the temp allocator
        int cReg = allocReg();
        emitLoadQwordDisp8(cReg, 3, 8);
        emit8(0x48); emit8(0x39); emit8((uint8_t)(0xC0 + (cReg << 3))); // cmp rax, cReg
        freeReg(cReg);
        emitJcc(">=", overflowLabel);

        bsReg = allocReg();
        emitLoadQwordDisp8(bsReg, 3, 0);
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8((uint8_t)(0xC0 + bsReg));
        freeReg(bsReg);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        ptrR = allocReg();
        if (ptrR != 0) { emitMovReg(ptrR, 0); freeReg(0); }

        emitLoadQwordDisp8(0, 3, 16);
        emit8(0x48); emit8(0xFF); emit8(0xC0);
        emitStoreQwordDisp8(0, 3, 16);
        emitJmp(doneLabel);

        emitLabel(overflowLabel);
        emitMovRegImm(ptrR >= 0 ? ptrR : 0, 0);

emitLabel(doneLabel);
        freeReg(3);
        regsUsed = (uint8_t)(saved & ~(1 << ptrR));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << ptrR));
        int r = allocReg();
        if (ptrR >= 0 && r != ptrR) { emitMovReg(r, ptrR); freeReg(ptrR); }
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // poolFree(pool, ptr) -> void
    if (call->name == "poolFree" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pReg = emitExpr(call->args[0].get());
        int ptrReg = emitExpr(call->args[1].get());
        emit8(0x50 + ptrReg);
        if (pReg != 3) { emitMovReg(3, pReg); freeReg(pReg); }
        emit8(0x59); // pop rcx (ptr)
        emit8(0x48); emit8(0x89); emit8(0xC8); // mov rax, rcx
        freeReg(ptrReg);                       // rcx (ptr) now copied into rax
        emit8(0x48); emit8(0x29); emit8(0xD8); // sub rax, rbx
        emit8(0x48); emit8(0x83); emit8(0xE8); emit8(0x20); // sub rax, 32
        regsUsed |= (1 << 0); // keep rax (offset) out of the temp allocator
        emit8(0x48); emit8(0x31); emit8(0xD2); // xor rdx, rdx: high half of dividend = 0
        regsUsed |= (1 << 2); // keep rdx out so the divisor never lands in it
        int bsReg = allocReg();                // rcx (1) — a register other than rdx
        emitLoadQwordDisp8(bsReg, 3, 0);       // bsReg = blockSize
        emit8(0x48); emit8(0xF7); emit8((uint8_t)(0xF0 + bsReg)); // div bsReg
        freeReg(bsReg);
        emitMovReg(2, 0); // rdx = idx
        int bsReg2 = allocReg();
        emitLoadQwordDisp8(bsReg2, 3, 0);
        emitMovReg(0, 2);
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8((uint8_t)(0xC0 + bsReg2));
        freeReg(bsReg2);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(0x20);
        emitLoadQwordDisp8(1, 3, 24);
        emitStoreQwordDisp8(1, 0, 0);
        emitStoreQwordDisp8(2, 3, 24);

        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // poolReset(pool) -> void
    if (call->name == "poolReset" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int p = emitExpr(call->args[0].get());
        if (p != 3) { emitMovReg(3, p); freeReg(p); }
        emitMovQwordDisp8Imm32(3, 16, 0);
        emitMovQwordDisp8Imm32(3, 24, -1);
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // poolDestroy(pool) -> void (free pool block back to heap)
    if (call->name == "poolDestroy" && call->args.size() == 1) {
        int r = emitExpr(call->args[0].get());
        if (r != 1) { emitMovReg(1, r); freeReg(r); }
        regsUsed = 0;
        emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0); // lea rax, [rcx-16]
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx
        emit8(0x48); emit8(0x89); emit8(0x05);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // ============== Slot Allocator Builtins ==============
    // Header: [maxCount:8][dataSize:8][freeHead:8][aliveCount:8] at handle+0
    // Slots at handle+32, stride = 16 + dataSize
    // Each slot: [generation:8][nextFree:8][data:dataSize]
    // Handle = (generation << 32) | slotIndex
    // rbx(3) = slot handle throughout

    // Helper: compute slotAddr = rbx + 32 + idx*stride into dstReg
    // idxReg has the index. Uses rax, rcx as temps. stride stored in memory.
    // After: dstReg = slotAddr, idxReg destroyed, rax/rcx trashed

    // slotCreate(maxCount, dataSize) -> slot
    if (call->name == "slotCreate" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int mcReg = emitExpr(call->args[0].get());
        int dsReg = emitExpr(call->args[1].get());
        // rbx = maxCount
        if (mcReg != 3) { emitMovReg(3, mcReg); freeReg(mcReg); }
        // rcx = dataSize
        if (dsReg != 1) { emitMovReg(1, dsReg); freeReg(dsReg); }
        // Save dataSize on stack, compute total size in rcx
        emit8(0x51); // push rcx (dataSize)
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16); // stride = dataSize+16
        emitImul(1, 3); // rcx *= maxCount
        // +32 slot header, align to 16, +16 block header
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(32 + 15); // add rcx, 47
        emit8(0x48); emit8(0x83); emit8(0xE1); emit8(0xF0);    // and rcx, -16
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);      // add rcx, 16 (block header)
        // rcx = totalSize
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), heapAreaRVA}); emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC0); // mov r8, rax (save heapArea)
        emit8(0x48); emit8(0x03); emit8(0xCA); // rcx = totalSize + offset = newOffset
        emit8(0x48); emit8(0x81); emit8(0xF9); emit32(64 * 1024 * 1024);
        int scFail = newLabel();
        emit8(0x0F); emit8(0x87);
        jmpFixups.push_back({code.size(), scFail}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x0D);
        heapFixups.push_back({code.size(), heapOffsetRVA}); emit32(0);
        // rcx = newOffset, rdx = old_offset, r8 = heapArea
        emit8(0x48); emit8(0x29); emit8(0xD1); // sub rcx, rdx (totalSize)
        emit8(0x49); emit8(0x89); emit8(0x4C); emit8(0x10); emit8(8); // mov [r8+rdx+8], totalSize
        emit8(0x49); emit8(0x8D); emit8(0x44); emit8(0x10); emit8(16); // lea rax, [r8+rdx+16]
        int scDone = newLabel();
        emitJmp(scDone);
        emitLabel(scFail);
        emit8(0x48); emit8(0x31); emit8(0xC0);
        emitLabel(scDone);
        // rax = block, stack has [dataSize]
        emit8(0x59); // pop rcx (dataSize)
        emitStoreQwordDisp8(3, 0, 0); // [rax+0] = maxCount
        emitStoreQwordDisp8(1, 0, 8); // [rax+8] = dataSize
        emitMovQwordDisp8Imm32(0, 16, -1); // freeHead = -1
        emitMovQwordDisp8Imm32(0, 24, 0);  // aliveCount = 0
        freeReg(3);
        int r = allocReg();
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // slotSpawn(slot) -> handle
    if (call->name == "slotSpawn" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        regsUsed |= (1 << 3);

        int fullLabel = newLabel();
        int doneLabel = newLabel();
        int freeListLabel = newLabel();

        // rax = freeHead
        emitLoadQwordDisp8(0, 3, 16);
        // cmp rax, -1
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8((uint8_t)(int8_t)-1);
        // jne freeListLabel
        emitJcc("!=", freeListLabel);

        // === SEQUENTIAL PATH (freeHead == -1) ===
        emitLoadQwordDisp8(1, 3, 0);  // rcx = maxCount
        emitLoadQwordDisp8(2, 3, 24); // rdx = aliveCount = idx
        // cmp rdx, rcx; jae full
        emit8(0x48); emit8(0x39); emit8(0xCA); // cmp rdx, rcx
        emitJcc(">=", fullLabel);

        emit8(0x52); // push rdx (save idx)
        // stride = [rbx+8] + 16
        emitLoadQwordDisp8(0, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(16);
        // slotAddr = rbx + idx*stride + 32
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xD0); // imul rdx, rax
        emitAdd(2, 3);
        emit8(0x48); emit8(0x83); emit8(0xC2); emit8(32);
        // Load gen, bump
        emitLoadQwordDisp8(0, 2, 0); // rax = gen
        emitIncQwordDisp8(2, 0);     // gen++
        // Pack: (gen << 32) | idx
        emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x20); // shl rax, 32
        emit8(0x59); // pop rcx (idx)
        emitAdd(0, 1); // rax += idx
        emitIncQwordDisp8(3, 24); // aliveCount++
        emitJmp(doneLabel);

        // === FREE LIST PATH ===
        emitLabel(freeListLabel);
        // rax = freeHead = idx
        emit8(0x50); // push rax (save idx)
        // stride = [rbx+8] + 16
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // slotAddr = rbx + idx*stride + 32
        emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); // imul rax, rcx
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        // Update free list
        emitLoadQwordDisp8(1, 0, 8); // rcx = nextFree
        emitStoreQwordDisp8(1, 3, 16); // [rbx+16] = nextFree
        // Load gen (no bump)
        emitLoadQwordDisp8(2, 0, 0); // rdx = gen
        // Pack: (gen << 32) | idx
        emit8(0x48); emit8(0xC1); emit8(0xE2); emit8(0x20); // shl rdx, 32
        emit8(0x59); // pop rcx (idx)
        emitMovReg(0, 2); // rax = gen<<32
        emitAdd(0, 1);    // rax += idx
        emitIncQwordDisp8(3, 24); // aliveCount++
        emitJmp(doneLabel);

        // === FULL ===
        emitLabel(fullLabel);
        emit8(0x48); emit8(0x31); emit8(0xC0); // xor rax, rax

emitLabel(doneLabel);
        freeReg(3);
        int r = allocReg();
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // slotKill(slot, handle) -> void
    if (call->name == "slotKill" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        int hReg = emitExpr(call->args[1].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
        // Extract idx: mov eax, eax
        emit8(0x89); emit8(0xC0);
        emitMovReg(2, 0); // rdx = idx
        // stride = [rbx+8] + 16
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // slotAddr = rbx + idx*stride + 32
        emitImul(0, 1); // rax *= rcx
        emitAdd(0, 3);  // rax += rbx
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        // Bump generation: inc [rax+0]
        emitIncQwordDisp8(0, 0);
        // Push to free list: [rax+8] = oldFreeHead; [rbx+16] = idx
        emitLoadQwordDisp8(1, 3, 16); // rcx = oldFreeHead
        emitStoreQwordDisp8(1, 0, 8); // [rax+8] = oldFreeHead
        emitStoreQwordDisp8(2, 3, 16); // [rbx+16] = idx
        // Dec aliveCount: dec [rbx+24]
        emit8(0x48); emit8(0xFF); emit8(0x4B); emit8(0x18);
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // slotGetI64(slot, handle, byteOffset) -> int
    if (call->name == "slotGetI64" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        int hReg = emitExpr(call->args[1].get());
        int bReg = emitExpr(call->args[2].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
        emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
        if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
        // stride
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // slotAddr+byteOffset
        emitImul(0, 1);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emitAdd(0, 2); // + byteOffset
        // Load value
        emitLoadQwordDisp8(1, 0, 0); // rcx = value
        freeReg(3);
        int r = allocReg();
        if (r != 1) { emitMovReg(r, 1); freeReg(1); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // slotSetI64(slot, handle, byteOffset, value) -> void
    if (call->name == "slotSetI64" && call->args.size() == 4) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        int hReg = emitExpr(call->args[1].get());
        int bReg = emitExpr(call->args[2].get());
        int vReg = emitExpr(call->args[3].get());
        // save value BEFORE clobbering rbx with slot handle
        emit8(0x50 + vReg); // push value
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
        emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
        if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
        // stride
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // addr
        emitImul(0, 1);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emitAdd(0, 2);
        // Store
        emit8(0x59); // pop rcx (value)
        emitStoreQwordDisp8(1, 0, 0); // [rax] = value
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // slotGetF32(slot, handle, byteOffset) -> i64 (float bits)
    if (call->name == "slotGetF32" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        int hReg = emitExpr(call->args[1].get());
        int bReg = emitExpr(call->args[2].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
        emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
        if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
        // stride
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // addr
        emitImul(0, 1);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emitAdd(0, 2);
        // Load float bits: movss xmm0, [rax+0] then movd rcx, xmm0
        int x = allocXmmReg();
        emitMovssXmmFromMem(x, 0, 0);
        emitMovdGpFromXmm(1, x); // rcx = float bits as int
        freeXmmReg(x);
        freeReg(3);
        int r = allocReg();
        if (r != 1) { emitMovReg(r, 1); freeReg(1); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // slotSetF32(slot, handle, byteOffset, value) -> void
    if (call->name == "slotSetF32" && call->args.size() == 4) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        int hReg = emitExpr(call->args[1].get());
        int bReg = emitExpr(call->args[2].get());
        int vReg = emitExpr(call->args[3].get());
        // Convert value to float and park it on the stack BEFORE clobbering
        // rbx with the slot handle (the value may live in rbx itself).
        int x = allocXmmReg();
        emitCvtsi2ss(x, vReg); // xmm = (float)value
        // sub rsp, 4 for float storage
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x04);
        emitMovssXmmToMem(x, 4, 0); // movss [rsp], xmm
        freeXmmReg(x);
        freeReg(vReg);
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        if (hReg != 0) { emitMovReg(0, hReg); freeReg(hReg); }
        emit8(0x89); emit8(0xC0); // mov eax, eax (idx)
        if (bReg != 2) { emitMovReg(2, bReg); freeReg(bReg); }
        // stride
        emitLoadQwordDisp8(1, 3, 8);
        emit8(0x48); emit8(0x83); emit8(0xC1); emit8(16);
        // addr
        emitImul(0, 1);
        emitAdd(0, 3);
        emit8(0x48); emit8(0x83); emit8(0xC0); emit8(32);
        emitAdd(0, 2);
        // Load float from stack into xmm, store to addr
        int x2 = allocXmmReg();
        emitMovssXmmFromMem(x2, 4, 0); // xmm from [rsp]
        emitMovssXmmToMem(x2, 0, 0);   // movss [rax], xmm
        freeXmmReg(x2);
        // add rsp, 4
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x04);
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // slotCount(slot) -> int
    if (call->name == "slotCount" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        emitLoadQwordDisp8(0, 3, 24); // rax = aliveCount
        freeReg(3);
        int r = allocReg();
        if (r != 0) { emitMovReg(r, 0); freeReg(0); }
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // slotReset(slot) -> void
    if (call->name == "slotReset" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int sReg = emitExpr(call->args[0].get());
        if (sReg != 3) { emitMovReg(3, sReg); freeReg(sReg); }
        emitMovQwordDisp8Imm32(3, 16, -1); // freeHead = -1
        emitMovQwordDisp8Imm32(3, 24, 0);  // aliveCount = 0
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // slotDestroy(slot) -> void (free the slot block back to heap)
    if (call->name == "slotDestroy" && call->args.size() == 1) {
        int r = emitExpr(call->args[0].get());
        if (r != 1) { emitMovReg(1, r); freeReg(r); }
        regsUsed = 0;
        emit8(0x48); emit8(0x8D); emit8(0x41); emit8(0xF0); // lea rax, [rcx-16]
        emit8(0x48); emit8(0x8B); emit8(0x15);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x10); // mov [rax], rdx
        emit8(0x48); emit8(0x89); emit8(0x05);
        heapFixups.push_back({code.size(), heapFreeHeadRVA}); emit32(0);
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // fbits(f) -> int: returns the raw 32-bit pattern of a float.
    if (call->name == "fbits" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int fx = emitFloatExpr(call->args[0].get());
        if (fx < 0) fx = 0;
        if (fx != 0) { emitMovssXmm(0, fx); freeXmmReg(fx); }
        xmmRegsUsed = (uint8_t)(1 << 0);   // xmm0 busy: holds the float
        int r = allocReg();
        emitMovdGpFromXmm(r, 0);           // r = float bits as int
        freeXmmReg(0);
        xmmRegsUsed = 0;
        regsUsed = (uint8_t)(saved & ~(1 << r));
        reloadRegs();
        regsUsed = (uint8_t)(saved | (1 << r));
        resultReg = r >= 0 ? r : 0;
        return true;
    }

    // sleep(seconds) -> void
    if (call->name == "sleep" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        if (isFloatExpr(call->args[0].get())) {
            // Float argument: seconds -> ms in FLOAT domain (arg * 1000.0f),
            // then convert to int. Fixes sleep(0.016) = Sleep(16) (was Sleep(0)).
            int x = emitFloatExpr(call->args[0].get());
            int t = allocXmmReg();
            if (t >= 0) {
                emitMovssXmmImm(t, 1000.0f);
                emitMulss(x, t);
                freeXmmReg(t);
            }
            int r = allocReg(); if (r < 0) r = 0;
            emitCvtss2si(r, x);
            freeXmmReg(x);
            freeReg(0);
            // r = ms; move to rax
            if (r != 0) { emitMovReg(0, r); freeReg(r); }
            if (t < 0) {
                // no free XMM: fall back to ms = (int)seconds * 1000
                emit8(0x48); emit8(0x69); emit8(0xC0); emit32(1000); // imul rax, rax, 1000
            }
        } else {
            int sReg = emitExpr(call->args[0].get());
            if (sReg != 0) { emitMovReg(0, sReg); freeReg(sReg); }
            // rax = seconds; ms = rax * 1000
            emit8(0x48); emit8(0x69); emit8(0xC0); emit32(1000); // imul rax, rax, 1000
        }
        // sub rsp, 0x20; mov ecx, eax; call Sleep; add rsp, 0x20
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // sub rsp, 32
        emit8(0x89); emit8(0xC1); // mov ecx, eax
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "Sleep", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 32
        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // pause() -> void: print message and wait for Enter
    if (call->name == "pause" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        // Find or add "Press any key to continue . . .\r\n"
        std::string pauseMsg = "Press any key to continue . . .\r\n";
        int pauseIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == pauseMsg) { pauseIdx = (int)i; break; }
        }
        if (pauseIdx < 0) {
            pauseIdx = (int)stringPool.size();
            stringPool.push_back(pauseMsg);
        }

        // --- Get stdout handle ---
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // sub rsp, 32
        emit8(0xB9); emit32((uint32_t)-11); // mov ecx, -11 (STD_OUTPUT_HANDLE)
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 32
        emit8(0x50); // push rax (save stdout)

        // --- WriteFile(stdout, msg, len, NULL, NULL) ---
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28); // sub rsp, 40
        emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40); // mov rcx, [rsp+40] = stdout
        emit8(0x48); emit8(0x8D); emit8(0x15); // lea rdx, [rip+msg]
        strFixups.push_back({code.size(), pauseIdx});
        emit32(0);
        emit8(0x41); emit8(0xB8); emit32((uint32_t)pauseMsg.size()); // mov r8d, len
        emit8(0x45); emit8(0x31); emit8(0xC9); // xor r9d, r9d
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // mov qword [rsp+32], 0
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28); // add rsp, 40

        // --- Get stdin handle ---
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28); // sub rsp, 40
        emit8(0xB9); emit32((uint32_t)-10); // mov ecx, -10 (STD_INPUT_HANDLE)
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28); // add rsp, 40
        // rax = stdin

        // --- ReadFile(stdin, buf, 1, &read, NULL) ---
        // [rsp+0..31] shadow, [rsp+32] overlapped, [rsp+40] buf, [rsp+48] bytesRead
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x38); // sub rsp, 56
        emit8(0x48); emit8(0x89); emit8(0xC1); // mov rcx, rax (stdin)
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x28); // lea rdx, [rsp+40] buf
        emit8(0x41); emit8(0xB8); emit32(1); // mov r8d, 1
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x30); // lea r9, [rsp+48] bytesRead
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // mov qword [rsp+32], 0
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "ReadFile", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x38); // add rsp, 56

        emit8(0x58); // pop rax (balance stdout push)

        freeReg(3);
        regsUsed = (uint8_t)saved;
        reloadRegs();
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    if (call->name == "print" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int newlineIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == "\r\n") { newlineIdx = (int)i; break; }
        }
        if (newlineIdx < 0) {
            newlineIdx = (int)stringPool.size();
            stringPool.push_back("\r\n");
        }

        // --- Step 1: GetStdHandle(STD_OUTPUT_HANDLE = -11) ---
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 32
        emit8(0xB9); emit32((uint32_t)-11);                   // mov ecx, -11
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetStdHandle", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32
        emit8(0x50);  // push rax  (save handle on stack)

        if (auto strExpr = dynamic_cast<StringExpr*>(call->args[0].get())) {
            int strIdx = -1;
            for (size_t i = 0; i < stringPool.size(); i++) {
                if (stringPool[i] == strExpr->value) { strIdx = (int)i; break; }
            }
            if (strIdx < 0) {
                strIdx = (int)stringPool.size();
                stringPool.push_back(strExpr->value);
            }
            int len = (int)strExpr->value.size();

            // --- WriteFile(handle, str, len, NULL, NULL) ---
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);  // sub rsp, 40
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40]
            emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+disp32]
            strFixups.push_back({code.size(), strIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32(len);  // mov r8d, len
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);  // add rsp, 40

            // WriteFile(handle, "\r\n", 2, NULL, NULL)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(40);  // mov rcx, [rsp+40]
            emit8(0x48); emit8(0x8D); emit8(0x15);  // lea rdx, [rip+disp32]
            strFixups.push_back({code.size(), newlineIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32(2);  // mov r8d, 2
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

            emit8(0x58);  // pop rax (balance push)

        } else if (isFloatExpr(call->args[0].get())) {
            // --- Float case: decimal string on stack, then WriteFile ---
            int fv = emitFloatExpr(call->args[0].get());
            if (fv < 0) fv = 0;
            if (fv != 0) { emitMovssXmm(0, fv); freeXmmReg(fv); }
            xmmRegsUsed = 1;   // xmm0 = value

            // Reserve 96-byte buffer. The saved handle (pushed earlier) is now
            // at [rsp+0x60].
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x60);  // sub rsp, 96

            // ---- sign detection (absolute value to xmm0 if negative) ----
            int negTrue = newLabel();
            int negDone = newLabel();
            emit8(0x66); emit8(0x0F); emit8(0x7E); emit8(0xC0);   // movd eax, xmm0
            emit8(0xA9); emit32(0x80000000);                       // test eax, 0x80000000
            emitJcc("==", negDone);                                // not negative
            emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x38); emit8(0x01); // byte[rsp+56]=1
            {   int saved = regsUsed; regsUsed = 0;
                int m = allocReg(); emitMovRegImm(m, 0x80000000);
                int mx = allocXmmReg(); if (mx < 0) mx = 0;
                emitMovdXmmFromGp(mx, m); freeReg(m); regsUsed = (uint8_t)saved;
                emitXorps(0, mx); freeXmmReg(mx);
            }
            emitJmp(negTrue);
            emitLabel(negDone);
            emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x38); emit8(0x00); // byte[rsp+56]=0
            emitLabel(negTrue);
            // xmm0 = |value|; byte[rsp+56] = negative flag

            // ---- integer part: rax = trunc(|value|) ----
                emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xC0); // cvttss2si rax, xmm0 (truncate)
            emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30); // [rsp+48]=int

            // ---- convert integer digits into buffer (r10=dst end, r8d=count) ----
            int izero = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);   // test rax, rax
            emitJcc("!=", izero);
            emit8(0x49); emit8(0x89); emit8(0xE2);               // r10 = rsp
            emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1E);  // r10 += 30 (headroom below for '-')
            emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x30);  // byte[r10]='0'
            emit8(0x41); emit8(0xB8); emit8(0x01); emit8(0x00); emit8(0x00); emit8(0x00); // r8d=1
            int iafter = newLabel();
            emitJmp(iafter);
            emitLabel(izero);
            emit8(0x49); emit8(0x89); emit8(0xE2);               // r10 = rsp
            emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1E);  // r10 += 30 (integer digits land near middle, leaving room for fraction)
            emit8(0x45); emit8(0x31); emit8(0xC0);               // r8d = 0
            emit8(0xB9); emit8(0x0A); emit8(0x00); emit8(0x00); emit8(0x00); // ecx=10
            int iloop = newLabel();
            emitLabel(iloop);
            emit8(0x48); emit8(0x31); emit8(0xD2);               // edx=0
            emit8(0x48); emit8(0xF7); emit8(0xF1);               // div rcx
            emit8(0x80); emit8(0xC2); emit8(0x30);               // dl += '0'
            emit8(0x49); emit8(0xFF); emit8(0xCA);               // r10--
            emit8(0x41); emit8(0x88); emit8(0x12);               // [r10]=dl
            emit8(0x41); emit8(0xFF); emit8(0xC0);               // r8d++
            emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax
            emitJcc("!=", iloop);
            emitLabel(iafter);

            // ---- fraction: frac = |value| - (float)int ----
            emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x30); // rax=[rsp+48]
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xC8); // cvtsi2ss xmm1, rax
            emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC1);             // subss xmm0, xmm1 (frac)
            int noFrac = newLabel();
            emitMovssXmmImm(1, 0.0f);                                       // xmm1 = 0.0
            emit8(0x0F); emit8(0x2E); emit8(0xC1);                          // ucomiss xmm0, xmm1
            emitJcc("==", noFrac);
            // write '.'
            emit8(0x4B); emit8(0x8D); emit8(0x04); emit8(0x02); // lea rax, [r10+r8] (dst)
            emit8(0xC6); emit8(0x00); emit8(0x2E);              // byte[rax]='.'
            emit8(0x41); emit8(0xFF); emit8(0xC0);              // r8d++
            emitMovssXmmImm(2, 10.0f);                          // xmm2 = 10.0
            // decimal digit loop, up to 4 digits
            emit8(0x41); emit8(0xBE); emit8(0x04); emit8(0x00); emit8(0x00); emit8(0x00); // r14d=4 (max)
            int fTop = newLabel();
            int fDone = newLabel();
            emitLabel(fTop);
            emit8(0x4B); emit8(0x8D); emit8(0x04); emit8(0x02);             // lea rax,[r10+r8]
            emit8(0xF3); emit8(0x0F); emit8(0x59); emit8(0xC2);             // mulss xmm0,xmm2 (*10)
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2C); emit8(0xD0); // cvttss2si rdx, xmm0 (digit, truncate)
            emit8(0xF3); emit8(0x48); emit8(0x0F); emit8(0x2A); emit8(0xDA); // cvtsi2ss xmm3, rdx
            emit8(0xF3); emit8(0x0F); emit8(0x5C); emit8(0xC3);             // subss xmm0,xmm3
            emit8(0x80); emit8(0xC2); emit8(0x30);                         // dl += '0'
            emit8(0x88); emit8(0x10);                                       // byte[rax]=dl
            emit8(0x41); emit8(0xFF); emit8(0xC0);                         // r8d++
            emit8(0x41); emit8(0xFF); emit8(0xCE);                         // r14d--
            emit8(0x45); emit8(0x85); emit8(0xF6);                         // test r14d
            emitJcc("==", fDone);
            emit8(0x0F); emit8(0x2E); emit8(0xC1);                         // ucomiss xmm0, xmm1
            emitJcc("!=", fTop);
            emitLabel(fDone);
            emitLabel(noFrac);

            // ---- prepend '-' if negative ----
            int noNeg = newLabel();
            emit8(0x80); emit8(0x7C); emit8(0x24); emit8(0x38); emit8(0x00); // cmp byte[rsp+56],0
            emitJcc("==", noNeg);
            emit8(0x49); emit8(0xFF); emit8(0xCA);               // r10--
            emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x2D);  // byte[r10]='-'
            emit8(0x41); emit8(0xFF); emit8(0xC0);               // r8d++
            emitLabel(noNeg);

            // ---- WriteFile(handle, r10, r8d, NULL, NULL) ----
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(136); // rcx=[rsp+136] (handle)
            emit8(0x4C); emit8(0x89); emit8(0xD2);               // rdx = r10
            emit8(0x45); emit8(0x31); emit8(0xC9);               // r9d=0
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

            // ---- WriteFile(handle, "\r\n", 2, NULL, NULL) ----
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(136); // rcx=[rsp+136] (handle)
            emit8(0x48); emit8(0x8D); emit8(0x15);
            strFixups.push_back({code.size(), newlineIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32(2);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x60);  // add rsp, 96 (buffer)
            emit8(0x58);  // pop rax (balance push)

        } else {
            // --- Int case: convert to string on stack, then WriteFile ---
            int exprReg = emitExpr(call->args[0].get());
            if (exprReg != 0) { emitMovReg(0, exprReg); freeReg(exprReg); }
            else freeReg(0);

            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 32 (buffer)

            // Check for negative number
            int isNegLabel = newLabel();
            int notNegLabel = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x88);  // js isNegLabel (jump if sign flag set)
            jmpFixups.push_back({code.size(), isNegLabel});
            emit32(0);
            emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x0A); emit8(0x00);  // mov byte [rsp+10], 0 (positive flag)
            emitJmp(notNegLabel);
            emitLabel(isNegLabel);
            emit8(0x48); emit8(0xF7); emit8(0xD8);  // neg rax
            emit8(0xC6); emit8(0x44); emit8(0x24); emit8(0x0A); emit8(0x01);  // mov byte [rsp+10], 1 (negative flag)
            emitLabel(notNegLabel);

            int notZero = newLabel();
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x85);
            jmpFixups.push_back({code.size(), notZero});
            emit32(0);
            emit8(0xC6); emit8(0x04); emit8(0x24); emit8(0x30);  // mov byte [rsp], '0'
            emit8(0x41); emit8(0xB8); emit8(0x01); emit8(0x00); emit8(0x00); emit8(0x00);  // mov r8d, 1
            emit8(0x49); emit8(0x89); emit8(0xE2);  // mov r10, rsp
            int afterZero = newLabel();
            emitJmp(afterZero);
            emitLabel(notZero);

            emit8(0x49); emit8(0x89); emit8(0xE2);  // mov r10, rsp
            emit8(0x49); emit8(0x83); emit8(0xC2); emit8(0x1F);  // add r10, 31
            emit8(0x45); emit8(0x31); emit8(0xC0);  // xor r8d, r8d
            emit8(0xB9); emit8(0x0A); emit8(0x00); emit8(0x00); emit8(0x00);  // mov ecx, 10

            int convLoop = newLabel();
            emitLabel(convLoop);
            emit8(0x48); emit8(0x31); emit8(0xD2);  // xor edx, edx
            emit8(0x48); emit8(0xF7); emit8(0xF1);  // div rcx
            emit8(0x80); emit8(0xC2); emit8(0x30);  // add dl, '0'
            emit8(0x49); emit8(0xFF); emit8(0xCA);  // dec r10
            emit8(0x41); emit8(0x88); emit8(0x12);  // mov [r10], dl
            emit8(0x41); emit8(0xFF); emit8(0xC0);  // inc r8d
            emit8(0x48); emit8(0x85); emit8(0xC0);  // test rax, rax
            emit8(0x0F); emit8(0x85);
            jmpFixups.push_back({code.size(), convLoop});
            emit32(0);

            // If was negative, prepend '-' before the digits
            int notNegPrint = newLabel();
            emit8(0x80); emit8(0x7C); emit8(0x24); emit8(0x0A); emit8(0x01);  // cmp byte [rsp+10], 1
            emit8(0x75);  // jne notNegPrint
            int jnePos2 = (int)code.size();
            emit8(0x00);  // placeholder
            emit8(0x49); emit8(0xFF); emit8(0xCA);  // dec r10
            emit8(0x41); emit8(0xC6); emit8(0x02); emit8(0x2D);  // mov byte [r10], '-'
            emit8(0x41); emit8(0xFF); emit8(0xC0);  // inc r8d
            emitLabel(notNegPrint);
            code[jnePos2] = (uint8_t)((int)code.size() - jnePos2 - 1);

            emitLabel(afterZero);

            // WriteFile(handle, r10, r8d, NULL, NULL)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(72);
            emit8(0x4C); emit8(0x89); emit8(0xD2);  // mov rdx, r10
            emit8(0x45); emit8(0x31); emit8(0xC9);  // xor r9d, r9d
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

            // WriteFile(handle, "\r\n", 2, NULL, NULL)
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);
            emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(72);
            emit8(0x48); emit8(0x8D); emit8(0x15);
            strFixups.push_back({code.size(), newlineIdx});
            emit32(0);
            emit8(0x41); emit8(0xB8); emit32(2);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 32 (buffer)
            emit8(0x58);  // pop rax (balance push)
        }

        regsUsed = (uint8_t)saved;
        reloadRegs();
        resultReg = 0;
        return true;
    }

    // ============== EFI Builtins ==============
    // efi_image_handle() — returns EFI_HANDLE
    if (call->name == "efi_image_handle" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // efi_system_table() — returns EFI_SYSTEM_TABLE*
    if (call->name == "efi_system_table" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // efi_exit(status) — returns status from EfiMain
    if (call->name == "efi_exit" && call->args.size() == 1) {
        spillRegs();
        regsUsed = 0;
        int statusReg = emitExpr(call->args[0].get());
        if (statusReg != 0) { emitMovReg(0, statusReg); freeReg(statusReg); }
        else freeReg(0);
        if (frameSize > 0) {
            if (frameSize <= 127) {
                emit8(0x48); emit8(0x83); emit8(0xC4); emit8((uint8_t)frameSize);
            } else {
                emit8(0x48); emit8(0x81); emit8(0xC4); emit32((uint32_t)frameSize);
            }
        }
        emit8(0x5B);  // pop rbx
        emit8(0x5D);  // pop rbp
        emit8(0xC3);  // ret
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // efi_print(text) — prints string via EFI SystemTable ConOut->OutputString
    if (call->name == "efi_print" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int strReg = emitExpr(call->args[0].get());
        if (strReg != 0) { emitMovReg(0, strReg); freeReg(strReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x220); // sub rsp, 0x220
        emit8(0x48); emit8(0x89); emit8(0xC6); // mov rsi, rax
        emit8(0x48); emit8(0x8D); emit8(0x7C); emit8(0x24); emit8(0x20); // lea rdi, [rsp + 0x20]
        emit8(0x41); emit8(0xB8); emit32(255); // mov r8d, 255 (char budget, rcx kept free as scratch)

        int loopLabel = newLabel();
        int endLabel = newLabel();
        int oneByteLabel = newLabel();
        int storeLabel = newLabel();
        int gatherLabel = newLabel();
        int gatherDoneLabel = newLabel();
        int twoByteLabel = newLabel();
        int threeByteLabel = newLabel();
        emitLabel(loopLabel);
        emit8(0x0F); emit8(0xB6); emit8(0x06); // movzx eax, byte [rsi]
        emit8(0x84); emit8(0xC0); // test al, al
        emitJcc("e", endLabel);
        emit8(0xA8); emit8(0x80); // test al, 0x80
        emit8(0x0F); emit8(0x89); jmpFixups.push_back({code.size(), oneByteLabel}); emit32(0); // jns -> ASCII
        emit8(0xA8); emit8(0x40); // test al, 0x40
        emitJcc("==", oneByteLabel); // stray continuation (10xxxxxx) -> emit as-is
        // lead byte (11xxxxxx): full UTF-8 decode 2/3/4 bytes
        emit8(0x3C); emit8(0xE0); // cmp al, 0xE0
        emitJcc("<", twoByteLabel);
        emit8(0x3C); emit8(0xF0); // cmp al, 0xF0
        emitJcc("<", threeByteLabel);
        // four-byte: 11110xxx, cp = b1&0x07, 3 continuation bytes
        emit8(0x24); emit8(0x07); // and al, 0x07
        emit8(0xBA); emit32(3);   // mov edx, 3
        emitJmp(gatherLabel);
        emitLabel(twoByteLabel);
        emit8(0x24); emit8(0x1F); // and al, 0x1F
        emit8(0xBA); emit32(1);   // mov edx, 1
        emitJmp(gatherLabel);
        emitLabel(threeByteLabel);
        emit8(0x24); emit8(0x0F); // and al, 0x0F
        emit8(0xBA); emit32(2);   // mov edx, 2
        emitLabel(gatherLabel);
        emit8(0x85); emit8(0xD2); // test edx, edx
        emitJcc("==", gatherDoneLabel);
        emit8(0xC1); emit8(0xE0); emit8(0x06); // shl eax, 6
        emit8(0x48); emit8(0xFF); emit8(0xC6); // inc rsi
        emit8(0x0F); emit8(0xB6); emit8(0x0E); // movzx ecx, byte [rsi]
        emit8(0x83); emit8(0xE1); emit8(0x3F); // and ecx, 0x3F
        emit8(0x09); emit8(0xC8); // or eax, ecx
        emit8(0xFF); emit8(0xCA); // dec edx
        emitJmp(gatherLabel);
        emitLabel(gatherDoneLabel);
        emit8(0x48); emit8(0xFF); emit8(0xC6); // inc rsi (consume lead byte)
        emitJmp(storeLabel);
        emitLabel(oneByteLabel);
        emit8(0x48); emit8(0xFF); emit8(0xC6); // inc rsi
        emitLabel(storeLabel);
        emit8(0x66); emit8(0x89); emit8(0x07); // mov [rdi], ax
        emit8(0x48); emit8(0x83); emit8(0xC7); emit8(0x02); // add rdi, 2
        emit8(0x41); emit8(0xFF); emit8(0xC8); // dec r8d (char budget)
        emitJcc("!=", loopLabel);

        emitLabel(endLabel);
        emit8(0x66); emit8(0xC7); emit8(0x07); emit16(0); // mov word ptr [rdi], 0

        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0); // rax = SystemTable

        emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x40); // mov rcx, [rax + 0x40] (rcx = ConOut)
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // lea rdx, [rsp + 0x20]
        emit8(0xFF); emit8(0x51); emit8(0x08); // call qword ptr [rcx + 8] (OutputString)

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x220); // add rsp, 0x220
        regsUsed = (uint8_t)saved;
        reloadRegs();
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // EFI Keyboard Input (kernel_mode: dependent)
    // Uses ConIn (EFI_SIMPLE_TEXT_INPUT_PROTOCOL):
    //   ConIn          = [SystemTable + 0x30]
    //   ReadKeyStroke  = [ConIn + 0x08]  (rcx=This, rdx=EFI_INPUT_KEY*)
    //   EFI_INPUT_KEY  = { u16 ScanCode; u16 UnicodeChar }
    // ReadKeyStroke returns EFI_SUCCESS (0) when a key is available and
    // EFI_NOT_READY otherwise. Because ReadKeyStroke consumes the key, a
    // small cache lives in win32Globals+52..+55 so efi_check_key() can peek
    // without losing the key:
    //   +52 = pending flag (1 = key cached)
    //   +53 = cached ScanCode (low byte)
    //   +54 = cached UnicodeChar (low byte)
    // =====================================================================

    // efi_get_char() — blocking read of a key. Returns the UnicodeChar
    // (low byte). Special keys (arrows, F-keys) have UnicodeChar = 0; use
    // efi_get_key() to also get the scan code.
    if (call->name == "efi_get_char" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int noCacheLbl = newLabel();
        int readLoop = newLabel();
        int doneLbl = newLabel();

        // Consume a key cached by efi_check_key() first.
        emit8(0x8A); emit8(0x05);                       // mov al, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        emit8(0x84); emit8(0xC0);                       // test al, al
        emitJcc("==", noCacheLbl);
        emit8(0x0F); emit8(0xB6); emit8(0x05);          // movzx eax, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 54});
        emit32(0);
        emit8(0xB2); emit8(0x00);                       // mov dl, 0
        emit8(0x88); emit8(0x15);                       // mov byte [rip+..], dl
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        emitJmp(doneLbl);

        // rbx = ConIn = [SystemTable + 0x30]
        emitLabel(noCacheLbl);
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x58); emit8(0x30); // mov rbx, [rax+0x30]

        // sub rsp, 0x30: 0x20 shadow space + 0x10 key buffer
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);
        emitLabel(readLoop);
        emit8(0x48); emit8(0x89); emit8(0xD9);               // mov rcx, rbx (This)
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // lea rdx, [rsp+0x20] (Key)
        emit8(0xFF); emit8(0x53); emit8(0x08);               // call [rbx+0x08] ReadKeyStroke
        emit8(0x85); emit8(0xC0);                            // test eax, eax
        emitJcc("!=", readLoop);                             // loop until a key arrives
        emit8(0x0F); emit8(0xB7); emit8(0x44); emit8(0x24); emit8(0x22); // movzx eax, word [rsp+0x22] (UnicodeChar)
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 0x30

        emitLabel(doneLbl);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // efi_check_key() — non-blocking. Returns 1 if a key is available, 0 if not.
    // The key is NOT consumed: it is cached so the next efi_get_char()/
    // efi_get_key() returns it.
    if (call->name == "efi_check_key" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int haveLbl = newLabel();
        int noKeyLbl = newLabel();
        int doneLbl = newLabel();

        // A key is already cached -> available.
        emit8(0x8A); emit8(0x05);                       // mov al, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        emit8(0x84); emit8(0xC0);                       // test al, al
        emitJcc("!=", haveLbl);

        // rbx = ConIn = [SystemTable + 0x30]
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x58); emit8(0x30); // mov rbx, [rax+0x30]

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30); // sub rsp, 0x30
        emit8(0x48); emit8(0x89); emit8(0xD9);               // mov rcx, rbx (This)
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // lea rdx, [rsp+0x20] (Key)
        emit8(0xFF); emit8(0x53); emit8(0x08);               // call [rbx+0x08] ReadKeyStroke
        emit8(0x85); emit8(0xC0);                            // test eax, eax
        emitJcc("!=", noKeyLbl);

        // Key available: cache scan + unicode, mark pending.
        emit8(0x0F); emit8(0xB6); emit8(0x44); emit8(0x24); emit8(0x20); // movzx eax, byte [rsp+0x20] (ScanCode)
        emit8(0x88); emit8(0x05);                           // mov byte [rip+..], al
        heapFixups.push_back({code.size(), win32GlobalsRVA + 53});
        emit32(0);
        emit8(0x0F); emit8(0xB6); emit8(0x44); emit8(0x24); emit8(0x22); // movzx eax, byte [rsp+0x22] (UnicodeChar)
        emit8(0x88); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 54});
        emit32(0);
        emit8(0xB0); emit8(0x01);                           // mov al, 1
        emit8(0x88); emit8(0x05);                           // mov byte [rip+..], al
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        // NOTE: never use "mov byte [rip+..], imm" (C6 05 disp32 imm8) here:
        // heapFixups resolves disp assuming no trailing imm, so the store
        // lands one byte past the target. A register store (88 05) is safe.
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30); // add rsp, 0x30
        emitMovRegImm(0, 1);
        emitJmp(doneLbl);

        emitLabel(noKeyLbl);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30); // add rsp, 0x30
        emitMovRegImm(0, 0);
        emitJmp(doneLbl);

        emitLabel(haveLbl);
        emitMovRegImm(0, 1);

        emitLabel(doneLbl);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // efi_get_key() — blocking read of a full key. Returns 32-bit:
    // (ScanCode << 16) | UnicodeChar. For arrows/F-keys UnicodeChar is 0
    // and ScanCode identifies the key (e.g. 0x01 = Up, 0x0D = Enter...).
    if (call->name == "efi_get_key" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int noCacheLbl = newLabel();
        int readLoop = newLabel();
        int doneLbl = newLabel();

        // Consume a key cached by efi_check_key() first.
        emit8(0x8A); emit8(0x05);                       // mov al, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        emit8(0x84); emit8(0xC0);                       // test al, al
        emitJcc("==", noCacheLbl);
        emit8(0x0F); emit8(0xB6); emit8(0x05);          // movzx eax, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 53});
        emit32(0);
        emit8(0xC1); emit8(0xE0); emit8(0x10);          // shl eax, 16
        emit8(0x8A); emit8(0x05);                       // mov al, byte [rip+..]
        heapFixups.push_back({code.size(), win32GlobalsRVA + 54});
        emit32(0);
        emit8(0xB2); emit8(0x00);                       // mov dl, 0
        emit8(0x88); emit8(0x15);                       // mov byte [rip+..], dl
        heapFixups.push_back({code.size(), win32GlobalsRVA + 52});
        emit32(0);
        emitJmp(doneLbl);

        // rbx = ConIn = [SystemTable + 0x30]
        emitLabel(noCacheLbl);
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x58); emit8(0x30); // mov rbx, [rax+0x30]

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30); // sub rsp, 0x30
        emitLabel(readLoop);
        emit8(0x48); emit8(0x89); emit8(0xD9);               // mov rcx, rbx (This)
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // lea rdx, [rsp+0x20] (Key)
        emit8(0xFF); emit8(0x53); emit8(0x08);               // call [rbx+0x08] ReadKeyStroke
        emit8(0x85); emit8(0xC0);                            // test eax, eax
        emitJcc("!=", readLoop);
        emit8(0x0F); emit8(0xB7); emit8(0x44); emit8(0x24); emit8(0x20); // movzx eax, word [rsp+0x20] (ScanCode)
        emit8(0xC1); emit8(0xE0); emit8(0x10);               // shl eax, 16
        emit8(0x0F); emit8(0xB7); emit8(0x4C); emit8(0x24); emit8(0x22); // movzx ecx, word [rsp+0x22] (UnicodeChar)
        emit8(0x09); emit8(0xC8);                            // or eax, ecx
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);  // add rsp, 0x30

        emitLabel(doneLbl);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // =====================================================================
    // EFI-independent kernel support: disable the firmware watchdog timer.
    // An independent-mode kernel booted through the EFI stub never calls
    // ExitBootServices, so the 5-minute boot-services watchdog stays armed
    // and would reset the machine mid-session. Calling SetWatchdogTimer(0)
    // disarms it. Two candidate slot offsets are invoked because different
    // builds lay out the boot-services table slightly differently; both
    // slots hold harmless functions for these arguments (Stall(0) is a
    // no-op, SetWatchdogTimer(0) disarms).
    // =====================================================================
    if (call->name == "wd_disable" && call->args.empty() &&
        prog.appType == AppType::EFI) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int doneLbl = newLabel();

        // rbx = BootServices = [[win32Globals+8] + 0x60]; skip if zero.
        emit8(0x48); emit8(0x8B); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA + 8});
        emit32(0);
        emit8(0x48); emit8(0x85); emit8(0xC0);          // test rax, rax
        emitJcc("==", doneLbl);
        emit8(0x48); emit8(0x8B); emit8(0x58); emit8(0x60); // mov rbx, [rax+0x60]
        emit8(0x48); emit8(0x85); emit8(0xDB);          // test rbx, rbx
        emitJcc("==", doneLbl);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20); // sub rsp, 0x20

        // call [rbx+0xF8](0,0,0,0) — disp32 form (0xF8 does not fit disp8)
        emit8(0x31); emit8(0xC9);                       // xor ecx, ecx
        emit8(0x31); emit8(0xD2);                       // xor edx, edx
        emit8(0x45); emit8(0x31); emit8(0xC0);          // xor r8d, r8d
        emit8(0x45); emit8(0x31); emit8(0xC9);          // xor r9d, r9d
        emit8(0xFF); emit8(0x93); emit32(0x000000F8);   // call qword [rbx+0xF8]

        // call [rbx+0x100](0,0,0,0) — disp32 form (0x100 > 127)
        emit8(0x31); emit8(0xC9); emit8(0x31); emit8(0xD2);
        emit8(0x45); emit8(0x31); emit8(0xC0); emit8(0x45); emit8(0x31); emit8(0xC9);
        emit8(0xFF); emit8(0x93); emit32(0x00000100);   // call qword [rbx+0x100]

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20); // add rsp, 0x20

        emitLabel(doneLbl);
        emitMovRegImm(0, 0);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== Bare-Metal / VGA Builtins ==============
    // Note: vga_clear/vga_putc/vga_print are handled by the cursor-aware
    // implementations in tryEFICall (EFI/Bare) and tryBIOSCall (BIOS).

    // halt() — cli; hlt loop. On OS-hosted Windows PE targets cli is a
    // privileged instruction (#GP in ring 3), so exit through kernel32
    // first and keep cli;hlt;spin as belt-and-braces should that return.
    if (call->name == "halt" && call->args.empty()) {
        if (prog.appType == AppType::Console || prog.appType == AppType::GUI) {
            emit8(0x33); emit8(0xC9);                  // xor ecx, ecx (exit code 0)
            emit8(0xFF); emit8(0x15);                  // call [rip+..] ExitProcess
            importCallFixups.push_back({code.size(), "ExitProcess", "kernel32.dll"});
            emit32(0);
        }
        emit8(0xFA); // cli
        emit8(0xF4); // hlt
        int loopLbl = newLabel();
        emitLabel(loopLbl);
        emit8(0xEB); emit8(0xFE); // jmp $
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // outb(port, val)
    if (call->name == "outb" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 0) { emitMovReg(0, portReg); freeReg(portReg); }
        else freeReg(0);
        emit8(0x50); // push port (rax)
        int valReg = emitExpr(call->args[1].get());
        if (valReg != 0) { emitMovReg(0, valReg); freeReg(valReg); }
        else freeReg(0);
        emit8(0x50); // push val (rax)
        emit8(0x58); // pop rax (val)
        emit8(0x5A); // pop rdx (port)
        emit8(0xEE); // out dx, al
        regsUsed = (uint8_t)saved;
        reloadRegs();
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // inb(port)
    if (call->name == "inb" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int portReg = emitExpr(call->args[0].get());
        if (portReg != 2) { emitMovReg(2, portReg); freeReg(portReg); }
        else freeReg(2);
        emit8(0xEC); // in al, dx
        emit8(0x0F); emit8(0xB6); emit8(0xC0); // movzx eax, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // efi_gslot(i) — read qword slot i from the compiler's win32Globals area.
    // Slot 0 = ImageHandle, 1 = SystemTable, 2 = GOP, 3.. fb info fields.
    // This is the only sanctioned way for Zenith code to reach boot-services
    // era pointers (used by drv_efi.z BEFORE ExitBootServices only).
    if (call->name == "efi_gslot" && call->args.size() == 1 &&
        prog.appType == AppType::EFI) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int idxReg = emitExpr(call->args[0].get());
        if (idxReg != 1) { emitMovReg(1, idxReg); freeReg(idxReg); }
        else freeReg(1);
        emit8(0x48); emit8(0xC1); emit8(0xE1); emit8(3);    // shl rcx, 3
        // lea rax,[rip+win32GlobalsRVA] — ADDRESS of the globals block.
        // A plain mov here would load *slot0* (ImageHandle) and treat it
        // as the base pointer => every slot read returned garbage/-1.
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x04); emit8(0x08); // mov rax,[rax+rcx]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // uefi_call(fn, a, b, c, d, e) — MS x64 indirect call into a UEFI
    // protocol/boot-services function. Up to 6 args: rcx,rdx,r8,r9 +
    // [rsp+0x20],[rsp+0x28] stack slots. Frame is 0x40 so rsp stays
    // 16-aligned at the call (caller guarantees rsp%16==0 here).
    if (call->name == "uefi_call" && call->args.size() >= 1 && call->args.size() <= 6 &&
        prog.appType == AppType::EFI) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        // Frame layout (offsets from rsp AFTER sub; rsp%16==0 at `call rax`):
        //   [0x00]=fn  [0x08]=a(rcx)  [0x10]=b(rdx)  [0x18]=c(r8)
        //   [0x20]=e   -> live stack-arg slot #5 required by ABI
        //   [0x28]=f   -> live stack-arg slot #6 required by ABI
        //   [0x30]=d   -> temp, loaded into r9 before the call
        static const uint8_t argSlot[6] = {0x00, 0x08, 0x10, 0x18, 0x30, 0x20};
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40); // sub rsp, 0x40

        for (int k = 0; k < (int)call->args.size(); k++) {
            int ar = emitExpr(call->args[k].get());
            if (ar != 0) { emitMovReg(0, ar); freeReg(ar); }
            else freeReg(0);
            emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24);
            emit8(argSlot[k]);                              // mov [rsp+slot], rax
        }
        if (call->args.size() >= 5)
            { emit8(0x4C); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x30); } // r9 = d (from slot 0x30)
        else
            { emit8(0x45); emit8(0x31); emit8(0xC9); }      // r9d = 0
        if (call->args.size() >= 1)
            { emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x08); } // rcx = a
        else
            { emit8(0x48); emit8(0x31); emit8(0xC9); }      // rcx = 0
        if (call->args.size() >= 2)
            { emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x10); } // rdx = b
        else
            { emit8(0x48); emit8(0x31); emit8(0xD2); }      // rdx = 0
        if (call->args.size() >= 3)
            { emit8(0x4C); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x18); } // r8  = c
        else
            { emit8(0x4D); emit8(0x31); emit8(0xC0); }      // r8  = 0
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x00); // rax = fn
        emit8(0xFF); emit8(0xD0);                           // call rax
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x40); // add rsp, 0x40

        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // mem_copy_q(dst, src, qwords) — rep movsq blit. Used by the console
    // scroll (60+ KiB per line) instead of an interpreted poke() loop.
    if (call->name == "mem_copy_q" && call->args.size() == 3 &&
        prog.appType == AppType::EFI) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int ra = emitExpr(call->args[0].get());   // dst -> rdi
        int rb = emitExpr(call->args[1].get());   // src -> rsi
        int rc = emitExpr(call->args[2].get());   // cnt -> rcx
        if (ra != 7) { emitMovReg(7, ra); freeReg(ra); } else freeReg(7);
        if (rb != 6) { emitMovReg(6, rb); freeReg(rb); } else freeReg(6);
        if (rc != 1) { emitMovReg(1, rc); freeReg(rc); } else freeReg(1);
        emit8(0xFC);                              // cld
        emit8(0xF3); emit8(0x48); emit8(0xA5);    // rep movsq
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // io_insw(port, dst, words) — rep insw: ATA PIO sector transfer.
    // One string instruction replaces the 256-iteration inw()/poke() loop.
    if (call->name == "io_insw" && call->args.size() == 3 &&
        prog.appType == AppType::EFI) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int ra = emitExpr(call->args[0].get());   // port -> edx
        int rb = emitExpr(call->args[1].get());   // dst  -> rdi
        int rc = emitExpr(call->args[2].get());   // cnt  -> rcx
        if (ra != 2) { emitMovReg(2, ra); freeReg(ra); } else freeReg(2);
        if (rb != 7) { emitMovReg(7, rb); freeReg(rb); } else freeReg(7);
        if (rc != 1) { emitMovReg(1, rc); freeReg(rc); } else freeReg(1);
        emit8(0xFC);                              // cld
        emit8(0xF3); emit8(0x6D);                 // rep insw
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== PS/2 Keyboard (BIOS / bare-metal, no BIOS int) ==============
    // Polls the legacy 8042 controller via ports 0x64 (status) and 0x60 (data).
    //   kb_hit()  -> 1 if at least one scancode is pending (status bit 0), else 0
    //   kb_get()  -> blocking read of one scancode (raw byte from 0x60).
    // Scancode is "set 1" (PC/AT make codes), e.g. 'a' = 0x1E, Enter = 0x1C,
    // Space = 0x39. Translation to a character is left to the source program,
    // so keyboard layout can be chosen freely.
    if (call->name == "kb_hit" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xBA); emit8(0x64); emit8(0x00); emit8(0x00); emit8(0x00); // mov edx, 0x64
        emit8(0xEC);                            // in al, dx
        emit8(0x24); emit8(0x01);               // and al, 1
        emit8(0x0F); emit8(0xB6); emit8(0xC0);  // movzx eax, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    if (call->name == "kb_get" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int waitLbl = newLabel();
        // rbx = persistent pointer to port 0x60 (avoids re-loading dx each loop)
        emitLabel(waitLbl);
        emit8(0xBA); emit8(0x64); emit8(0x00); emit8(0x00); emit8(0x00); // mov edx, 0x64
        emit8(0xEC);                             // in al, dx
        emit8(0x24); emit8(0x01);               // and al, 1
        emitJcc("==", waitLbl);                 // no data -> keep polling
        emit8(0xBA); emit8(0x60); emit8(0x00); emit8(0x00); emit8(0x00); // mov edx, 0x60
        emit8(0xEC);                             // in al, dx
        emit8(0x0F); emit8(0xB6); emit8(0xC0);  // movzx eax, al
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // ============== TSC + I/O delay (both modes, no firmware needed) ==============
    // rdtsc() -> 64-bit Time-Stamp Counter (useful for timing, spin-locks, boot
    // profiling). Works in independent and dependent mode alike.
    if (call->name == "rdtsc" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x0F); emit8(0x31);   // rdtsc (edx:eax)
        emit8(0x48); emit8(0xC1); emit8(0xE2); emit8(0x20); // shl rdx, 32
        emit8(0x48); emit8(0x09); emit8(0xC2); // or rdx, rax
        emit8(0x48); emit8(0x89); emit8(0xD0); // mov rax, rdx
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // io_delay() — small I/O delay: write to port 0x80 (standard "post" port).
    // Classic trick used by kernels at boot (PS/2 init, etc.) to let the
    // controller settle without interrupts.
    if (call->name == "io_delay" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0xBA); emit8(0x80); emit8(0x00); emit8(0x00); emit8(0x00); // mov edx, 0x80
        emit8(0xB0); emit8(0x00); // mov al, 0
        emit8(0xEE);              // out dx, al
        emit8(0xEE);              // out dx, al (double write = classic two-cycle delay)
        regsUsed = (uint8_t)saved;
        reloadRegs();
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // ================= GUI WINDOWS / TOOL BUILTINS (Zenith Studio) =================
    // These are generic Win32-backed builtins used by the IDE (code editor,
    // scene editor) and the game runtime. Available in GUI console-tool apps;
    // they wrap user32/kernel32 so they only make sense on the Windows PE target.

    // --- glyphAt(x, y, ch, color) ---
    // Draw a single 5x7 bitmap glyph at pixel (x, y). Pixels outside the
    // framebuffer are clipped (the other draw* builtins do NOT clip, but the
    // editor needs safe off-window text near the right/bottom edge).
    if (call->name == "glyphAt" && call->args.size() == 4) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int cReg = emitExpr(call->args[3].get());
        if (cReg != 0) { emitMovReg(0, cReg); freeReg(cReg); } else freeReg(0);
        emit8(0x50);
        int tReg = emitExpr(call->args[2].get());
        if (tReg != 0) { emitMovReg(0, tReg); freeReg(tReg); } else freeReg(0);
        emit8(0x50);
        int yReg = emitExpr(call->args[1].get());
        if (yReg != 0) { emitMovReg(0, yReg); freeReg(yReg); } else freeReg(0);
        emit8(0x50);
        int xReg = emitExpr(call->args[0].get());
        if (xReg != 0) { emitMovReg(0, xReg); freeReg(xReg); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);  // pop r8  (x)
        emit8(0x41); emit8(0x59);  // pop r9  (y)
        emit8(0x41); emit8(0x5A);  // pop r10 (ch)
        emit8(0x41); emit8(0x5B);  // pop r11 (color)

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        emit8(0x4C); emit8(0x8B); emit8(0x6B); emit8(0x28);  // r13 = fb
        emit8(0x44); emit8(0x8B); emit8(0x73); emit8(0x20);  // r14d = width
        emit8(0x44); emit8(0x8B); emit8(0x7B); emit8(0x24);  // r15d = height
        emit8(0x4D); emit8(0x85); emit8(0xED);               // test r13, r13
        int skipGlyph = newLabel();
        emitJcc("==", skipGlyph);

        // clamp ch to 32..126 so out-of-range (tab, newline) maps to a space
        emit8(0x41); emit8(0x83); emit8(0xFA); emit8(0x20);  // cmp r10d, 32
        int gNoLo = newLabel();
        emitJcc(">=", gNoLo);
        emit8(0x41); emit8(0xBA); emit32(32);
        emitLabel(gNoLo);
        emit8(0x41); emit8(0x83); emit8(0xFA); emit8(0x7E);  // cmp r10d, 126
        int gNoHi = newLabel();
        emitJcc("<=", gNoHi);
        emit8(0x41); emit8(0xBA); emit32(126);
        emitLabel(gNoHi);

        emit8(0x41); emit8(0x83); emit8(0xEA); emit8(0x20);  // sub r10d, 32
        emit8(0x4D); emit8(0x6B); emit8(0xD2); emit8(0x07);  // imul r10, r10, 7
        emit8(0x4C); emit8(0x8D); emit8(0x25);
        heapFixups.push_back({code.size(), fontRVA});
        emit32(0);                                            // r12 = font
        emit8(0x4D); emit8(0x01); emit8(0xE2);               // add r10, r12 (glyph)

        emit8(0x31); emit8(0xC0);                            // xor eax, eax (row)
        int glyphRowL = newLabel();
        int glyphBitL = newLabel();
        int glyphPxSkip = newLabel();
        int glyphBitSkip = newLabel();
        emitLabel(glyphRowL);
        emit8(0x49); emit8(0x0F); emit8(0xB6); emit8(0x0C); emit8(0x02); // movzx rcx, byte[r10+rax]
        emit8(0x50);                                         // push rax (row)
        emit8(0x51);                                         // push rcx (byte)
        emit8(0x31); emit8(0xD2);                            // xor edx, edx (bit)
        emitLabel(glyphBitL);
        emit8(0x48); emit8(0x8B); emit8(0x0C); emit8(0x24);  // rcx = [rsp] (byte)
        emit8(0xF6); emit8(0xC1); emit8(0x01);               // test cl, 1
        emitJcc("==", glyphBitSkip);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x08);  // rax = [rsp+8] (row)
        emit8(0x4C); emit8(0x01); emit8(0xC8);               // add rax, r9 (y+row)
        emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
        emitJcc("<", glyphPxSkip);                           // y+row < 0 -> clip
        emit8(0x4C); emit8(0x39); emit8(0xF8);               // cmp rax, r15
        emitJcc(">=", glyphPxSkip);                          // y+row >= height -> clip
        emit8(0x49); emit8(0x0F); emit8(0xAF); emit8(0xC6);  // imul rax, r14 (width)
        emit8(0xBB); emit32(4);                              // mov ebx, 4
        emit8(0x48); emit8(0x29); emit8(0xD3);               // sub rbx, rdx
        emit8(0x4C); emit8(0x01); emit8(0xC3);              // add rbx, r8 (px)
        emit8(0x48); emit8(0x85); emit8(0xDB);               // test rbx, rbx
        emitJcc("<", glyphPxSkip);                           // px < 0 -> clip
        emit8(0x4C); emit8(0x39); emit8(0xF3);               // cmp rbx, r14
        emitJcc(">=", glyphPxSkip);                          // px >= width -> clip
        emit8(0x48); emit8(0x01); emit8(0xD8);               // add rax, rbx
        emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x02);  // shl rax, 2
        emit8(0x4C); emit8(0x01); emit8(0xE8);               // add rax, r13 (+fb)
        emit8(0x44); emit8(0x89); emit8(0x18);               // mov [rax], r11d
        emitLabel(glyphPxSkip);
        emitLabel(glyphBitSkip);
        emit8(0x48); emit8(0x8B); emit8(0x0C); emit8(0x24);  // rcx = [rsp] (byte)
        emit8(0x48); emit8(0xD1); emit8(0xE9);               // shr rcx, 1
        emit8(0x48); emit8(0x89); emit8(0x0C); emit8(0x24);  // [rsp] = rcx
        emit8(0x48); emit8(0xFF); emit8(0xC2);               // inc rdx
        emit8(0x48); emit8(0x83); emit8(0xFA); emit8(0x05);  // cmp rdx, 5
        emitJcc("<", glyphBitL);
        emit8(0x59);                                         // pop rcx
        emit8(0x58);                                         // pop rax
        emit8(0x48); emit8(0xFF); emit8(0xC0);               // inc rax
        emit8(0x48); emit8(0x83); emit8(0xF8); emit8(0x07);  // cmp rax, 7
        emitJcc("<", glyphRowL);
        emitLabel(skipGlyph);

        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // --- mouseX() / mouseY() ---
    // GetCursorPos + ScreenToClient against the app window; returns the
    // cursor position in client pixels (or whatever GetCursorPos leaves if
    // ScreenToClient fails).
    auto emitMouseGet = [&](int fieldOffset) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x40);
        emit8(0x48); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x28);  // rcx = &pt
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetCursorPos", "user32.dll"});
        emit32(0);
        emit8(0x85); emit8(0xC0);
        int mFail = newLabel();
        emitJcc("==", mFail);
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x08);   // rcx = hwnd
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x28);  // rdx = &pt
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "ScreenToClient", "user32.dll"});
        emit32(0);
        emitLabel(mFail);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8((uint8_t)fieldOffset); // eax = pt.x/y
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x40);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    };
    if (call->name == "mouseX" && call->args.empty()) { emitMouseGet(0x28 + 0); return true; }
    if (call->name == "mouseY" && call->args.empty()) { emitMouseGet(0x28 + 4); return true; }

    // --- mouseBtn(button) -> int ---
    // High bit of GetAsyncKeyState for a mouse button (VK_LBUTTON=1, ...).
    if (call->name == "mouseBtn" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int bReg = emitExpr(call->args[0].get());
        if (bReg != 0) { emitMovReg(0, bReg); freeReg(bReg); } else freeReg(0);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
        emit8(0x89); emit8(0xC1);                            // mov ecx, eax
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetAsyncKeyState", "user32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
        emit8(0xC1); emit8(0xE8); emit8(0x0F);               // shr eax, 15
        emit8(0x83); emit8(0xE0); emit8(0x01);               // and eax, 1
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- tapKey(vk) -> int ---
    // GetAsyncKeyState LSB (0x0001): key was pressed since the previous call.
    if (call->name == "tapKey" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int vkReg = emitExpr(call->args[0].get());
        if (vkReg != 0) { emitMovReg(0, vkReg); freeReg(vkReg); } else freeReg(0);
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
        emit8(0x89); emit8(0xC1);                            // mov ecx, eax
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetAsyncKeyState", "user32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
        emit8(0x83); emit8(0xE0); emit8(0x01);               // and eax, 1
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- typeChar() -> int ---
    // Returns one typed printable character per call (0 if none). US-layout
    // ASCII mapping using GetAsyncKeyState + VK_SHIFT, so it produces the same
    // characters the compiler accepts in source (laters incl. upper/lowercase,
    // shifted digit-row symbols and punctuation).
    if (call->name == "typeChar" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        auto emitAsync = [&](int vk) {
            emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
            emit8(0xB9); emit32((uint32_t)(int32_t)vk);      // mov ecx, vk
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "GetAsyncKeyState", "user32.dll"});
            emit32(0);
            emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);
        };
        auto emitShiftScore = [&]() {
            emitAsync(0x10);                                 // VK_SHIFT
            emit8(0xC1); emit8(0xE8); emit8(0x0F);           // shr eax, 15
            emit8(0x83); emit8(0xE0); emit8(0x01);           // and eax, 1
        };
        int kDone = newLabel();
        struct CV { int vk; int plain; int shifted; };
        vector<CV> keys;
        keys.push_back({0x08, 8, 8});    // backspace
        keys.push_back({0x09, 9, 9});    // tab
        keys.push_back({0x0D, 13, 13});  // enter
        keys.push_back({0x20, ' ', ' '});
        const char* dshift = ")!@#$%^&*(";
        for (int vk = 0x30; vk <= 0x39; vk++) keys.push_back({vk, vk, dshift[vk - 0x30]});
        const int oemv[][3] = {
            {0xBA, ';', ':'}, {0xBB, '=', '+'}, {0xBC, ',', '<'}, {0xBD, '-', '_'},
            {0xBE, '.', '>'}, {0xBF, '/', '?'}, {0xC0, '`', '~'}, {0xDB, '[', '{'},
            {0xDC, '\\', '|'}, {0xDD, ']', '}'}, {0xDE, '\'', '"'}
        };
        for (auto& o : oemv) keys.push_back({o[0], o[1], o[2]});
        for (int vk = 0x41; vk <= 0x5A; vk++) keys.push_back({vk, vk + 0x20, vk});
        for (auto& k : keys) {
            int nextK = newLabel();
            emitAsync(k.vk);
            emit8(0x83); emit8(0xE0); emit8(0x01);           // and eax, 1 (edge)
            emitJcc("==", nextK);
            if (k.plain == k.shifted) {
                emitMovRegImm(0, k.plain);
                emitJmp(kDone);
            } else {
                emitShiftScore();
                int plainL = newLabel();
                emitJcc("==", plainL);                       // shift not held -> plain
                emitMovRegImm(0, k.shifted);
                emitJmp(kDone);
                emitLabel(plainL);
                emitMovRegImm(0, k.plain);
                emitJmp(kDone);
            }
            emitLabel(nextK);
        }
        emitMovRegImm(0, 0);
        emitLabel(kDone);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- memNew(n) -> int / memDel(p) ---
    // HeapAlloc/HeapFree wrappers (GetProcessHeap). memNew zero-fills (flag 8).
    if (call->name == "memNew" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int nReg = emitExpr(call->args[0].get());
        if (nReg != 0) { emitMovReg(0, nReg); freeReg(nReg); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x40);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);  // save n
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetProcessHeap", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);                             // rcx = heap
        emit8(0xBA); emit32(8);                                            // edx = HEAP_ZERO_MEMORY
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x20);   // rax = n
        emit8(0x49); emit8(0x89); emit8(0xC0);                             // r8 = n
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "HeapAlloc", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x40);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }
    if (call->name == "memDel" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pReg = emitExpr(call->args[0].get());
        if (pReg != 0) { emitMovReg(0, pReg); freeReg(pReg); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x40);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);  // save p
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetProcessHeap", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);                             // rcx = heap
        emit8(0x31); emit8(0xD2);                                          // edx = 0
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x20);   // rax = p
        emit8(0x49); emit8(0x89); emit8(0xC0);                             // r8 = p
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "HeapFree", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x40);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- memByte(p, off) -> int  / memByteW(p, off, v) ---
    // Signed? No: reads are zero-extended bytes, writes write a single byte.
    if (call->name == "memByte" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x50);
        int or_ = emitExpr(call->args[1].get());
        if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);                       // pop r8 (off)
        emit8(0x41); emit8(0x59);                       // pop r9 (p)
        emit8(0x4D); emit8(0x01); emit8(0xC1);          // add r9, r8
        emit8(0x41); emit8(0x0F); emit8(0xB6); emit8(0x01);  // movzx eax, byte[r9]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }
    if (call->name == "memByteW" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x50);
        int or_ = emitExpr(call->args[1].get());
        if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
        emit8(0x50);
        int vr = emitExpr(call->args[2].get());
        if (vr != 0) { emitMovReg(0, vr); freeReg(vr); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);                       // pop r8 (v)
        emit8(0x41); emit8(0x59);                       // pop r9 (off)
        emit8(0x41); emit8(0x5A);                       // pop r10 (p)
        emit8(0x4D); emit8(0x01); emit8(0xD1);          // add r9, r10
        emit8(0x45); emit8(0x88); emit8(0x01);          // mov [r9], r8b
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- memQ(p, off) -> int  / memQw(p, off, v) ---
    if (call->name == "memQ" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x50);
        int or_ = emitExpr(call->args[1].get());
        if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);                       // pop r8 (off)
        emit8(0x41); emit8(0x59);                       // pop r9 (p)
        emit8(0x4D); emit8(0x01); emit8(0xC1);          // add r9, r8
        emit8(0x49); emit8(0x8B); emit8(0x01);          // mov rax, [r9]
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }
    if (call->name == "memQw" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x50);
        int or_ = emitExpr(call->args[1].get());
        if (or_ != 0) { emitMovReg(0, or_); freeReg(or_); } else freeReg(0);
        emit8(0x50);
        int vr = emitExpr(call->args[2].get());
        if (vr != 0) { emitMovReg(0, vr); freeReg(vr); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);                       // pop r8 (v)
        emit8(0x41); emit8(0x59);                       // pop r9 (off)
        emit8(0x41); emit8(0x5A);                       // pop r10 (p)
        emit8(0x4D); emit8(0x01); emit8(0xD1);          // add r9, r10
        emit8(0x4D); emit8(0x89); emit8(0x01);          // mov [r9], r8
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- fileLoad(path) -> int ---
    // Returns a heap header pointer, or 0 on failure.
    //   [hdr+0]  = file length (qword)
    //   [hdr+8]  = reserved (0)
    //   [hdr+16] = file bytes
    // The caller translates what it needs into its own buffers and calls
    // memDel(hdr) when done.
    if (call->name == "fileLoad" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x60);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x50);  // [rsp+0x50] = path
        // CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NORMAL, NULL)
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x50);  // rcx = path
        emit8(0xBA); emit32(0x80000000);                   // edx = GENERIC_READ
        emit8(0x41); emit8(0xB8); emit32(1);               // r8d = FILE_SHARE_READ
        emit8(0x45); emit8(0x31); emit8(0xC9);             // r9d = 0 (security)
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(3);  // OPEN_EXISTING
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80); // NORMAL
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);   // hTemplate
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);             // r12 = hFile
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);  // cmp r12, -1
        int fFailNoClose = newLabel();
        emitJcc("==", fFailNoClose);
        // GetFileSizeEx(hFile, &size) ; size -> [rsp+0x38]
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x38);  // rdx = &size
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetFileSizeEx", "kernel32.dll"});
        emit32(0);
        emit8(0x85); emit8(0xC0);
        int fFailClose = newLabel();
        emitJcc("==", fFailClose);
        emit8(0x4C); emit8(0x8B); emit8(0x6C); emit8(0x24); emit8(0x38);  // r13 = len
        // GetProcessHeap(); HeapAlloc(heap, 8, len+16)
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "GetProcessHeap", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);             // rcx = heap
        emit8(0xBA); emit32(8);                            // edx = HEAP_ZERO_MEMORY
        emit8(0x4D); emit8(0x8D); emit8(0x45); emit8(0x10); // lea r8, [r13+16]
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "HeapAlloc", "kernel32.dll"});
        emit32(0);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("==", fFailClose);
        emit8(0x49); emit8(0x89); emit8(0xC7);             // r15 = header
        emit8(0x4D); emit8(0x89); emit8(0x2F);             // [r15+0] = len
        // ReadFile(hFile, data, len, &written, NULL)
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0x49); emit8(0x8D); emit8(0x57); emit8(0x10); // rdx = data
        emit8(0x4D); emit8(0x89); emit8(0xE8);             // r8 = len
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x48);  // r9 = &written
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "ReadFile", "kernel32.dll"});
        emit32(0);
        // CloseHandle(hFile); return header
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xF8);             // rax = header
        int fDone = newLabel();
        emitJmp(fDone);
        emitLabel(fFailClose);
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emitLabel(fFailNoClose);
        emit8(0x31); emit8(0xC0);                          // eax = 0
        emitLabel(fDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x60);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- fileSave(path, data, len) -> int ---
    // Overwrites path with data bytes; returns number of bytes written (0=fail).
    if (call->name == "fileSave" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x50);
        int dr = emitExpr(call->args[1].get());
        if (dr != 0) { emitMovReg(0, dr); freeReg(dr); } else freeReg(0);
        emit8(0x50);
        int lr = emitExpr(call->args[2].get());
        if (lr != 0) { emitMovReg(0, lr); freeReg(lr); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x58);                          // pop r8 (len)
        emit8(0x41); emit8(0x59);                          // pop r9 (data)
        emit8(0x41); emit8(0x5A);                          // pop r10 (path)
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x60);
        emit8(0x4C); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x50);  // save len
        emit8(0x4C); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x48);  // save data
        // CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, NORMAL, NULL)
        emit8(0x4C); emit8(0x89); emit8(0xD1);             // rcx = path
        emit8(0xBA); emit32(0x40000000);                   // GENERIC_WRITE
        emit8(0x45); emit8(0x31); emit8(0xC0);             // r8d = 0 (no share)
        emit8(0x45); emit8(0x31); emit8(0xC9);             // r9d = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);   // CREATE_ALWAYS
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80); // NORMAL
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);             // r12 = hFile
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);  // cmp r12, -1
        int sFail = newLabel();
        emitJcc("==", sFail);
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x48);  // rdx = data
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x50);  // rax = len
        emit8(0x49); emit8(0x89); emit8(0xC0);             // r8 = len
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x40);  // r9 = &written
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = hFile
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x40); // eax = written
        int sDone = newLabel();
        emitJmp(sDone);
        emitLabel(sFail);
        emit8(0x31); emit8(0xC0);
        emitLabel(sDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x60);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- fileExists(path) -> int ---
    if (call->name == "fileExists" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x40);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);  // save path
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x20);  // rcx = path
        emit8(0x31); emit8(0xD2);                          // edx = 0 (query attrs)
        emit8(0x41); emit8(0xB8); emit32(7);               // r8d = share all
        emit8(0x45); emit8(0x31); emit8(0xC9);             // r9d = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(3);   // OPEN_EXISTING
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80); // NORMAL
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);             // r12 = handle
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);  // cmp r12, -1
        int eBad = newLabel();
        emitJcc("==", eBad);
        emit8(0x4C); emit8(0x89); emit8(0xE1);             // rcx = handle
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emit8(0xB8); emit32(1);
        int eDone = newLabel();
        emitJmp(eDone);
        emitLabel(eBad);
        emit8(0x31); emit8(0xC0);
        emitLabel(eDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x40);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- chdir(path) -> int ---
    // Set the process current directory (SetCurrentDirectoryA). 1=ok, 0=fail.
    if (call->name == "chdir" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x40);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);  // save path
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x20);  // rcx = path
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "SetCurrentDirectoryA", "kernel32.dll"});
        emit32(0);
        emit8(0x85); emit8(0xC0);                        // test eax,eax (BOOL)
        int cdFail = newLabel();
        emitJcc("==", cdFail);
        emit8(0xB8); emit32(1);
        int cdDone = newLabel();
        emitJmp(cdDone);
        emitLabel(cdFail);
        emit8(0x31); emit8(0xC0);
        emitLabel(cdDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x40);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- spawn(path) -> int ---
    // Launch path (NUL-terminated pointer, literal or runtime buffer) via
    // CreateProcessA. Returns 1 on success, 0 on failure.
    if (call->name == "spawn" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int pr = emitExpr(call->args[0].get());
        if (pr != 0) { emitMovReg(0, pr); freeReg(pr); } else freeReg(0);
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x100);        // sub rsp,0x100
        // save path FIRST ([rsp+0xC0]) while rax still holds it
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit8(0xC0); emit8(0x00); emit8(0x00); emit8(0x00); // [rsp+0xC0]=path
        // then zero si[0x60..0xA8) + pi[0xA8..0xC0) in one block [0x60..0xC0)
        emit8(0x48); emit8(0x8D); emit8(0x7C); emit8(0x24); emit8(0x60);
        emit8(0x31); emit8(0xC0);
        emit8(0xB9); emit32(12);
        emit8(0xF3); emit8(0x48); emit8(0xAB);               // rep stosq (12*8=96 B)
        // arguments [0x20..0x50) stay reserved for the 5th..8th + 9th/10th
        emit8(0xC7); emit8(0x84); emit8(0x24); emit8(0x60); emit8(0x00); emit8(0x00); emit8(0x00); emit32(0x44); // si.cb=0x44
        emit8(0x31); emit8(0xC9);                                        // xor ecx,ecx => lpApplicationName=NULL
        emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit8(0xC0); emit8(0x00); emit8(0x00); emit8(0x00); // edx=path => lpCommandLine
        emit8(0x45); emit8(0x31); emit8(0xC0);                           // r8d=0
        emit8(0x45); emit8(0x31); emit8(0xC9);                           // r9d=0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x60); // rax=&si
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x40); // [rsp+0x40]=&si (9th arg)
        emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit8(0xA8); emit8(0x00); emit8(0x00); emit8(0x00); // rax=&pi
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48); // [rsp+0x48]=&pi (10th arg)
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateProcessA", "kernel32.dll"});
        emit32(0);
        emit8(0x85); emit8(0xC0);                                       // test eax,eax
        int spFail = newLabel();
        emitJcc("==", spFail);
        emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit8(0xB0); emit8(0x00); emit8(0x00); emit8(0x00); // rcx=pi.hThread
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emit8(0xB8); emit32(1);
        int spDone = newLabel();
        emitJmp(spDone);
        emitLabel(spFail);
        emit8(0x31); emit8(0xC0);
        emitLabel(spDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x100);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    // --- dirNames(dst, cap) -> int ---
    // Lists the current-directory entries into dst as '\n'-separated names.
    // Skips "." and "..". Returns bytes written, or 0 on failure/overflow.
    if (call->name == "dirNames" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        int d0 = emitExpr(call->args[0].get());
        if (d0 != 0) { emitMovReg(0, d0); freeReg(d0); } else freeReg(0);
        emit8(0x50);
        int d1 = emitExpr(call->args[1].get());
        if (d1 != 0) { emitMovReg(0, d1); freeReg(d1); } else freeReg(0);
        emit8(0x50);
        emit8(0x41); emit8(0x59);                       // pop r9 (cap)
        emit8(0x41); emit8(0x5A);                       // pop r10 (dst)
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x300);
        emit8(0x4C); emit8(0x89); emit8(0x94); emit8(0x24); emit8(0xD0); emit8(0x02); emit8(0x00); emit8(0x00); // [rsp+0x2D0]=dst
        emit8(0x4C); emit8(0x89); emit8(0x8C); emit8(0x24); emit8(0xD8); emit8(0x02); emit8(0x00); emit8(0x00); // [rsp+0x2D8]=cap
        // pattern "*.*\0" at [rsp+0x2E0]
        emit8(0xC6); emit8(0x84); emit8(0x24); emit8(0xE0); emit8(0x02); emit8(0x00); emit8(0x00); emit8(0x2A);
        emit8(0xC6); emit8(0x84); emit8(0x24); emit8(0xE1); emit8(0x02); emit8(0x00); emit8(0x00); emit8(0x2E);
        emit8(0xC6); emit8(0x84); emit8(0x24); emit8(0xE2); emit8(0x02); emit8(0x00); emit8(0x00); emit8(0x2A);
        emit8(0xC6); emit8(0x84); emit8(0x24); emit8(0xE3); emit8(0x02); emit8(0x00); emit8(0x00); emit8(0x00);
        emit8(0x48); emit8(0x8D); emit8(0x8C); emit8(0x24); emit8(0xE0); emit8(0x02); emit8(0x00); emit8(0x00); // rcx=&pattern
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x40); // rdx=&fd
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "FindFirstFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x83); emit8(0xF8); emit8(0xFF);          // cmp eax,-1
        int dnFail = newLabel();
        emitJcc("==", dnFail);
        emit8(0x49); emit8(0x89); emit8(0xC5);          // r13 = handle
        emit8(0x4C); emit8(0x8B); emit8(0xBC); emit8(0x24); emit8(0xD0); emit8(0x02); emit8(0x00); emit8(0x00); // r15 = dst ([rsp+0x2D0])
        int dnOverflow = newLabel();
        int dnNext = newLabel();
        int dnLoop = newLabel();
        emitLabel(dnLoop);
        emit8(0x48); emit8(0x8D); emit8(0xBC); emit8(0x24); emit8(0x6C); emit8(0x00); emit8(0x00); emit8(0x00); // lea rdi,[rsp+0x40+0x2C]=fd.cFileName
        emit8(0x45); emit8(0x31); emit8(0xE4);          // r12d=0 (len)
        int dnStr = newLabel();
        int dnStrEnd = newLabel();
        emitLabel(dnStr);
        emit8(0x0F); emit8(0xB6); emit8(0x07);          // movzx eax, byte[rdi]
        emit8(0x84); emit8(0xC0);
        emitJcc("==", dnStrEnd);
        emit8(0x48); emit8(0xFF); emit8(0xC7);          // inc rdi
        emit8(0x49); emit8(0xFF); emit8(0xC4);          // inc r12
        emit8(0x0F); emit8(0x1F); emit8(0x00);          // nop (alignment)
        emitJmp(dnStr);
        emitLabel(dnStrEnd);
        // skip "." and ".."
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0x01);  // cmp r12,1
        int skipDot = newLabel();
        emitJcc("!=", skipDot);
        // cmp byte[fd.cFileName], '.'
        emit8(0x80); emit8(0xBC); emit8(0x24); emit8(0x6C); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x2E);
        int dnDot = newLabel();
        emitJcc("==", dnDot);
        emitLabel(skipDot);
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0x02);  // cmp r12,2
        int dnNot2 = newLabel();
        emitJcc("!=", dnNot2);
        // cmp word[fd.cFileName], 0x2E2E
        emit8(0x66); emit8(0x81); emit8(0xBC); emit8(0x24); emit8(0x6C); emit8(0x00); emit8(0x00); emit8(0x00); emit8(0x2E); emit8(0x2E);
        emitJcc("==", dnDot);
        emitLabel(dnNot2);
        // cap check: r15-dst + r12 + 1 > cap -> overflow
        emit8(0x4C); emit8(0x89); emit8(0xF8);          // rax=r15 (dst progress)
        emit8(0x48); emit8(0x2B); emit8(0x84); emit8(0x24); emit8(0xD0); emit8(0x02); emit8(0x00); emit8(0x00); // sub rax,[rsp+0x2D0]
        emit8(0x4C); emit8(0x01); emit8(0xE0);          // add rax,r12
        emit8(0x48); emit8(0xFF); emit8(0xC0);          // inc rax
        emit8(0x48); emit8(0x3B); emit8(0x84); emit8(0x24); emit8(0xD8); emit8(0x02); emit8(0x00); emit8(0x00); // cmp rax,[rsp+0x2D8]
        emitJcc(">", dnOverflow);
        // copy name: rsi=fd+0x2C, rdi=r15, rcx=r12, rep movsb
        emit8(0x48); emit8(0x8D); emit8(0xB4); emit8(0x24); emit8(0x6C); emit8(0x00); emit8(0x00); emit8(0x00); // lea rsi,[rsp+0x40+0x2C]=fd.cFileName
        emit8(0x4C); emit8(0x89); emit8(0xE1);          // rcx = r12
        emit8(0x4C); emit8(0x89); emit8(0xFF);          // rdi = r15
        emit8(0xF3); emit8(0x48); emit8(0xA4);          // rep movsb
        emit8(0x49); emit8(0x89); emit8(0xFF);          // r15 = rdi (advanced)
        emit8(0xC6); emit8(0x07); emit8(0x0A);          // byte[r15]=0x0A
        emit8(0x49); emit8(0xFF); emit8(0xC7);          // inc r15
        emitJmp(dnNext);
        emitLabel(dnDot);
        emitLabel(dnNext);
        // FindNextFileA(handle, &fd)
        emit8(0x4C); emit8(0x89); emit8(0xE9);          // rcx = r13
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x40); // rdx=&fd
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "FindNextFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x85); emit8(0xC0);
        emitJcc("!=", dnLoop);
        emitJmp(dnOverflow);
        emitLabel(dnOverflow);
        // FindClose(handle); rax = r15 - dst
        emit8(0x4C); emit8(0x89); emit8(0xE9);          // rcx = r13
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "FindClose", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xF8);          // rax = r15
        emit8(0x48); emit8(0x2B); emit8(0x84); emit8(0x24); emit8(0xD0); emit8(0x02); emit8(0x00); emit8(0x00); // sub rax,[rsp+0x2D0]
        int dnDone = newLabel();
        emitJmp(dnDone);
        emitLabel(dnFail);
        emit8(0x31); emit8(0xC0);
        emitLabel(dnDone);
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x300);
        regsUsed = (uint8_t)(saved & ~1);
        reloadRegs();
        regsUsed = (uint8_t)(saved | 1);
        resultReg = 0;
        return true;
    }

    return false;
}
