; ===========================================================================
; asmrt_enc.inc -- byte output, prefix emission, ModRM/SIB/disp encoding.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_emit_b(al) -- append one byte. rdx is the only scratch register used
; here and it is saved: callers keep loop bounds in edx, and the store path
; (g_out != 0, i.e. pass 2) used to overwrite it, so multi-byte helpers
; emitted fewer bytes on the emit pass than they had sized for.
; ---------------------------------------------------------------------------
asmf_emit_b:
    push rbx
    push rdx
    mov rbx, [g_out]
    test rbx, rbx
    jz .count
    mov rdx, [g_pos]
    cmp rdx, [g_cap]
    jae .count
    mov [rbx + rdx], al
.count:
    inc qword [g_pos]
    pop rdx
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_n(eax = value, edi = width in bytes) -- little-endian append
; The value is peeled off a byte at a time: shifting by the loop counter
; rather than by counter*8 emitted value>>0, value>>1, value>>2 ... instead
; of value>>0, value>>8, value>>16 ...
; ---------------------------------------------------------------------------
asmf_emit_n:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rax                ; the original value, returned to the caller
    mov r14, rax                ; the bytes still to emit
    mov r13d, edi
.l:
    test r13d, r13d
    jz .d
    mov rax, r14
    and al, 0xFF
    call asmf_emit_b
    mov cl, 8
    shr r14, cl
    dec r13d
    jmp .l
.d:
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_rex(w, r, x, b) -- emits a REX byte when any bit is set, or when
; `force` is passed in dl != 0 (the spl/bpl/sil/dil case).
;   al = W, cl = R, dl = force, r8b = X, r9b = B
; ---------------------------------------------------------------------------
asmf_emit_rex:
    push rbx
    mov bl, al                   ; W
    mov al, cl                   ; R
    shl al, 2
    or bl, al
    mov al, r8b
    shl al, 1
    or bl, al
    or bl, r9b
    test bl, bl
    jnz .emit
    test dl, dl
    jz .d
.emit:
    or bl, 0x40
    mov al, bl
    call asmf_emit_b
.d:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_size_prefix(edx = SZ_*) -- 0x66 for word operands, and nothing for
; everything else. Byte and dword need no prefix; 64-bit uses REX.W instead.
; ---------------------------------------------------------------------------
asmf_emit_size_prefix:
    cmp edx, SZ_W
    jne .d
    mov al, 0x66
    call asmf_emit_b
.d:
    ret

; ---------------------------------------------------------------------------
; asmf_emit_modrm(edi = ModRM byte) -- one byte
; ---------------------------------------------------------------------------
asmf_emit_modrm:
    call asmf_emit_b
    ret

; ---------------------------------------------------------------------------
; asmf_emit_disp(rdi = operand record) -- emits the displacement for a memory
; operand, choosing the width the encoder asked for through g_disp_kind
; (0 = none, 1 = disp8, 2 = disp32).
; ---------------------------------------------------------------------------
asmf_emit_disp:
    push rbx
    mov rbx, rdi
    mov r9, [rbx + OP_VALUE]
    mov ecx, [rbx + OP_SYM]
    test rcx, rcx
    jz .noval
    ; 1-based symbol index, and it has to land in rax for asmf_sym_val
    dec rcx
    mov rax, rcx
    call asmf_sym_val
    add rax, r9
    jmp .now
.noval:
    mov rax, r9
.now:
    mov ecx, [g_disp_kind]
    cmp ecx, 3
    je .rip
    cmp ecx, 1
    je .d8
    cmp ecx, 2
    je .d32
    jmp .d
.rip:
    ; RIP-relative: the distance runs from the end of the instruction, but
    ; the disp32 is not always the last field -- `mov byte [rel b], 0` puts
    ; an immediate behind it.  The value is therefore patched by
    ; asmf_emit_insn once g_pos really is the end of the instruction; the
    ; provisional store below keeps the field defined when nothing follows.
    mov [g_rip_target], rax
    mov rax, [g_pos]
    mov [g_rip_patch], rax
    add rax, 4
    mov rcx, [g_rip_target]
    sub rcx, rax
    mov rax, rcx
    mov edi, 4
    jmp .n
.d8:
    mov edi, 1
    jmp .n
.d32:
    mov edi, 4
.n:
    call asmf_emit_n
.d:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_mem(edi = operand record, esi = reg field, edx = size) --
; the whole ModRM + SIB + disp sequence for a memory r/m operand.
; ---------------------------------------------------------------------------
asmf_emit_mem:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12d, esi                ; reg field
    mov r13d, edx                ; size (kept for callers that need it)

    mov eax, [rbx + OP_BASE]
    mov ecx, [rbx + OP_INDEX]
    mov dword [g_ri_base], eax
    mov dword [g_ri_index], ecx

    ; --- register r/m operand: mod = 11 -------------------------------
    ; Without this every reg,reg instruction fell through to the absolute
    ; addressing path and came out as `modrm sib disp32` over address 0.
    cmp dword [rbx + OP_KIND], K_REG
    jne .notreg
    mov al, 0xC0
    mov ecx, r12d
    and cl, 7
    shl cl, 3
    or al, cl
    mov cl, [rbx + OP_REG]
    and cl, 7
    or al, cl
    call asmf_emit_modrm
    jmp .d

    ; --- RIP-relative: mod=00, rm=101, disp32 --------------------------
    ; This used to sit after an unconditional `jmp .d` and behind a `jne
    ; .norel`, so nothing could ever reach it and `[rel x]` fell through to
    ; the absolute SIB form instead.
.notreg:
    ; `rel` is only meaningful for a displacement-only address: with a
    ; register base NASM drops it and encodes `[rbx]` normally
    cmp dword [g_ri_base], -1
    jne .norel
    cmp dword [g_ri_index], -1
    jne .norel
    mov eax, [rbx + OP_FLAGS]
    test eax, F_REL
    jz .norel
    mov al, r12b
    and al, 7
    shl al, 3
    or al, 0x05
    call asmf_emit_modrm
    mov dword [g_disp_kind], 3
    mov rdi, rbx
    call asmf_emit_disp
    jmp .d

.norel:
    ; --- absolute: no base and no index -> SIB 0x25 --------------------
    cmp dword [g_ri_base], -1
    jne .havebase
    cmp dword [g_ri_index], -1
    jne .noindex
    mov al, r12b
    and al, 7
    shl al, 3
    or al, 0x04
    call asmf_emit_modrm
    mov al, 0x25
    call asmf_emit_b
    mov dword [g_disp_kind], 2
    mov rdi, rbx
    call asmf_emit_disp
    jmp .d

    ; --- index*scale + disp, no base -----------------------------------
.noindex:
    mov al, r12b
    and al, 7
    shl al, 3
    or al, 0x04
    call asmf_emit_modrm
    mov edx, [rbx + OP_SCALE]
    call asmf_scale_log2
    shl al, 6
    mov ecx, [g_ri_index]
    and cl, 7
    shl cl, 3
    or al, cl
    or al, 0x05                  ; no base
    call asmf_emit_b
    mov dword [g_disp_kind], 2
    mov rdi, rbx
    call asmf_emit_disp
    jmp .d

    ; --- base (+ index) -------------------------------------------------
.havebase:
    mov eax, [g_ri_base]
    mov [g_rm_base], eax
    cmp dword [g_ri_index], -1
    jne .bindex

    ; base only. rsp/r12 (low3 == 4) must go through a SIB byte.
    mov edx, eax
    and edx, 7
    cmp edx, 4
    je .b_sib
    mov [g_rm_low], edx
    jmp .b_common
.b_sib:
    mov dword [g_rm_low], 4
    mov byte [g_need_sib], 1
    jmp .b_common
.bindex:
    mov edx, [g_ri_index]
    and edx, 7
    mov dword [g_rm_low], 4            ; SIB is mandatory once an index is used
    mov byte [g_need_sib], 1

.b_common:
    ; pick mod: 00 when the displacement is zero and the base is not
    ; rbp/r13 (which would otherwise encode as "no displacement").
    mov rdi, rbx
    call asmf_mem_disp
    cmp byte [g_disp_kind], 0
    jne .have_disp
    mov ecx, [g_rm_base]
    and ecx, 7
    cmp ecx, 5
    je .force_disp
    jmp .mod0
.force_disp:
    mov byte [g_disp_kind], 1
.have_disp:
    cmp byte [g_disp_kind], 1
    je .mod1
    cmp byte [g_disp_kind], 2
    je .mod2
.mod0:
    xor ecx, ecx
    jmp .emit_modrm
.mod1:
    mov ecx, 1
    jmp .emit_modrm
.mod2:
    mov ecx, 2
.emit_modrm:
    mov al, cl
    shl al, 6
    mov edx, r12d
    and dl, 7
    shl edx, 3
    or al, dl
    mov edx, [g_rm_low]
    or al, dl
    call asmf_emit_modrm
    cmp byte [g_need_sib], 0
    je .no_sib
    mov edx, [rbx + OP_SCALE]
    call asmf_scale_log2
    shl al, 6
    mov ecx, [g_ri_index]
    cmp ecx, -1
    je .sib_noindex
    and cl, 7
    shl cl, 3
    or al, cl
    jmp .sib_emit
.sib_noindex:
    or al, 4 << 3               ; index = 100 (none)
.sib_emit:
    mov ecx, [g_rm_base]
    and cl, 7
    or al, cl
    call asmf_emit_b
.no_sib:
    mov rdi, rbx
    call asmf_emit_disp
.d:
    mov rax, r13
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_mem_disp -- rdi = memory operand. Decides the displacement width and
; returns the (symbol-free) numeric part in rax. Sets g_disp_kind to
; 0 (none), 1 (disp8) or 2 (disp32).
;
; The width must be identical in both passes, so a symbolic displacement
; always uses disp32.
; ---------------------------------------------------------------------------
asmf_mem_disp:
    push rbx
    mov rbx, rdi
    mov eax, [rbx + OP_SYM]
    test rax, rax
    jz .nosym
    ; a symbol in the displacement: always disp32
    mov dword [g_disp_kind], 2
    mov rax, [rbx + OP_VALUE]
    pop rbx
    ret
.nosym:
    mov rax, [rbx + OP_VALUE]
    test rax, rax
    jnz .have
    mov dword [g_disp_kind], 0
    pop rbx
    ret
.have:
    ; fits in a signed byte?
    mov rdx, rax
    shl rdx, 56
    sar rdx, 56
    cmp rdx, rax
    je .d8
    mov dword [g_disp_kind], 2
    pop rbx
    ret
.d8:
    mov dword [g_disp_kind], 1
    pop rbx
    ret

; edx = scale (1/2/4/8) -> al = log2 scale
asmf_scale_log2:
    cmp edx, 8
    je .l3
    cmp edx, 4
    je .l2
    cmp edx, 2
    je .l1
    xor eax, eax
    ret
.l3: mov eax, 3
    ret
.l2: mov eax, 2
    ret
.l1: mov eax, 1
    ret
