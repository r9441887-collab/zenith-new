; ===========================================================================
; asmrt_mem.inc -- `[memory]` parsing and constant expressions.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_parse_mem -- the slot index is in g_oprec and the cursor sits on '['.
; Supports [reg], [reg+reg*scale], [label], [rel label], [label+const] and the
; absolute form. Offsets of registers inside brackets are treated as base /
; index / scale, matching NASM's simplification for x86-64.
; ---------------------------------------------------------------------------
asmf_parse_mem:
    push rbx
    push r12
    push r13
    push r14
    mov eax, [g_oprec]
    OPSLOT rbx, rax, r11

    mov dword [rbx + OP_KIND], K_MEM
    mov dword [rbx + OP_SCALE], 1
    mov dword [g_ri_base], -1
    mov dword [g_ri_index], -1
    mov dword [g_ri_32], 0

    mov rax, [g_cur]
    inc rax                      ; past '['
    mov [g_cur], rax

.loop:
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .bad
    ; not al: rax *is* the cursor here, and `mov al,[rax]` replaces its low
    ; byte, so every `inc rax` afterwards walked to a wild address
    mov r9b, [rax]
    cmp r9b, ']'
    je .close
    cmp r9b, ','
    je .bad

    ; a register?
    call asmf_try_reg
    jc .reg
    ; `rel label`
    call asmf_try_rel
    jc .rel
    ; `abs label`
    call asmf_try_abs
    jc .abs
    ; a bare number or a +/- chain
    call asmf_try_number
    jc .number
    ; otherwise a symbol
    call asmf_sym_here
    cmp dword [g_err], 0
    jne .d
    mov [rbx + OP_SYM], rax       ; already 1-based, 0 = none
    jmp .pm

.rel:
    or dword [rbx + OP_FLAGS], F_REL
    jmp .loop

.abs:
    ; explicit `abs` beats `default rel`
    and dword [rbx + OP_FLAGS], ~F_REL
    or dword [rbx + OP_FLAGS], F_ABS
    jmp .loop

.number:
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .d
    add [rbx + OP_VALUE], rax

    ; trailing `+ const` / `- const`
.pm:
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .loop
    mov r9b, [rax]
    cmp r9b, '+'
    je .pm_plus
    cmp r9b, '-'
    je .pm_minus
    jmp .loop
.pm_plus:
    inc rax
    mov [g_cur], rax
    call asmf_skip_space
    ; `[base+index*scale]`: a register after the sign is the index, not a
    ; number, and feeding it to asmf_parse_number reported "bad number"
    call asmf_try_reg
    jc .reg
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .d
    add [rbx + OP_VALUE], rax
    jmp .loop
.pm_minus:
    inc rax
    mov [g_cur], rax
    call asmf_skip_space
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .d
    sub [rbx + OP_VALUE], rax
    jmp .loop

.reg:
    ; the first register is the base, the second the index
    mov eax, [g_reg_num]
    cmp dword [g_reg_size], SZ_D
    jne .regRole
    mov dword [g_ri_32], 1        ; needs a 67 address-size override
.regRole:
    cmp dword [g_ri_base], -1
    jne .maybe_index
    mov [g_ri_base], eax
    jmp .maybe_scale
.maybe_index:
    cmp dword [g_ri_index], -1
    jne .bad
    mov [g_ri_index], eax
.maybe_scale:
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .loop
    mov r9b, [rax]
    cmp r9b, '*'
    jne .loop
    inc rax
    mov [g_cur], rax
    call asmf_skip_space
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .d
    cmp rax, 8
    je .s8
    cmp rax, 4
    je .s4
    cmp rax, 2
    je .s2
    jmp .bad
.s8:
    mov dword [rbx + OP_SCALE], 8
    jmp .loop
.s4:
    mov dword [rbx + OP_SCALE], 4
    jmp .loop
.s2:
    mov dword [rbx + OP_SCALE], 2
    ; no fall-through into .close: `[base+index*2+disp]` still has text to
    ; read, and treating the `+` as the closing bracket reported "bad operand"
    jmp .loop
.close:
    mov rax, [g_cur]
    inc rax
    mov [g_cur], rax
    ; `default rel` promotes a bare displacement-only symbol reference to
    ; RIP relative. A plain number address (`[0x100]`) carries no symbol and
    ; stays absolute, matching NASM; so does anything with a register base
    ; or index, and an explicit `[abs ...]` always wins.
    mov eax, [rbx + OP_FLAGS]
    test eax, F_REL | F_ABS
    jnz .relDone
    cmp dword [g_defrel], 0
    je .relDone
    cmp dword [g_ri_base], -1
    jne .relDone
    cmp dword [g_ri_index], -1
    jne .relDone
    cmp dword [rbx + OP_SYM], 0
    je .relDone
    or dword [rbx + OP_FLAGS], F_REL
.relDone:
    ; publish the register roles for the encoder
    mov eax, [g_ri_base]
    mov [rbx + OP_BASE], eax
    mov eax, [g_ri_index]
    mov [rbx + OP_INDEX], eax
    ; an explicit size keyword wins; otherwise the encoder infers it
    mov eax, [g_op_size]
    mov [rbx + OP_SIZE], eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.bad:
    mov rdi, E_MEMORY
    call asmf_err_code
.d:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_try_rel -- CF set when the cursor is at the `rel` keyword.
; ---------------------------------------------------------------------------
asmf_try_rel:
    mov r8, 3
    lea rdi, [rel txt_rel]
    jmp asmf_keyeq

; ---------------------------------------------------------------------------
; asmf_try_abs -- CF set when the cursor is at the `abs` keyword.
; ---------------------------------------------------------------------------
asmf_try_abs:
    mov r8, 3
    lea rdi, [rel txt_abs]
    jmp asmf_keyeq

; ---------------------------------------------------------------------------
; asmf_sym_here -- intern the identifier at the cursor. Returns rax = 1-based
; symbol index (0 when the cursor is not on an identifier, or on error).
; ---------------------------------------------------------------------------
asmf_sym_here:
    push rbx
    push r12
    push r13
    mov rbx, [g_cur]
    mov r13, [g_end]
    cmp rbx, r13
    jae .no
    mov al, [rbx]
    call asmf_is_idstart
    jz .no
    mov rdi, rbx
    call asmf_scan_ident          ; rax = length, r11 = one past the name
    mov r12, r11                  ; where g_cur has to land afterwards
    ; rsi holds the end pointer, not the length: using it here passed a source
    ; address as the name length, and the length check in asmf_sym_intern
    ; then reported "too many labels" for any symbol reference at all
    mov rsi, rax
    mov r13, rax
    mov rdi, rbx                  ; intern wants the start pointer
    call asmf_scope_name          ; `.x` refers to the enclosing label's `.x`
    call asmf_sym_intern
    mov [g_cur], r12
    pop r13
    pop r12
    pop rbx
    test rax, rax
    js .none
    ; 1-based: a bare 0 would be indistinguishable from "no symbol", so a
    ; reference to the very first label was silently dropped
    inc eax
    ret
.none:
    xor eax, eax
    ret
.no:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_parse_expr -- a left-to-right evaluator:
;     term (('+'|'-') term)*
; where a term is a number, a symbol or a parenthesised expression. Returns
; rax = the value and publishes the single symbol involved in g_expr_sym
; (0 when the expression is purely numeric). Resolving the symbol is left to
; the encoder, because only pass 2 knows the final addresses.
; ---------------------------------------------------------------------------
asmf_parse_expr:
    push rbx
    ; a purely numeric expression must not inherit the previous one's symbol
    mov dword [g_expr_sym], 0
    mov dword [g_expr_first], 0
    mov dword [g_expr_net], 0
    mov dword [g_expr_sign], 1
    mov dword [g_reloc], 0
    call asmf_expr_term
    cmp dword [g_err], 0
    jne .d
    mov rbx, rax
    call asmf_expr_account
.loop:
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .d
    mov cl, [rax]
    cmp cl, '+'
    je .plus
    cmp cl, '-'
    je .minus
    jmp .d
.plus:
    inc rax
    mov [g_cur], rax
    mov dword [g_expr_sign], 1
    call asmf_skip_space
    call asmf_expr_term
    cmp dword [g_err], 0
    jne .d
    add rbx, rax
    call asmf_expr_account
    jmp .loop
.minus:
    inc rax
    mov [g_cur], rax
    mov dword [g_expr_sign], -1
    call asmf_skip_space
    call asmf_expr_term
    cmp dword [g_err], 0
    jne .d
    sub rbx, rax
    call asmf_expr_account
    jmp .loop
.d:
    mov rax, rbx
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_expr_account -- tally the symbol the term just parsed. g_expr_net is
; how many labels the expression still owes: +1 each time one is added, -1
; when it is subtracted. `a - b` nets zero and is a plain constant, while
; `a + 8` keeps one and stays position dependent.
; ---------------------------------------------------------------------------
asmf_expr_account:
    mov eax, [g_expr_sym]
    test eax, eax
    jz .a
    dec eax
    SYMSLOT rcx, rax, r11
    cmp dword [rcx + SY_ABS], 0
    jne .a                     ; an `equ` is a constant, never a relocation
    mov eax, [g_expr_sym]
    cmp dword [g_expr_first], 0
    jne .sign
    mov [g_expr_first], eax
.sign:
    mov ecx, [g_expr_sign]
    add [g_expr_net], ecx
.a:
    ret

; ---------------------------------------------------------------------------
; asmf_expr_term -- rax = one term. A symbol contributes 0 to the numeric
; value and is remembered in g_expr_sym instead.
; ---------------------------------------------------------------------------
asmf_expr_term:
    push rbx
    mov dword [g_expr_sym], 0
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .bad
    mov r9b, [rax]              ; al would smash the cursor before .paren's inc
    cmp r9b, '('
    je .paren
    call asmf_try_number
    jc .num
    call asmf_sym_here
    test rax, rax
    jz .bad
    ; g_expr_sym is a dword: an 8-byte store here overwrote g_reg_num
    mov [g_expr_sym], eax
    ; the term itself contributes the label's address, so `b - a` folds to
    ; the distance between them instead of 0 - 0
    dec eax
    call asmf_sym_val
    jmp .d
.num:
    call asmf_parse_number
    jmp .d
.paren:
    mov ecx, [g_expr_first]
    mov [g_paren_first], ecx
    mov ecx, [g_expr_net]
    mov [g_paren_net], ecx
    inc rax
    mov [g_cur], rax
    ; asmf_parse_expr and asmf_expr_term recurse into each other, so the
    ; nesting depth is whatever the host stack can take. Without a cap a
    ; source of N open parens dies on the stack guard page (SEGV inside the
    ; blob, no error reported); with it the caller gets E_FORM instead.
    cmp dword [g_depth], MAXDEPTH
    jae .toodeep
    inc dword [g_depth]
    call asmf_parse_expr
    dec dword [g_depth]
    cmp dword [g_err], 0
    jne .d
    mov [g_paren_val], rax
    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .d
    cmp byte [rax], ')'
    jne .bad
    inc rax
    mov [g_cur], rax
    mov ecx, [g_paren_first]
    test ecx, ecx
    jz .paren_net
    cmp dword [g_expr_first], 0
    jne .paren_net
    mov [g_expr_first], ecx
.paren_net:
    mov ecx, [g_paren_net]
    add [g_expr_net], ecx
    mov dword [g_expr_sym], 0
    mov rax, [g_paren_val]
    jmp .d
.bad:
    mov rdi, E_OPERAND
    call asmf_err_code
.d:
    pop rbx
    ret
.toodeep:
    mov rdi, E_FORM
    call asmf_err_code
    jmp .d

; ---------------------------------------------------------------------------
; asmf_try_number -- CF set when the cursor starts a numeric literal.
; ---------------------------------------------------------------------------
; The peek byte goes in r8b, never al: rax is the cursor itself and `.sign`
; does `inc rax`, so loading al replaced the cursor's low byte and the probe
; that followed read from cursor&~0xFF instead of from the source.
asmf_try_number:
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .no
    mov r8b, [rax]
    cmp r8b, 0x30               ; '0'
    jb .maybe
    cmp r8b, 0x39
    jbe .yes
.maybe:
    cmp r8b, '$'
    je .yes
    cmp r8b, '%'
    je .yes
    cmp r8b, '-'
    je .sign
    cmp r8b, '+'
    je .sign
.no:
    clc
    ret
.sign:
    ; a sign only counts when a number follows it
    inc rax
    cmp rax, [g_end]
    jae .no
    mov r8b, [rax]
    cmp r8b, 0x30
    jb .no2
    cmp r8b, 0x39
    jbe .yes
    cmp r8b, '$'
    je .yes
    cmp r8b, '%'
    je .yes
.no2:
    clc
    ret
.yes:
    stc
    ret

section .rodata
txt_64:  db '64'
txt_equ: db 'equ'
txt_rel: db 'rel'
; `asmf_try_abs` and `default abs` pass length 3, so this must be exactly the
; three bytes 'abs' with no terminator -- the same contract as txt_rel.
txt_abs: db 'abs'
section .text
