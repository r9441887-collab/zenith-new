; ===========================================================================
; asmrt_oper.inc -- operand parsing, size keywords, register names.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_op_clear -- rdi = operand record address. Zeroes it and sets the
; "no base, no index" default.
; ---------------------------------------------------------------------------
asmf_op_clear:
    push rbx
    push rcx
    push rdx
    mov rbx, rdi
    xor eax, eax
    mov ecx, OPSZ/8
.l:
    mov [rbx + rcx*8 - 8], rax
    dec ecx
    jnz .l
    mov dword [rbx + OP_BASE], -1
    mov dword [rbx + OP_INDEX], -1
    mov dword [rbx + OP_SCALE], 1
    pop rdx
    pop rcx
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_parse_operand -- edi = operand slot index. Fills g_ops[edi].
; An optional size keyword may precede a register, a `[memory]` reference or
; an immediate; a string literal is only meaningful for db/dw/dd/dq.
; ---------------------------------------------------------------------------
asmf_parse_operand:
    push rbx
    mov rbx, rdi                  ; slot index, kept in rbx
    REC rdi, rbx, 6, g_ops, r11
    call asmf_op_clear

    call asmf_skip_space

    ; an optional size keyword
    ; each operand starts a fresh expression, so a previous `$` cannot tag
    ; this one relocatable
    mov dword [g_reloc], 0

    xor edi, edi
    call asmf_try_size
    mov eax, [g_op_size]
    REC rdi, rbx, 6, g_ops, r11
    mov dword [rdi + OP_SIZE], eax

    call asmf_skip_space
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .bad

    mov cl, [rax]
    cmp cl, '['
    je .memory
    cmp cl, 0x27                 ; '
    je .string
    cmp cl, '"'
    je .string
    cmp cl, '-'
    je .symbol_or_value
    cmp cl, '+'
    je .symbol_or_value
    cmp cl, 0x30                 ; '0'
    jb .symbol_or_value
    cmp cl, 0x39
    jbe .number
    cmp cl, '$'
    je .number
    cmp cl, '%'
    je .number

.symbol_or_value:
    ; a register, or a symbol/number expression
    call asmf_try_reg
    jc .reg
    ; an expression, which may be a bare symbol or `sym +/- const`
    call asmf_parse_expr
    cmp dword [g_err], 0
    jne .d
    mov rdx, rax                 ; keep the value across the addressing macro
    REC rdi, rbx, 6, g_ops, r11
    mov dword [rdi + OP_KIND], K_IMM
    ; the expression already folded to a number, labels included, so there is
    ; nothing left to re-resolve. `a - b` nets zero and stays a constant;
    ; anything still holding a label is tagged relocatable for the encoding.
    mov dword [rdi + OP_SYM], 0
    mov [rdi + OP_VALUE], rdx
    cmp dword [g_reloc], 0
    jne .symReloc
    cmp dword [g_expr_net], 0
    je .symRelDone
.symReloc:
    or dword [rdi + OP_FLAGS], F_RELOC
.symRelDone:
    jmp .d

.number:
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .d
    REC rdi, rbx, 6, g_ops, r11
    mov dword [rdi + OP_KIND], K_IMM
    mov dword [rdi + OP_SYM], 0
    mov [rdi + OP_VALUE], rax
    cmp dword [g_reloc], 0
    je .numRelDone
    or dword [rdi + OP_FLAGS], F_RELOC
.numRelDone:
    ; a quoted string is a data-directive literal
    cmp dword [g_strlen], 0
    je .d
    mov dword [rdi + OP_KIND], K_STR
    mov dword [rdi + OP_FLAGS], F_STR
    jmp .d

.string:
    call asmf_parse_number         ; dispatches to the quoted-literal path
    cmp dword [g_err], 0
    jne .d
    REC rdi, rbx, 6, g_ops, r11
    mov dword [rdi + OP_SYM], 0
    mov [rdi + OP_VALUE], rax
    ; only the data directives emit the literal bytes. `'A'` anywhere else is
    ; the character's value, which NASM assembles as an ordinary immediate --
    ; tagging it K_STR sent `mov al, 'A'` down the mov r/m path instead.
    cmp dword [g_mnemonic_id], H_DATA
    je .strData
    mov dword [rdi + OP_KIND], K_IMM
    jmp .d
.strData:
    mov dword [rdi + OP_KIND], K_STR
    mov dword [rdi + OP_FLAGS], F_STR
    ; remember this operand's own literal: g_strptr only ever points at the
    ; most recent one, so `db "ab","cd"` emitted "cd" twice
    mov rax, [g_strptr]
    mov [rdi + OP_STRPTR], rax
    mov rax, [g_strend]
    mov [rdi + OP_STREND], rax
    jmp .d

.reg:
    REC rdi, rbx, 6, g_ops, r11
    mov dword [rdi + OP_KIND], K_REG
    mov eax, [g_reg_num]
    mov dword [rdi + OP_REG], eax
    mov eax, [g_reg_flags]
    mov dword [rdi + OP_FLAGS], eax
    ; the register's own width is the default; an explicit keyword wins
    mov eax, [g_reg_size]
    mov dword [rdi + OP_SIZE], eax
    mov eax, [g_op_size]
    test eax, eax
    jz .d
    mov dword [rdi + OP_SIZE], eax
    ; without this the store above fell straight into .memory and re-parsed a
    ; plain register operand as a memory reference
    jmp .d

.memory:
    mov [g_oprec], ebx
    REC rdi, rbx, 6, g_ops, r11
    call asmf_parse_mem
    jmp .d

.bad:
    mov rdi, E_OPERAND
    mov rsi, [g_cur]
    cmp rsi, [g_end]
    jb .have
    xor esi, esi
.have:
    mov rdx, 1
    call asmf_error
.d:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_try_size -- consumes a size keyword (byte/word/dword/qword/tbyte/...)
; leaving its size code in g_op_size. CF set when one was consumed.
; ---------------------------------------------------------------------------
asmf_try_size:
    push rbx
    ; no keyword means "no explicit size": the flag has to be cleared here,
    ; not only on .accept, or the previous operand's keyword leaks into this one
    mov dword [g_op_size], 0
    mov rbx, [g_cur]
    mov r10, [g_end]
    xor r8d, r8d
.loop:
    lea rdx, [rel sz_names]
    lea rdx, [rdx + r8*8]
    xor ecx, ecx
.scan:
    ; the two peek bytes live in r9b/r11b: al and dl are the low bytes of
    ; rax (the computed source address) and rdx (the table pointer), and
    ; loading either destroyed the value the next iteration needed
    mov r9b, [rdx + rcx]
    test r9b, r9b
    jz .matched                  ; the whole keyword matched
    cmp rcx, 8
    jae .next_entry
    lea rax, [rbx + rcx]
    cmp rax, r10
    jae .next_entry
    mov r11b, [rax]
    or r11b, 0x20
    cmp r9b, r11b
    jne .next_entry
    inc rcx
    jmp .scan
.matched:
    ; the following character must not continue an identifier
    lea rax, [rbx + rcx]
    cmp rax, r10
    jae .accept
    mov al, [rax]
    push rcx
    call asmf_is_idchar
    pop rcx
    jnz .next_entry
.accept:
    lea rax, [rbx + rcx]        ; al was clobbered by the idchar test above
    mov [g_cur], rax
    ; sz_names is 0-based, SZ_B is 1 (SZ_NONE is 0): storing the raw index
    ; turned `byte` into "no size", `word` into `byte`, and so on up the list
    lea eax, [r8d + 1]
    mov [g_op_size], eax
    pop rbx
    stc
    ret
.next_entry:
    inc r8d
    cmp r8d, 8
    jb .loop
    pop rbx
    clc
    ret

; ---------------------------------------------------------------------------
; asmf_try_reg -- consumes a register name. CF set on success, publishing
; g_reg_num (0..15), g_reg_size (SZ_*) and g_reg_flags (F_REX8).
; Register numbering follows the hardware encoding, so al/cl/dl/bl are 0..3
; and spl/bpl/sil/dil are 4..7.
; ---------------------------------------------------------------------------
asmf_try_reg:
    push rbx
    mov rbx, [g_cur]
    mov r10, [g_end]
    cmp rbx, r10
    jae .no
    mov al, [rbx]
    call asmf_is_idstart
    jz .no

    mov rdi, rbx
    lea rdx, [rel regname]
    call asmf_reg_match
    jc .r64
    lea rdx, [rel regname32]
    call asmf_reg_match
    jc .r32
    lea rdx, [rel regname16]
    call asmf_reg_match
    jc .r16
    lea rdx, [rel regname8]
    call asmf_reg_match
    jc .r8
    lea rdx, [rel regname8h]
    call asmf_reg_match
    jc .r8h
.no:
    pop rbx
    clc
    ret

.r64:
    mov eax, r8d
    mov [g_reg_num], eax
    mov dword [g_reg_size], SZ_Q
    xor eax, eax
    mov [g_reg_flags], eax
    pop rbx
    stc
    ret
.r32:
    mov eax, r8d
    mov [g_reg_num], eax
    mov dword [g_reg_size], SZ_D
    xor eax, eax
    mov [g_reg_flags], eax
    pop rbx
    stc
    ret
.r16:
    mov eax, r8d
    mov [g_reg_num], eax
    mov dword [g_reg_size], SZ_W
    xor eax, eax
    mov [g_reg_flags], eax
    pop rbx
    stc
    ret
.r8:
    mov eax, r8d
    mov [g_reg_num], eax
    mov dword [g_reg_size], SZ_B
    ; spl/bpl/sil/dil encode as 4..7 but only with a REX prefix present
    xor ecx, ecx
    cmp eax, 4
    jb .r8ok
    cmp eax, 8
    jae .r8ok
    mov ecx, F_REX8
.r8ok:
    mov [g_reg_flags], ecx
    pop rbx
    stc
    ret
.r8h:
    ; ah/ch/dh/bh live at hardware numbers 4..7 with no REX allowed
    mov eax, r8d
    add eax, 4
    mov [g_reg_num], eax
    mov dword [g_reg_size], SZ_B
    mov dword [g_reg_flags], F_HI8
    mov dword [g_hi8_any], 1
    pop rbx
    stc
    ret

; ---------------------------------------------------------------------------
; asmf_reg_match -- rdx = table of 8-byte NUL-padded names, rbx = cursor.
; CF set when a name matched; r8d = the index and g_cur advanced past it.
; ---------------------------------------------------------------------------
asmf_reg_match:
    mov r10, [g_end]
    xor rcx, rcx                  ; table index
.top:
    cmp rcx, 16
    jae .no
    lea rsi, [rdx + rcx*8]
    xor r8d, r8d
    mov rdi, rbx
.scan:
    mov r9b, [rsi + r8]
    test r9b, r9b
    jz .end
    cmp r8, 7
    jae .nextEntry
    lea rax, [rdi + r8]
    cmp rax, r10
    jae .nextEntry
    ; the source byte goes in r11b: r10 holds g_end for the whole scan, and
    ; writing r10b here replaced the cursor limit with a character, so the
    ; bounds test below compared against garbage and every register name
    ; could be rejected
    mov r11b, [rax]
    or r11b, 0x20
    cmp r9b, r11b
    jne .nextEntry
    inc r8
    jmp .scan
.end:
    ; the next source character must not continue an identifier
    lea rax, [rdi + r8]
    cmp rax, r10
    jae .ok
    mov r11b, [rax]
    test r11b, r11b
    jz .ok
    mov al, r11b
    call asmf_is_idchar
    jnz .nextEntry
.ok:
    lea rax, [rdi + r8]
    mov [g_cur], rax
    mov r8d, ecx
    stc
    ret
.nextEntry:
    inc rcx
    jmp .top
.no:
    clc
    ret
