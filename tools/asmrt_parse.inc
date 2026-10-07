; ===========================================================================
; asmrt_parse.inc -- line / instruction / operand parsing.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_parse_line -- one logical line. Handles leading whitespace, ';' and
; '*' comments, ignored directives, `label:` and `name EQU value`, then the
; mnemonic and its operand list. Advances g_cur past the instruction; the
; caller skips the rest of the line.
; ---------------------------------------------------------------------------
asmf_parse_line:
    push rbx
    mov qword [g_times_left], 0
    call asmf_skip_space

    ; comment lines
    mov rbx, [g_cur]
    cmp rbx, [g_end]
    jae .done
    mov al, [rbx]
    cmp al, ';'
    je .done
    cmp al, '*'
    je .done

    ; ignored directives (whole-line, everything after them is skipped)
    call asmf_try_directive
    jc .done

    ; labels
.labels:
    call asmf_is_label_here
    jnc .not_label           ; asmf_is_label_here sets CF when it found one
    call asmf_take_label
    cmp dword [g_err], 0
    jne .done
    call asmf_skip_space
    jmp .labels
.not_label:

    ; `times <count> <statement>`: replay the statement count times. The
    ; statement itself starts where g_cur sits now, so it is rewound to that
    ; point between repetitions.
    call asmf_skip_space
    mov rbx, [g_cur]
    cmp rbx, [g_end]
    jae .done
    mov al, [rbx]
    cmp al, ';'
    je .done
    cmp al, 10
    je .done
    mov r8, 5
    lea rdi, [rel dir_times]
    call asmf_keyeq
    jnc .mnem
    call asmf_skip_space
    call asmf_parse_expr
    cmp dword [g_err], 0
    jne .done
    mov [g_times_left], rax
    mov rax, [g_cur]
    mov [g_times_from], rax
    jmp .nextstmt

    ; mnemonic
.mnem:
    mov rbx, [g_cur]
    cmp rbx, [g_end]
    jae .nextstmt
    mov al, [rbx]
    cmp al, ';'
    je .nextstmt
    cmp al, 10
    je .nextstmt

    mov rdi, rbx
    call asmf_scan_ident
    mov rdi, rbx
    mov rsi, rax
    push rsi
    call asmf_find_mnem
    pop rsi
    test rax, rax
    js .bad_mnem
    ; rax = table entry index; remember the token for diagnostics
    mov [g_mnem_idx], rax
    mov rdx, rax
    shl rdx, 4                   ; MNEMSZ == 16
    lea rcx, [rel mnem_tbl]
    add rcx, rdx
    movzx eax, word [rcx + 8]
    mov [g_mnemonic_id], eax
    movzx eax, word [rcx + 10]
    mov [g_param], eax
    movzx eax, word [rcx + 12]
    mov [g_minops], eax
    movzx eax, word [rcx + 14]
    mov [g_maxops], eax
    mov rbx, [g_cur]
    add rbx, rsi
    mov [g_cur], rbx

    ; operands. g_nops is reset before the test because the "no operands"
    ; arm jumps straight to .emit: leaving it stale would arity-check the
    ; previous instruction against this mnemonic's table entry.
    mov dword [g_nops], 0
    mov dword [g_hi8_any], 0
    call asmf_skip_space
    call asmf_at_eol
    jz .emit
.loop:
    mov eax, [g_nops]
    cmp eax, MAXOPS
    jae .too_many
    mov rdi, rax
    call asmf_parse_operand
    cmp dword [g_err], 0
    jne .done
    inc dword [g_nops]
    call asmf_skip_space
    call asmf_at_eol
    jnz .sep
    jmp .emit
.sep:
    mov rbx, [g_cur]
    mov al, [rbx]
    cmp al, ','
    jne .bad_oper
    inc rbx
    mov [g_cur], rbx
    call asmf_skip_space
    jmp .loop
.too_many:
    mov rdi, E_OPERAND
    call asmf_err_code
    jmp .done
.bad_oper:
    mov rdi, E_OPERAND
    call asmf_err_code
    jmp .done

.emit:
    ; arity check against the mnemonic table
    mov eax, [g_nops]
    cmp eax, [g_minops]
    jb .arity
    cmp eax, [g_maxops]
    jbe .emit_ok
.arity:
    mov rdi, E_FORM
    call asmf_err_code
    jmp .done
.emit_ok:
    call asmf_emit_insn
.nextstmt:
    cmp qword [g_times_left], 0
    je .done
    dec qword [g_times_left]
    mov rax, [g_times_from]
    mov [g_cur], rax
    jmp .mnem
.bad_mnem:
    mov rdi, E_MNEM
    mov rsi, [g_cur]
    xor edx, edx
    call asmf_error
.done:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_try_directive -- CF set when a whole-line directive was consumed.
; ---------------------------------------------------------------------------
asmf_try_directive:
    mov r8, 4
    lea rdi, [rel dir_bits]
    call asmf_keyeq
    jc .bits
    mov r8, 7
    lea rdi, [rel dir_section]
    call asmf_keyeq
    jc .consume
    mov r8, 6
    lea rdi, [rel dir_global]
    call asmf_keyeq
    jc .consume
    mov r8, 6
    lea rdi, [rel dir_extern]
    call asmf_keyeq
    jc .consume
    mov r8, 7
    lea rdi, [rel dir_default]
    call asmf_keyeq
    jc .default
    mov r8, 3
    lea rdi, [rel dir_cpu]
    call asmf_keyeq
    jc .consume
    mov r8, 3
    lea rdi, [rel dir_org]
    call asmf_keyeq
    jc .org
    clc
    ret
.bits:
    ; only "bits 64" is accepted
    call asmf_skip_space
    mov r8, 2
    lea rdi, [rel txt_64]
    call asmf_keyeq
    jnc .bad_bits
    jmp .consume
.bad_bits:
    mov rdi, E_FORM
    call asmf_err_code
    stc
    ret
.org:
    ; org N -- the origin only matters for the very first label, which
    ; asm_run already seeds from g_org, so accept and ignore the number.
    call asmf_skip_space
    call asmf_parse_number
    cmp dword [g_err], 0
    jne .oerr
    stc
    ret
.oerr:
    stc
    ret
.default:
    ; `default rel` / `default abs` -- select the addressing flavour of a
    ; bare `[symbol]` that carries no explicit `rel`. The blob used to
    ; swallow the whole line, so `default rel` was silently a no-op and
    ; every `[label]` assembled to the absolute SIB form instead of RIP
    ; relative, diverging from NASM on any real source.
    call asmf_skip_space
    mov r8, 3
    lea rdi, [rel txt_rel]
    call asmf_keyeq
    jc .def_rel
    mov r8, 3
    lea rdi, [rel txt_abs]
    call asmf_keyeq
    jc .def_abs
    mov rdi, E_FORM
    call asmf_err_code
    stc
    ret
.def_rel:
    mov dword [g_defrel], 1
    jmp .consume
.def_abs:
    mov dword [g_defrel], 0
    jmp .consume
.consume:
    ; Skip the rest of the line -- but stop *on* the newline, never past it.
    ; asmf_run_pass calls asmf_skip_eol after every line, and that helper
    ; consumes the newline and bumps g_line itself: swallowing it here made
    ; the next source line vanish as if it were the tail of the directive,
    ; which is how `bits 64` on line 1 silently deleted line 2.
    mov rbx, [g_cur]
    mov r10, [g_end]
.l:
    cmp rbx, r10
    jae .d
    mov al, [rbx]
    cmp al, 10
    je .d
    inc rbx
    jmp .l
.d:
    mov [g_cur], rbx
    stc
    ret

; ---------------------------------------------------------------------------
; asmf_is_label_here -- CF set when the cursor is at `identifier:` or
; `identifier equ`.
; ---------------------------------------------------------------------------
asmf_is_label_here:
    push rbx
    mov rbx, [g_cur]
    cmp rbx, [g_end]
    jae .n
    mov al, [rbx]
    call asmf_is_idstart
    jz .n
    mov rdi, rbx
    call asmf_scan_ident
    mov rcx, rax                 ; length
    lea rax, [rbx + rcx]
    cmp rax, [g_end]
    jae .n
    cmp byte [rax], ':'
    je .y
    ; `NAME equ <expr>` defines a symbol just as `NAME:` does
    mov r10, rax
.skip:
    cmp r10, [g_end]
    jae .n
    mov dl, [r10]
    cmp dl, ' '
    je .adv
    cmp dl, 9
    jne .equ
.adv:
    inc r10
    jmp .skip
.equ:
    mov rdx, [g_end]
    sub rdx, r10
    cmp rdx, 3
    jl .n
    mov dl, [r10]
    or dl, 0x20
    cmp dl, 'e'
    jne .n
    mov dl, [r10 + 1]
    or dl, 0x20
    cmp dl, 'q'
    jne .n
    mov dl, [r10 + 2]
    or dl, 0x20
    cmp dl, 'u'
    jne .n
    lea rax, [r10 + 3]
    cmp rax, [g_end]
    jae .y
    mov al, [rax]                ; asmf_is_idchar reads the byte in al
    call asmf_is_idchar
    jnz .n
.y:
    stc
    pop rbx
    ret
.n:
    clc
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_take_label -- consume `name:` and define it at the current position.
; A label whose name is followed by `equ <expr>` becomes an absolute symbol.
; ---------------------------------------------------------------------------
asmf_take_label:
    push rbx
    push r12
    push r13
    mov rbx, [g_cur]
    mov rdi, rbx
    call asmf_scan_ident
    mov r12, rbx                 ; name start
    mov r13, rax                 ; name length
    lea rbx, [r12 + r13]
    mov [g_cur], rbx
    call asmf_skip_space
    ; the colon is optional: `NAME equ <expr>` has none
    mov rax, [g_cur]
    cmp rax, [g_end]
    jae .colon
    cmp byte [rax], ':'
    jne .colon
    inc rax
    mov [g_cur], rax
.colon:
    call asmf_skip_space

    cmp byte [r12], '.'
    je .localname
    ; a plain label opens the scope its `.local` labels will live in
    mov ecx, r13d
    cmp ecx, SCOPESZ
    jbe .sc_store
    mov ecx, SCOPESZ
.sc_store:
    mov [g_scopelen], ecx
    xor r8d, r8d
    lea r9, [rel g_scopebuf]
.sc_copy:
    cmp r8d, ecx
    jae .named
    mov al, [r12 + r8]
    mov [r9 + r8], al
    inc r8d
    jmp .sc_copy
.localname:
    mov rdi, r12
    mov rsi, r13
    call asmf_scope_name
    mov r12, rdi
    mov r13, rsi
.named:

    ; `name EQU <expr>`?
    call asmf_skip_space
    mov r8, 3
    lea rdi, [rel txt_equ]
    call asmf_keyeq
    jnc .plain
    call asmf_skip_space
    mov dword [g_expr_sym], 0
    call asmf_parse_expr
    cmp dword [g_err], 0
    jne .d
    mov rdx, rax                 ; asmf_parse_expr already folded the labels
.equ_go:
    mov rcx, 1
    mov rdi, r12
    mov rsi, r13
    call asmf_sym_define
    jmp .d
.plain:
    mov rdx, [g_pos]
    xor ecx, ecx
    mov rdi, r12
    mov rsi, r13
    call asmf_sym_define
.d:
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_find_mnem -- rdi = name, rsi = length. Returns rax = table index or -1.
; The name is lowercased into the 8-byte g_mnembuf and compared a qword at a
; time, since every table entry is already NUL padded to 8 bytes.
; ---------------------------------------------------------------------------
asmf_find_mnem:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                  ; name
    mov r13, rsi                  ; length
    cmp r13, 8
    ja .none

    ; zero the scratch, then copy the lowercased name in. The zeroing has to
    ; be a real store: `mov rax,[r15] / mov [r15],rax` is a no-op, and the
    ; bytes a previous longer mnemonic left behind then make a shorter name
    ; (say "nop" after "syscall") compare unequal for every entry.
    lea r15, [rel g_mnembuf]
    xor eax, eax
    mov [r15], rax
    xor r14d, r14d
.copy:
    cmp r14d, r13d
    jae .ready
    mov al, [r12 + r14]
    or al, 0x20
    mov [r15 + r14], al
    inc r14d
    jmp .copy

.ready:
    mov r14, [r15]                ; the qword we are looking for
    xor ecx, ecx
.scan:
    cmp ecx, MNEM_COUNT
    jae .none
    MNEMSLOT r15, rcx, r11
    mov rax, [r15]
    cmp rax, r14
    jne .next
    mov rax, rcx
    jmp .done
.next:
    inc ecx
    jmp .scan
.none:
    mov rax, -1
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    ret
