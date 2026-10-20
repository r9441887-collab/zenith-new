; ===========================================================================
; asmrt_num.inc -- numeric literals (NASM-compatible) and string literals.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_parse_number -- reads one number at the global cursor.
; Returns rax = value and leaves g_cur just past the literal.
; g_htmp is set to 1 when the literal needed more than 32 bits, so that
; `mov eax, 0x100000000` still takes the 64-bit immediate form like NASM.
;
; Accepted: 123  0x1f  $1f  %1010  0b1010  0o17  0q17  0d12  0y17
;           1fh   1010b  17o  17q  12d  12y  0_1_2  'c'  "str"  \n escapes
; ---------------------------------------------------------------------------
asmf_parse_number:
    push rbx
    push r12
    push r13
    push r14
    ; g_strlen is the quoted-literal result and only the quote path fills it
    ; in. It was never cleared, so pass 2 saw pass 1's leftover count and
    ; reinterpreted every plain immediate after a `db "..."` as a string.
    mov dword [g_strlen], 0
    mov r12, [g_cur]              ; cursor
    mov r13, [g_end]
    mov dword [g_htmp], 0
    xor ebx, ebx                  ; accumulator
    xor r14d, r14d                ; digit count

    ; --- leading sign ----------------------------------------------------
    xor r15d, r15d
    cmp r12, r13
    jae .bad
    mov al, [r12]
    cmp al, '-'
    je .sneg
    cmp al, '+'
    je .spos
    jmp .main
.sneg:
    mov r15d, 1
    inc r12
    jmp .main
.spos:
    inc r12

.main:
    cmp r12, r13
    jae .bad
    mov al, [r12]
    cmp al, 0x27
    je .quoted
    cmp al, '"'
    je .quoted

    ; --- scan the whole token so we can inspect its last character -------
    mov r9, r12                  ; digit start (advanced past a prefix)
    mov r11, r12                 ; digit end (one past the last digit)
    mov r8, r12                  ; token end
.scan_tok:
    cmp r8, r13
    jae .tok_end
    mov al, [r8]
    call asmf_is_idchar
    jz .tok_end
    inc r8
    jmp .scan_tok
.tok_end:
    cmp r8, r12
    ja .have_tok
    jmp .bad
.have_tok:
    ; remember where the literal ends: a trailing radix suffix makes the
    ; digit loop stop one byte early, and g_cur has to land past it
    mov [g_tokend], r8
    ; a lone `$` is the current position (instruction start, g_pos)
    lea rax, [r12+1]
    cmp rax, r8
    jne .not_here
    cmp byte [r12], '$'
    jne .not_here
    mov r9, r8
    mov r14d, 1
    mov rbx, [g_pos]
    ; `$` is position dependent, which is why NASM assembles `mov rax, $`
    ; through the full 64-bit immediate form
    mov dword [g_reloc], 1
    jmp .acc_done
.not_here:
    ; radix from an explicit prefix, else from a trailing letter
    mov r10d, 10
    mov al, [r12]
    cmp al, '$'
    je .pfx_hex
    cmp al, '%'
    je .pfx_bin
    cmp al, '0'
    jne .suffix_try
    lea rax, [r12+1]
    cmp rax, r13
    jae .suffix_try
    mov al, [rax]
    or al, 0x20
    cmp al, 'x'
    je .pfx_hex
    cmp al, 'b'
    je .pfx_bin
    cmp al, 'o'
    je .pfx_oct
    cmp al, 'q'
    je .pfx_oct
    cmp al, 'd'
    je .pfx_dec
    cmp al, 'y'
    je .pfx_bin
    jmp .suffix_try
.pfx_hex:
    mov r10d, 16
    add r9, 2
    jmp .set_end
.pfx_bin:
    mov r10d, 2
    add r9, 2
    jmp .set_end
.pfx_oct:
    mov r10d, 8
    add r9, 2
    jmp .set_end
.pfx_dec:
    mov r10d, 10
    add r9, 2
    jmp .set_end

    ; A trailing letter selects the radix: 1fh, 1010b, 17o, 17q, 12d, 12y
.suffix_try:
    mov rax, r8
    dec rax
    cmp rax, r12
    jb .set_end
    mov cl, [rax]
    or cl, 0x20
    cmp cl, 'h'
    je .suf_hex
    cmp cl, 'b'
    je .suf_bin
    cmp cl, 'o'
    je .suf_oct
    cmp cl, 'q'
    je .suf_oct
    cmp cl, 'd'
    je .suf_dec
    cmp cl, 'y'
    je .suf_bin
    jmp .set_end
.suf_hex: mov r10d, 16
    dec r8
    jmp .set_end
.suf_bin: mov r10d, 2
    dec r8
    jmp .set_end
.suf_oct: mov r10d, 8
    dec r8
    jmp .set_end
.suf_dec: mov r10d, 10
    dec r8

.set_end:
    mov r11, r8

    ; --- accumulate ------------------------------------------------------
    cmp r9, r11
    jae .bad
.digits:
    cmp r9, r11
    jae .acc_done
    mov al, [r9]
    cmp al, '_'
    je .next
    cmp al, '`'
    je .next
    mov rdx, r10
    xor ecx, ecx
    call asmf_digit_val
    cmp rcx, rdx
    jae .bad                     ; digit out of range for this radix
    imul rbx, r10                 ; acc = acc * radix + digit
    add rbx, rcx
    ; note when the value outgrows 32 bits: the immediate form depends on it
    mov rdx, rbx
    shr rdx, 32
    test rdx, rdx
    jz .next
    cmp dword [g_htmp], 0
    jne .next
    mov dword [g_htmp], 1
.next:
    inc r9
    inc r14d
    jmp .digits
.acc_done:
    test r14d, r14d
    jz .bad

    mov rax, [g_tokend]
    mov [g_cur], rax
    mov rax, rbx
    test r15d, r15d
    jz .store
    neg rax
.store:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.quoted:
    mov rdi, r12
    call asmf_parse_quoted
    cmp dword [g_err], 0
    jne .fail
    test r15d, r15d
    jz .qpos
    neg rax
.qpos:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.bad:
    mov rdi, E_NUMBER
    call asmf_err_code
.fail:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_digit_val -- al = char -> rcx = value, CF set when al is not a hex
; digit at all (in which case rcx = -1).
; ---------------------------------------------------------------------------
asmf_digit_val:
    xor ecx, ecx
    cmp al, '0'
    jb .maybe
    cmp al, '9'
    jbe .dec
.maybe:
    or al, 0x20
    cmp al, 'a'
    jb .no
    cmp al, 'f'
    ja .no
    movzx ecx, al                 ; the value has to come from the character:
    sub ecx, 'a' - 10             ; ecx starts out zero, so subtracting from it
    clc                           ; yielded -39 for every hex letter
    ret
.dec:
    movzx ecx, al
    sub ecx, '0'
    clc
    ret
.no:
    mov ecx, -1
    stc
    ret

; ---------------------------------------------------------------------------
; asmf_parse_quoted -- rdi = pointer at the opening quote.
; Decodes the literal into the g_strbuf arena and returns:
;   rax  = the first decoded byte (what a numeric use of a string means)
;   rdx  = the decoded byte count
;   g_strptr = start of the decoded bytes, g_strend = one past the last
;   g_strlen = the byte count
; g_cur is advanced past the closing quote. CF set on a malformed literal.
; ---------------------------------------------------------------------------
asmf_parse_quoted:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                 ; scanner
    mov r13, [g_end]
    ; each literal takes the next slice of the arena: g_strbuf is shared, so
    ; overwriting it made `db "ab","cd"` point both operands at "cd"
    lea rbx, [rel g_strbuf]      ; writer
    mov eax, [g_strfill]
    add rbx, rax
    xor ecx, ecx                 ; length so far
    mov r14b, [r12]              ; the quote character
    inc r12
    xor r15d, r15d               ; escape-state flags

.loop:
    cmp r12, r13
    jae .bad
    mov al, [r12]
    cmp al, r14b
    je .close
    cmp al, 10
    je .bad
    ; NASM treats `\` as an ordinary character in a literal: `db "a\nb"`
    ; assembles to 61 5c 6e 62, so there is no escape processing here
    cmp al, 0                    ; an embedded NUL terminates the source
    je .bad
    mov [rbx + rcx], al
    inc ecx
    mov eax, [g_strfill]
    add rax, rcx
    cmp rax, STRBUF
    jae .bad
    inc r12
    jmp .loop

.close:
    inc r12
    test rcx, rcx
    jz .bad
    mov [g_strptr], rbx
    lea rax, [rbx + rcx]
    mov [g_strend], rax
    mov [g_strlen], rcx
    add dword [g_strfill], ecx
    mov rdx, rcx
    movzx eax, byte [rbx]        ; a numeric use of a string takes its 1st byte
    mov [g_cur], r12
    clc
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.bad:
    mov rdi, E_NUMBER
    call asmf_err_code
    stc
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
