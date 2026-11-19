; ===========================================================================
; asmrt_core.inc -- entry point, pass driver, lexer, symbol table, numbers.
; Included from asmrt.asm (same directory).
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; asmf_error(code=rdi, name=rsi, namelen=rdx) -- record a fatal error. The
; first error wins; every parser routine bails out afterwards and the pass loop
; stops, so an aborted pass never has to unwind.
; ---------------------------------------------------------------------------
asmf_error:
    cmp dword [g_err], 0
    jne .keep
    mov [g_err], edi
    mov [g_errname], rsi
    mov [g_errnamelen], edx
.keep:
    ret

; rdi = error code only
asmf_err_code:
    xor esi, esi
    xor edx, edx
    call asmf_error
    ret

; ---------------------------------------------------------------------------
; asm_entry -- see the ABI comment at the top of asmrt.asm.
; ---------------------------------------------------------------------------
asm_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                  ; keep rsp 16-byte aligned for the callee

    mov r12d, edi               ; op
    mov r15, r8                 ; srcLen
    mov [g_org], r9             ; origin

    cmp r12d, 2
    je .errmsg
    cmp r12d, 1
    je .assemble
    cmp r12d, 3
    je .sizeonly
    mov rax, -1
    jmp .out

.sizeonly:
    mov rdx, 0
.assemble:
    test rcx, rcx
    jz .badargs
    test r15, r15
    jz .empty                   ; empty source: zero bytes, no error
    mov [g_dst], rsi
    mov [g_cap], rdx
    mov [g_src], rcx
    mov [g_srclen], r15
    call asm_run
    jmp .out
.empty:
    mov qword [g_err], 0
    xor eax, eax
    jmp .out
.badargs:
    mov rdi, E_ARGS
    call asmf_err_code
    mov rax, -1
    jmp .out

.errmsg:
    ; a1 = buffer, a2 = capacity: the writers need the end pointer, not the
    ; size. rsi is caller-saved and the formatters clobber it, so keep the
    ; start in r12 (the op code it used to hold is already consumed).
    ;
    ; A zero capacity has no room even for the NUL terminator: the truncate
    ; arm of asmf_format_error would place it at g_fmtend-1, i.e. one byte
    ; *before* the caller's buffer (and at -1 outright for a NULL buffer).
    test rdx, rdx
    jz .errmsg_empty
    test rsi, rsi
    jz .errmsg_empty
    mov r12, rsi
    mov rax, rsi
    add rax, rdx
    mov [g_fmtcur], rsi
    mov [g_fmtend], rax
    call asmf_format_error
    mov rax, [g_fmtcur]
    sub rax, r12
    jmp .out
.errmsg_empty:
    xor eax, eax
    jmp .out

.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_format_error -- renders the last error into [g_fmtcur, g_fmtend) and
; NUL-terminates it. Never writes past the caller's cap.
;   "asm: <line>: <reason> <token>"
; ---------------------------------------------------------------------------
asmf_format_error:
    push rbx
    mov rbx, [g_fmtcur]
    cmp dword [g_err], 0
    je .none
    lea rdi, [rel pfx_asm]
    call asmf_puts
    call asmf_put_dec
    lea rdi, [rel pfx_colon]
    call asmf_puts
    mov edi, [g_err]
    call asmf_put_reason
    mov rax, [g_errname]
    test rax, rax
    jz .nul
    cmp dword [g_errnamelen], 0
    je .nul
    lea rdi, [rel pfx_sp]
    call asmf_puts
    mov rdi, [g_errname]
    mov esi, [g_errnamelen]
    call asmf_putn
    jmp .nul
.nul:
    mov rax, [g_fmtcur]
    mov rcx, [g_fmtend]
    cmp rax, rcx
    jb .space
    mov rax, rcx
    dec rax
.space:
    mov byte [rax], 0
    mov rax, [g_fmtcur]
    sub rax, rbx
    pop rbx
    ret
.none:
    cmp rbx, [g_fmtend]
    jae .n0
    mov byte [rbx], 0
.n0:
    xor eax, eax
    pop rbx
    ret

; rdi = ptr, rsi = len -> append
asmf_putn:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    xor r13d, r13d
.l:
    cmp r13d, r12d
    jae .d
    mov al, [rbx + r13]
    call asmf_putc
    jnc .next
    jmp .d
.next:
    inc r13d
    jmp .l
.d:
    pop r13
    pop r12
    pop rbx
    ret

; rdi = NUL-terminated string -> append
asmf_puts:
    push rbx
    mov rbx, rdi
.l:
    mov al, [rbx]
    test al, al
    jz .d
    call asmf_putc
    jnc .next
    jmp .d
.next:
    inc rbx
    jmp .l
.d:
    pop rbx
    ret

; al = char -> append. CF set when the buffer is full (caller stops).
asmf_putc:
    mov rcx, [g_fmtcur]
    cmp rcx, [g_fmtend]
    jae .full
    mov [rcx], al
    inc qword [g_fmtcur]
    clc
    ret
.full:
    stc
    ret

; append g_line in decimal
; The digit count must live in a register asmf_putc leaves alone: putc uses
; rcx for the write cursor, and `dec ecx / jnz .emit` on a clobbered counter
; walks the stack into the guard page.
asmf_put_dec:
    push rbx
    mov eax, [g_line]
    test eax, eax
    jnz .divide
    mov al, '0'
    call asmf_putc
    jmp .done
.divide:
    mov ebx, 10
    xor r8d, r8d
.next:
    xor edx, edx
    div ebx
    add dl, '0'
    push rdx
    inc r8d
    test eax, eax
    jnz .next
.emit:
    pop rdx
    mov al, dl
    call asmf_putc
    dec r8d
    jnz .emit
.done:
    pop rbx
    ret

; rdi = error code -> append its reason text
asmf_put_reason:
    push rbx
    push r12
    push r13
    ERRSLOT r12, rdi, r11
    mov ecx, [r12]                ; offset into err_blob
    mov r13d, [r12 + 4]           ; length
    RECB rbx, rcx, err_blob
    mov rdi, rbx
    mov rsi, r13
    call asmf_putn
    pop r13
    pop r12
    pop rbx
    ret

section .rodata
pfx_asm:   db 'asm: ',0
pfx_colon: db ': ',0
pfx_sp:    db ' ',0


section .text

; ---------------------------------------------------------------------------
; asm_run -- reset state and run both passes. Returns the output size in rax,
; or -1 on error (g_err holds the code).
; ---------------------------------------------------------------------------
asm_run:
    mov dword [g_scopelen], 0
    mov dword [g_namelen], 0
    mov dword [g_firstlab], 0
    mov dword [g_err], 0
    mov dword [g_errnamelen], 0
    mov qword [g_errname], 0
    mov dword [g_iter], 0
    mov dword [g_depth], 0
    mov dword [g_defrel], 0
    mov qword [g_prevhash], 0
    ; op 1 and op 3 must walk the exact same iteration sequence, so the
    ; symbol table starts empty on every call instead of inheriting the
    ; values the previous call finished with
    call asmf_syms_reset

    ; A forward label is only as good as the address the previous sizing run
    ; gave it, so one pass cannot know where a short jump lands. Re-run the
    ; sizing pass with the addresses it just produced until they stop moving;
    ; pass 2 then sees the same values pass 1 decided with.
.sizerun:
    mov dword [g_pass], 1
    mov dword [g_line], 1
    mov dword [g_firstlab], 0
    call asmf_clear_stamps
    call asmf_run_pass
    cmp dword [g_err], 0
    jne .fail
    call asmf_syms_hash
    cmp rax, [g_prevhash]
    je .stable
    mov [g_prevhash], rax
    inc dword [g_iter]
    cmp dword [g_iter], 8
    jae .stable              ; oscillating layout: emit what we have
    jmp .sizerun
.stable:
    mov rax, [g_pos]
    mov [g_size1], rax

    mov dword [g_line], 1
    mov dword [g_pass], 2
    call asmf_run_pass
    cmp dword [g_err], 0
    jne .fail
    ; asmf_run_pass returns whatever asmf_parse_line/asf_skip_eol left in rax,
    ; never the size: compare g_pos against pass 1, not that stale register.
    mov rax, [g_pos]
    mov rbx, [g_size1]
    cmp rax, rbx
    jne .unstable
    call asmf_check_syms
    cmp dword [g_err], 0
    jne .fail
    ; asmf_check_syms clobbers rax, and the caller reads the size from it
    mov rax, [g_pos]
    ret
.unstable:
    ; pass 1 and pass 2 disagree on the size: an internal sizing bug
    mov rdi, E_FORM
    call asmf_err_code
.fail:
    mov rax, -1
    ret

; ---------------------------------------------------------------------------
; asmf_syms_reset -- forget every symbol. Values have to go as well: the
; sizing iterations need the addresses from the run before them, and two
; consecutive asm_entry calls would otherwise disagree.
; ---------------------------------------------------------------------------
asmf_syms_reset:
    xor ecx, ecx
.l:
    cmp ecx, [g_labels]
    jae .d
    mov eax, ecx
    SYMSLOT rdx, rax, r11
    mov dword [rdx + SY_STAMP], 0
    mov dword [rdx + SY_ABS], 0
    mov qword [rdx + SY_OFF], 0
    inc ecx
    jmp .l
.d:
    mov dword [g_labels], 0
    mov dword [g_namelen], 0
    ret

; asmf_clear_stamps -- labels defined by the previous sizing run are not
; redefinitions of the run that is about to start
asmf_clear_stamps:
    xor ecx, ecx
.l:
    cmp ecx, [g_labels]
    jae .d
    mov eax, ecx
    SYMSLOT rdx, rax, r11
    mov dword [rdx + SY_STAMP], 0
    inc ecx
    jmp .l
.d:
    ret

; asmf_syms_hash -> rax. Zero only when every address is still where it was.
asmf_syms_hash:
    push rbx
    xor ebx, ebx
    xor ecx, ecx
.l:
    cmp ecx, [g_labels]
    jae .d
    mov eax, ecx
    SYMSLOT rdx, rax, r11
    rol ebx, 1
    add rbx, [rdx + SY_OFF]
    add ebx, ecx
    inc ecx
    jmp .l
.d:
    mov rax, rbx
    pop rbx
    ret

; pass number comes from g_pass (1 = sizing, 2 = emit)
asmf_run_pass:
    ; Every pass restarts the local-label scope: carrying the last routine's
    ; name over made `.lp:` define `table.lp` on the second sizing run while
    ; the first run had defined `.lp`, leaving one of the two never stamped.
    mov dword [g_scopelen], 0
    mov dword [g_strfill], 0
    mov qword [g_pos], 0
    cmp dword [g_pass], 2
    jne .sizing
    mov rax, [g_dst]
    mov [g_out], rax
    jmp .go
.sizing:
    mov qword [g_out], 0
.go:
    mov rbx, [g_src]
    mov [g_cur], rbx
    mov rax, [g_srclen]
    add rax, rbx
    mov [g_end], rax
    cmp rax, rbx
    ja .loop
    ret
.loop:
    ; g_cur is the only cursor the parse loop may test: rbx is clobbered by
    ; asmf_skip_eol, and testing a copy loaded once before the loop never
    ; advances, so a clean line (a directive, a comment) spun forever and the
    ; watchdog reported it as a blob fault.
    mov rbx, [g_cur]
    cmp rbx, [g_end]
    jae .done
    call asmf_parse_line
    cmp dword [g_err], 0
    jne .done
    call asmf_skip_eol
    jmp .loop
.done:
    ret

; advance past the end of the current line (always consumes at least one byte)
asmf_skip_eol:
    mov r11, [g_cur]
    mov r10, [g_end]
.l:
    cmp r11, r10
    jae .d
    mov al, [r11]
    inc r11
    cmp al, 10
    je .nl
    jmp .l
.nl:
    inc dword [g_line]
.d:
    mov [g_cur], r11
    ret

; ---------------------------------------------------------------------------
; Character predicates: al is the argument. The contract every caller relies
; on is "NZ means yes, ZF means no" -- asmf_skip_space stops on `jz`,
; asmf_scan_ident stops on `jz`, asmf_keyeq bails on `jnz`, and the label /
; operand tests all branch on `jnz .y`.
;
; The `.y` arms therefore have to *clear* ZF explicitly. `mov eax,1` and
; `pop` leave the flags from the range `cmp` behind them, so without the
; `or eax,eax` the last character of every range ('z', '9') answers "no" and
; every other member answers "yes" only by luck.
; ---------------------------------------------------------------------------
asmf_is_space:                   ; SP HT CR VT FF
    cmp al, ' '
    je .y
    cmp al, 9
    je .y
    cmp al, 13
    je .y
    cmp al, 11
    je .y
    cmp al, 12
    je .y
    jmp .n
.y: mov eax, 1
    or eax, eax
    ret
.n: xor eax, eax
    ret

asmf_is_digit:
    cmp al, '0'
    jb .n
    cmp al, '9'
    jbe .y
.n: xor eax, eax
    ret
.y: mov eax, 1
    or eax, eax
    ret

; Leaves al clobbered: the case fold reuses it. Callers that still need the
; original character (asmf_is_idchar / asmf_is_idstart) keep a copy in bl.
asmf_is_alpha:
    push rax
    or al, 0x20
    cmp al, 'a'
    jb .n
    cmp al, 'z'
    jbe .y
.n: pop rax
    xor eax, eax
    ret
.y: pop rax
    mov eax, 1
    or eax, eax
    ret

asmf_is_idchar:
    push rbx
    mov bl, al                   ; is_alpha / is_digit both clobber al
    call asmf_is_alpha
    jnz .y
    mov al, bl
    call asmf_is_digit
    jnz .y
    mov al, bl
    cmp al, '_'
    je .y
    cmp al, '.'
    je .y
    cmp al, '$'
    je .y
    cmp al, '@'
    je .y
    cmp al, '?'
    je .y
    jmp .n
.y: pop rbx
    mov eax, 1
    or eax, eax
    ret
.n: pop rbx
    xor eax, eax
    ret

asmf_is_idstart:
    push rbx
    mov bl, al                   ; is_alpha clobbers al
    call asmf_is_alpha
    jnz .y
    mov al, bl
    cmp al, '_'
    je .y
    cmp al, '.'
    je .y
    cmp al, '$'
    je .y
    jmp .n
.y: pop rbx
    mov eax, 1
    or eax, eax
    ret
.n: pop rbx
    xor eax, eax
    ret

; ---------------------------------------------------------------------------
; Cursor helpers (all operate on the global g_cur, bounded by g_end)
; ---------------------------------------------------------------------------
asmf_skip_space:
    mov r11, [g_cur]
    mov r10, [g_end]
.l:
    cmp r11, r10
    jae .d
    mov al, [r11]
    call asmf_is_space
    jz .d
    inc r11
    jmp .l
.d:
    mov [g_cur], r11
    ret

; ZF set when the cursor sits on EOL (end of buffer, NUL, '\n' or ';').
; The end-of-buffer arm goes through `.atend` rather than jumping to `.y`:
; the caller tests ZF, and `cmp r11,[g_end]` leaves ZF *clear* when the
; cursor has stepped past the end, which would send it down the operand
; path where it reads [g_cur] one byte outside the source.
asmf_at_eol:
    mov r11, [g_cur]
    cmp r11, [g_end]
    jae .atend
    mov al, [r11]
    test al, al
    jz .y
    cmp al, 10
    je .y
    cmp al, ';'
    ret
.atend:
    xor eax, eax                ; ZF = 1
    ret
.y: ret

; rdi = start -> rax = length, rsi = r11 = one past the identifier
asmf_scan_ident:
    mov r11, rdi
    mov r10, [g_end]
.l:
    cmp r11, r10
    jae .d
    mov al, [r11]
    call asmf_is_idchar
    jz .d
    inc r11
    jmp .l
.d:
    mov rsi, r11
    mov rax, r11
    sub rax, rdi
    ret

; rdi = keyword, r8 = length. CF set when the word at g_cur matches and is
; followed by a non-identifier character. On a hit g_cur steps over the
; keyword: every caller follows with a skip_space and would otherwise test
; the keyword itself (`bits 64` failed as a bad bits value, and `[rel x]`
; looped forever because rel never got consumed).
;
; Every probe is bounded by g_end. The source buffer is handed in by the
; caller with an exact length and is not NUL terminated, so a keyword that
; runs up to the end of the buffer (`bits` as the very last bytes of the
; file) used to read srcLen and beyond -- one byte past the last page when
; the source ends exactly at a page boundary, i.e. a SEGV on perfectly
; legal input. A keyword truncated by the end of the buffer is simply not
; there; a keyword that ends exactly *at* the end still matches, because
; end-of-buffer terminates an identifier just like a non-id character.
asmf_keyeq:
    mov r11, [g_cur]
    mov r10, [g_end]
    xor ecx, ecx
.l:
    cmp rcx, r8
    jae .end
    mov rdx, r11
    add rdx, rcx
    cmp rdx, r10
    jae .n                      ; keyword would run past the end: no match
    mov al, [rdi + rcx]
    cmp al, [r11 + rcx]
    jne .n
    inc rcx
    jmp .l
.end:
    mov rdx, r11
    add rdx, rcx
    cmp rdx, r10
    jae .y                      ; ends exactly at the end of the source
    mov al, [r11 + rcx]
    test al, al
    jz .y
    call asmf_is_idchar
    jnz .n
.y:
    add qword [g_cur], r8
    stc
    ret
.n:
    clc
    ret

; ---------------------------------------------------------------------------
; Symbol table
; ---------------------------------------------------------------------------
; ---------------------------------------------------------------------------
; asmf_scope_name -- NASM gives a label starting with '.' the preceding
; non-local label as its prefix, so two routines can each have a `.loop`.
; rdi = name, rsi = length -> rdi/rsi = the name to intern. No-op when the
; name is not local or there is no scope yet. Clobbers rax, rcx, r8-r11.
; ---------------------------------------------------------------------------
asmf_scope_name:
    cmp rsi, 1
    jbe .no
    cmp byte [rdi], '.'
    jne .no
    mov r10d, [g_scopelen]
    test r10d, r10d
    jz .no
    lea rax, [r10 + rsi]
    cmp rax, NAMETMP
    jae .no
    lea r8, [rel g_scopebuf]
    lea r9, [rel g_nametmp]
    xor r11d, r11d
.s1:
    cmp r11d, r10d
    jae .s2
    mov al, [r8 + r11]
    mov [r9 + r11], al
    inc r11d
    jmp .s1
.s2:
    xor r11, r11
.s3:
    cmp r11, rsi
    jae .s4
    lea rcx, [r10 + r11]
    mov al, [rdi + r11]
    mov [r9 + rcx], al
    inc r11
    jmp .s3
.s4:
    mov rax, r10
    add rax, rsi
    mov rsi, rax
    lea rdi, [rel g_nametmp]
.no:
    ret

; rdi = name, rsi = length -> rax = index, creating the entry when missing
asmf_sym_intern:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    call asmf_sym_lookup
    test rax, rax
    jns .have
    mov eax, [g_labels]
    cmp eax, MAXSYM
    jae .full
    mov r8d, [g_namelen]
    mov r9d, r13d
    add r9d, r8d
    cmp r9d, NAMEPOOL
    jae .full
    RECB r10, r8, g_names
    xor r11d, r11d
.c:
    cmp r11d, r13d
    jae .c2
    mov dl, [r12 + r11]
    mov [r10 + r11], dl
    inc r11d
    jmp .c
.c2:
    SYMSLOT rdx, rax, r11
    mov dword [rdx + SY_NAMELEN], r13d
    mov dword [rdx + SY_NAMEOFF], r8d
    mov dword [rdx + SY_STAMP], 0
    mov dword [rdx + SY_ABS], 0
    mov qword [rdx + SY_OFF], 0
    mov [g_namelen], r9
    inc dword [g_labels]
    mov eax, [g_labels]
    dec eax
    jmp .have
.full:
    ; Returning g_labels-1 here would hand the caller a *different* symbol's
    ; slot, which asmf_sym_define would then overwrite. Signal the overflow
    ; instead; asmf_sym_define turns a negative index into E_MANYLBL.
    mov rdi, E_MANYLBL
    xor esi, esi
    xor edx, edx
    call asmf_error
    mov rax, -1
.have:
    pop r13
    pop r12
    pop rbx
    ret

; rdi = name, rsi = length -> rax = index or -1
asmf_sym_lookup:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    xor r14d, r14d
.l:
    cmp r14d, [g_labels]
    jae .n
    mov rax, r14
    REC rdx, rax, 5, g_labels_tab, r11
    cmp dword [rdx + SY_NAMELEN], r13d
    jne .next
    ; RECB must not alias its destination with the offset register: the lea
    ; overwrites the offset and the `add dest,offset` then doubles the base,
    ; so every lookup reads past the mapping instead of the name pool. r8 is
    ; free here -- it is only reused as the compare byte inside the loop.
    mov r8d, [rdx + SY_NAMEOFF]
    RECB rcx, r8, g_names
    xor eax, eax
.c:
    cmp eax, r13d
    jae .eq
    mov r8b, [rcx + rax]
    cmp r8b, [r12 + rax]
    jne .next
    inc eax
    jmp .c
.eq:
    mov rax, r14
    pop r14
    pop r13
    pop r12
    ret
.next:
    inc r14d
    jmp .l
.n:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    ret

; rax = symbol index -> rax = value (label offset, or the assigned constant
; for an absolute symbol)
asmf_sym_val:
    push rdx
    REC rdx, rax, 5, g_labels_tab, r11
    mov rax, [rdx + SY_OFF]
    pop rdx
    ret

; define a label. rdi = name, rsi = length, rdx = value, rcx = absolute flag
asmf_sym_define:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    push rcx                    ; absolute flag
    call asmf_sym_intern
    pop rcx
    test rax, rax
    js .full
    SYMSLOT rbx, rax, r11
    mov edx, [g_pass]
    cmp dword [rbx + SY_STAMP], edx
    je .redef
    mov [rbx + SY_STAMP], edx
    mov [rbx + SY_OFF], r14
    mov [rbx + SY_ABS], ecx     ; 0 = plain label, 1 = `name EQU value`
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.redef:
    mov rdi, E_REDEF
    mov rsi, r12
    mov rdx, r13
    call asmf_error
    jmp .done
.full:
    mov rdi, E_MANYLBL
    xor esi, esi
    xor edx, edx
    call asmf_error
    jmp .done

; Every symbol referenced must have been stamped by pass 2.
asmf_check_syms:
    push r12
    push r13
    xor r12d, r12d
.l:
    cmp r12d, [g_labels]
    jae .d
    REC rdx, r12, 5, g_labels_tab, r11
    mov eax, [rdx + SY_STAMP]
    cmp eax, 2
    jne .undef
    inc r12d
    jmp .l
.undef:
    mov ecx, [rdx + SY_NAMELEN]
    mov r8d, [rdx + SY_NAMEOFF]
    RECB rsi, r8, g_names        ; rsi must stay distinct from the offset
    mov rdx, rcx
    mov rdi, E_UNDEF
    call asmf_error
.d:
    pop r13
    pop r12
    ret
