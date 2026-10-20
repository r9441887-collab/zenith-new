; ===========================================================================
; asmrt_ops.inc -- the instruction encoders.
;
; Layout: every helper function comes first, then asmf_emit_insn at the bottom.
; NASM scopes `.local` labels to the most recent non-local label, so a global
; function may never be defined between two labels of the same function.
;
; All of them funnel through asmf_enc, a single descriptor-driven emitter:
;
;   g_desc_opcode   opcode byte
;   g_desc_0f       non-zero when the opcode is two-byte (0x0F prefix)
;   edi = r/m operand index, esi = ModRM reg field, edx = operand size
;
; Immediate-only and special forms have their own emitters.
; ===========================================================================

section .text

; ---------------------------------------------------------------------------
; Operand accessors
; ---------------------------------------------------------------------------
; edi = operand index -> rax = record address
asmf_op:
    OPSLOT rax, rdi, r11
    ret

; edi = operand index -> eax = its size, falling back to a register operand
; elsewhere in the list (NASM infers a memory operand's width from its pair).
asmf_op_size:
    push rbx
    push r12
    OPSLOT r12, rdi, r11
    mov eax, [r12 + OP_SIZE]
    test eax, eax
    jnz .done
    mov eax, [rel g_ops + OP_SIZE]
    test eax, eax
    jnz .done
    xor ecx, ecx
.scan:
    cmp ecx, [g_nops]
    jae .fallback
    OPSLOT rdx, rcx, r11
    cmp dword [rdx + OP_KIND], K_REG
    jne .next
    mov eax, [rdx + OP_SIZE]
    test eax, eax
    jnz .done
.next:
    inc ecx
    jmp .scan
.fallback:
    mov eax, SZ_Q
.done:
    pop r12
    pop rbx
    ret

; edi = operand index -> eax = its register number
asmf_op_reg:
    push rbx
    OPSLOT rbx, rdi, r11
    mov eax, [rbx + OP_REG]
    pop rbx
    ret

; edi = operand index -> rax = its symbol-resolved numeric value
asmf_op_val:
    push rbx
    push r12
    OPSLOT r12, rdi, r11
    mov r9, [r12 + OP_VALUE]
    mov ecx, [r12 + OP_SYM]
    test rcx, rcx
    jz .plain
    ; the index goes in rax, not rcx: asmf_sym_val reads rax, so the offset
    ; was taken from slot 0 whenever the displacement itself was zero
    dec rcx
    mov rax, rcx
    call asmf_sym_val
    add rax, r9
    jmp .done
.plain:
    mov rax, r9
.done:
    pop r12
    pop rbx
    ret

; edi = operand index -> eax = OP_KIND
asmf_op_kind:
    OPSLOT rax, rdi, r11
    mov eax, [rax + OP_KIND]
    ret

; edi = operand index -> eax = OP_FLAGS
asmf_op_flags:
    OPSLOT rax, rdi, r11
    mov eax, [rax + OP_FLAGS]
    ret

; CF set when the operand is a register / immediate / memory.
; A bare `cmp` cannot express that: it leaves CF=1 only for kind < K_*, so
; every caller testing `jc`/`jnc` would have seen the predicate inverted.
asmf_op_is_reg:
    OPSLOT rax, rdi, r11
    cmp dword [rax + OP_KIND], K_REG
    sete al
    neg al                         ; 0 -> CF=0, 1 -> 0xFF -> CF=1
    ret
asmf_op_is_imm:
    OPSLOT rax, rdi, r11
    cmp dword [rax + OP_KIND], K_IMM
    sete al
    neg al
    ret
asmf_op_is_mem:
    OPSLOT rax, rdi, r11
    cmp dword [rax + OP_KIND], K_MEM
    sete al
    neg al
    ret

; ---------------------------------------------------------------------------
; asmf_rex_bits -- the REX byte for an instruction.
;   edi = r/m operand index, esi = reg field number, edx = size
;   -> al = REX value (0 when no REX byte is needed at all)
; ---------------------------------------------------------------------------
asmf_rex_bits:
    push rbx
    push r12
    push r13
    mov r12d, esi
    mov r13d, edx
    xor eax, eax

    cmp r13d, SZ_Q
    jne .noW
    mov eax, 8                    ; REX.W
.noW:
    ; Group opcodes keep a /digit in the reg field, never a register, so the
    ; REX.R and spl/bpl/sil/dil rules below must not see it: digits 4..7
    ; used to be mistaken for those registers and `sar byte [rbx], 1` came
    ; out as `40 D0 3B`.  Every opcode listed here is group-only in this
    ; assembler.  ecx is free; al must survive, it already holds REX.W.
    movzx ecx, byte [g_desc_opcode]
    cmp ecx, 0x80
    je .regFieldIsDigit
    cmp ecx, 0x81
    je .regFieldIsDigit
    cmp ecx, 0x83
    je .regFieldIsDigit
    cmp ecx, 0xC0
    je .regFieldIsDigit
    cmp ecx, 0xC1
    je .regFieldIsDigit
    cmp ecx, 0xD0
    je .regFieldIsDigit
    cmp ecx, 0xD1
    je .regFieldIsDigit
    cmp ecx, 0xD2
    je .regFieldIsDigit
    cmp ecx, 0xD3
    je .regFieldIsDigit
    cmp ecx, 0xBA
    je .regFieldIsDigit
    cmp ecx, 0xF6
    je .regFieldIsDigit
    cmp ecx, 0xF7
    je .regFieldIsDigit
    cmp ecx, 0xFE
    je .regFieldIsDigit
    cmp ecx, 0xFF
    je .regFieldIsDigit
    mov ecx, r12d
    shr ecx, 3
    test ecx, ecx
    jz .noR
    or eax, 4                     ; REX.R
.noR:
    ; spl/bpl/sil/dil in either slot need an (otherwise empty) REX byte.
    ; ah/ch/dh/bh share the numbers 4..7 but forbid REX outright, so the
    ; range test only applies when the instruction has no high byte register.
    cmp r13d, SZ_B
    jne .noRex8
    cmp dword [g_hi8_any], 0
    jne .noRex8
    cmp r12d, 4
    jb .noRex8
    cmp r12d, 8
    jae .noRex8
    or eax, 0x40
.noRex8:
.regFieldIsDigit:
    OPSLOT rbx, rdi, r11
    cmp dword [rbx + OP_KIND], K_MEM
    je .mem
    mov ecx, [rbx + OP_REG]
    cmp r13d, SZ_B
    jne .regB
    ; the flag, not the number: 4..7 is spl..dil only when F_REX8 is set,
    ; and is ah..bh when F_HI8 is set instead
    test dword [rbx + OP_FLAGS], F_REX8
    jz .regB
    or eax, 0x40
.regB:
    shr ecx, 3
    test ecx, ecx
    jz .done
    or eax, 1                     ; REX.B
    jmp .done
.mem:
    mov ecx, [rbx + OP_BASE]
    cmp ecx, -1
    je .noB
    mov edx, ecx
    shr edx, 3
    test edx, edx
    jz .noB
    or eax, 1                     ; REX.B
.noB:
    mov ecx, [rbx + OP_INDEX]
    cmp ecx, -1
    je .noX
    mov edx, ecx
    shr edx, 3
    test edx, edx
    jz .noX
    or eax, 2                     ; REX.X
.noX:
.done:
    ; ah/ch/dh/bh and a REX prefix are mutually exclusive: any REX bit at
    ; all turns the high byte into a low byte (or is simply unencodable).
    cmp dword [g_hi8_any], 0
    je .d
    test eax, eax
    jz .d
    mov rdi, E_FORM
    call asmf_err_code
    xor eax, eax
.d:
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_enc -- descriptor-driven r/m + reg encoder.
;   edi = r/m operand index, esi = reg field, edx = size
; ---------------------------------------------------------------------------
asmf_enc:
    push rbx
    push r12
    push r13
    mov r12d, esi
    mov r13d, edx
    mov [g_enc_rm], edi

    ; operand-size prefix
    mov edx, r13d
    cmp edx, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    ; address-size prefix. `[ebx]` is not `[rbx]`: without 67 the ModRM is
    ; assembled against the 64-bit register of the same number.
    mov edi, [g_enc_rm]
    call asmf_op
    cmp dword [rax + OP_KIND], K_MEM
    jne .no67
    cmp dword [g_ri_32], 0
    je .no67
    mov al, 0x67
    call asmf_emit_b
.no67:
    ; REX
    mov edi, [g_enc_rm]
    mov esi, r12d
    mov edx, r13d
    call asmf_rex_bits
    test eax, eax
    jz .noRex
    or al, 0x40
    call asmf_emit_b
.noRex:
    ; two-byte opcode escape
    cmp dword [g_desc_0f], 0
    je .no0F
    mov al, 0x0F
    call asmf_emit_b
.no0F:
    mov al, [g_desc_opcode]
    call asmf_emit_b
    ; ModRM + SIB + disp. asmf_emit_mem wants the record address, not the
    ; operand index asmf_enc was handed: passing the index dereferenced
    ; address 0xc on every memory (and every general) encoding.
    mov edi, [g_enc_rm]
    call asmf_op
    mov rdi, rax
    mov esi, r12d
    mov edx, r13d
    call asmf_emit_mem
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_immval(edi = operand index, esi = width) -- emit the value of that
; operand, resolving a symbolic reference.
; ---------------------------------------------------------------------------
asmf_emit_immval:
    push rbx
    mov rbx, rdi
    call asmf_op_val
    mov edi, esi
    call asmf_emit_n
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_rel32(edi = operand index) -- a near branch displacement, measured
; from the end of the displacement field itself.
; ---------------------------------------------------------------------------
asmf_emit_rel32:
    push rbx
    call asmf_op_val
    mov rdx, [g_pos]
    add rdx, 4                    ; the field ends four bytes from here
    sub rax, rdx
    mov edi, 4
    call asmf_emit_n
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_rel8_ok -- edi = operand index -> CF set when a 2-byte relative form
; is both in range and the same size in every pass, rax = the displacement.
;
; A label stamped with the current pass was defined earlier in it, so its
; address is final.  Forward labels still carry the previous pass's stamp
; (or 0 when never defined), and pass 1 has not resolved them either, so
; both passes agree on "near" for them.  An operand with no symbol at all
; ($ or a literal) is final everywhere.
; ---------------------------------------------------------------------------
asmf_rel8_ok:
    push rbx
    push r12
    mov r12d, edi
    ; A label defined earlier in this pass already has its final address. A
    ; label still ahead has the address the previous sizing run computed --
    ; asm_run repeats that run until the addresses stop moving, so both the
    ; size pass and the emit pass read the same number here.
    mov edi, r12d
    call asmf_op_val
    mov rdx, [g_pos]
    add rdx, 2                  ; opcode byte + rel8
    sub rax, rdx
    cmp rax, -128
    jl .no
    cmp rax, 127
    jg .no
    pop r12
    pop rbx
    stc
    ret
.no:
    xor eax, eax
    pop r12
    pop rbx
    clc
    ret

; ---------------------------------------------------------------------------
; asmf_emit_reg_imm -- mov reg, imm
;   edi = destination register operand index, r13d = size
;   The immediate itself is always operand 1; taking it from `edi` encoded
;   the source register's (cleared) OP_VALUE as the literal.
; ---------------------------------------------------------------------------
asmf_emit_reg_imm:
    push rbx
    push r12
    push r13
    mov r12d, r13d
    mov r13, rdi
    OPSLOT rbx, r13, r11
    mov eax, [rbx + OP_REG]
    mov [g_enc_reg], eax
    mov edi, 1
    call asmf_op_val
    mov [g_immval], rax

    ; Pick the 64-bit immediate form before any prefix goes out.  A value in
    ; 0..0xffffffff uses the plain 32-bit mov with no REX at all: writing eax
    ; zeroes the upper half, so `mov rax, 0` is 5 bytes instead of 7 or 10.
    ; A negative value that fits a signed dword goes through C7 /0 id (7),
    ; everything else through B8+r imm64 (10).
    mov dword [g_enc_form], 0
    cmp r12d, SZ_Q
    jne .formDone
    ; a label or `$` has no settled value yet, and NASM always gives those
    ; the full 64-bit immediate form
    mov edi, 1
    call asmf_op_flags
    test eax, F_RELOC
    jz .formRange
    mov dword [g_enc_form], 2
    jmp .formDone
.formRange:
    mov rax, [g_immval]
    test rax, rax
    js .formSigned
    mov rdx, 0xFFFFFFFF
    cmp rax, rdx
    jbe .formDone
    mov dword [g_enc_form], 2
    jmp .formDone
.formSigned:
    mov rdx, rax
    sar rdx, 31                 ; 0 only when the value is a signed dword
    inc rdx
    jnz .formWide
    mov dword [g_enc_form], 1
    jmp .formDone
.formWide:
    ; below -2^31 the value no longer fits an id, so it needs imm64
    mov dword [g_enc_form], 2
.formDone:
    ; there is no ModRM register field in either form, so the REX byte
    ; carries W and B only -- asking for REX.R gave `mov r8, 0` a 0x45 REX
    ; where the plain 0x41 is correct.
    ; the 66 operand-size prefix has to leave before the REX byte: NASM
    ; writes `66 41 B8 imm16`, never `41 66 B8 imm16`
    cmp r12d, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    mov rdi, r13
    xor esi, esi
    mov edx, r12d
    call asmf_rex_bits
    cmp dword [g_enc_form], 0
    jne .rexBits
    cmp r12d, SZ_Q
    jne .rexBits
    and al, 0xF7                ; no REX.W for the zero-extending form
.rexBits:
    test eax, eax
    jz .noRex
    or al, 0x40
    call asmf_emit_b
.noRex:
    cmp r12d, SZ_B
    je .b8
    cmp r12d, SZ_W
    je .w16
    ; 32-bit destinations always take the imm32 form
    cmp r12d, SZ_D
    je .b32
    ; 64-bit destinations: the form chosen above decides.  `48 B8 imm32` is
    ; not an instruction -- with REX.W the B8+r form always takes a full
    ; 64-bit immediate -- so only form 0 may reuse the 32-bit encoding.
    mov eax, [g_enc_form]
    test eax, eax
    jz .b32
    cmp eax, 1
    je .c7
    jmp .b64
.c7:
    mov al, 0xC7
    call asmf_emit_b
    mov eax, [g_enc_reg]
    and al, 7
    or al, 0xC0                  ; mod = 11: the r/m field is a register
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 4
    call asmf_emit_n
    jmp .done
.b8:
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0xB0
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    jmp .done
.w16:
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0xB8
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 2
    call asmf_emit_n
    jmp .done
.b32:
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0xB8
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 4
    call asmf_emit_n
    jmp .done
.b64:
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0xB8
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 8
    call asmf_emit_n
.done:
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_rm_imm -- mov r/m, imm (B0+r ib, C7 /0 iw/id, REX.W C7 /0 id)
;   edi = r/m operand index, r13d = size
; ---------------------------------------------------------------------------
asmf_emit_rm_imm:
    push rbx
    push r12
    push r13
    mov r12d, r13d
    mov r13, rdi
    OPSLOT rbx, r13, r11

    mov edx, r12d
    cmp edx, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    ; address-size prefix for a 32-bit base/index inside the brackets
    cmp dword [rbx + OP_KIND], K_MEM
    jne .no67
    cmp dword [g_ri_32], 0
    je .no67
    mov al, 0x67
    call asmf_emit_b
.no67:
    mov rdi, r13
    mov esi, 0
    mov edx, r12d
    call asmf_rex_bits
    test eax, eax
    jz .noRex
    or al, 0x40
    call asmf_emit_b
.noRex:
    cmp dword [rbx + OP_KIND], K_REG
    jne .mem
    ; register: B0+r for bytes, C7 /0 otherwise
    mov eax, [rbx + OP_REG]
    and al, 7
    cmp r12d, SZ_B
    jne .regC7
    add al, 0xB0
    call asmf_emit_b
    jmp .imm
.regC7:
    mov al, 0xC7
    call asmf_emit_b
    ; al still holds the opcode here, so the ModRM has to be rebuilt:
    ; mod=11 plus the register number
    mov eax, [rbx + OP_REG]
    and al, 7
    or al, 0xC0
    call asmf_emit_b
    jmp .imm
.mem:
    mov al, 0xC6
    cmp r12d, SZ_B
    je .opHave
    mov al, 0xC7
.opHave:
    call asmf_emit_b
    mov rdi, r13                  ; r/m operand index -> record address
    call asmf_op
    mov rdi, rax
    mov esi, 0
    mov edx, r12d
    call asmf_emit_mem
.imm:
    ; the immediate is operand 1, not the r/m operand in r13: taking it from
    ; r13 encoded the (zero) value of the destination memory slot
    mov rdi, 1
    cmp r12d, SZ_B
    je .i1
    cmp r12d, SZ_W
    je .i2
    mov esi, 4
    jmp .emit
.i1:
    mov esi, 1
    jmp .emit
.i2:
    mov esi, 2
.emit:
    call asmf_emit_immval
.done:
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_movx_common -- shared body for movzx / movsx
;   edi = source operand, esi = reg field, edx = destination size
; ---------------------------------------------------------------------------
asmf_movx_common:
    push rbx
    push r12
    push r13
    mov r12d, esi                ; destination register (the reg field)
    mov r13d, edx                ; destination size (prefixes and REX.W)

    mov edi, 1
    call asmf_op_size            ; the source size picks the opcode
    cmp eax, SZ_B
    je .srcByte
    cmp eax, SZ_W
    je .srcWord
    cmp eax, SZ_D
    je .srcDword
    jmp .badSize
.srcDword:
    ; only `movsxd r64, r/m32` exists; movzx from a dword has no encoding
    cmp dword [g_mnemonic_id], H_MOVSX
    jne .badSize
    cmp r13d, SZ_Q
    jne .badSize
    mov r8d, 0x63
    jmp .setOp
.srcByte:
    mov r8d, 0xB6                ; movzx r, r/m8
    cmp dword [g_mnemonic_id], H_MOVSX
    jne .setOp
    mov r8d, 0xBE                ; movsx r, r/m8
    jmp .setOp
.srcWord:
    mov r8d, 0xB7                ; movzx r, r/m16
    cmp dword [g_mnemonic_id], H_MOVSX
    jne .setOp
    mov r8d, 0xBF                ; movsx r, r/m16
.setOp:
    mov byte [g_desc_0f], 1
    cmp r8d, 0x63
    jne .setOpGo
    mov byte [g_desc_0f], 0       ; movsxd is a plain one-byte opcode
.setOpGo:
    mov eax, r8d
    mov [g_desc_opcode], al
    mov edi, 1                   ; r/m is the source, not the destination
    mov esi, r12d
    mov edx, r13d
    call asmf_enc
    jmp .done
.badSize:
    mov rdi, E_SIZE
    call asmf_err_code
.done:
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_alu -- shared ALU body. g_param is the group index.
; ---------------------------------------------------------------------------
asmf_alu:
    push rbx
    mov eax, [g_param]
    shl eax, 3
    mov [g_alu_base], eax

    mov edi, 1
    call asmf_op_is_imm
    jc .withImm
    mov edi, 1
    call asmf_op_is_reg
    jc .regSecond

    ; operand 1 is the r/m side: `op r, r/m` is base+2/3, the reg field
    ; holds operand 0 and r/m holds operand 1
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax
    mov eax, [g_alu_base]
    add al, 0x02
    cmp r13d, SZ_B
    je .rmSide
    add al, 0x01
.rmSide:
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 0
    mov edi, 1
    mov edx, r13d
    call asmf_enc
    jmp .done

.regSecond:
    ; operand 1 is a register: `op r/m, r` is base+0/1, the reg field holds
    ; operand 1 and r/m holds operand 0 (the destination)
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_reg
    mov esi, eax
    mov eax, [g_alu_base]
    add al, 0x00
    cmp r13d, SZ_B
    je .regSide
    add al, 0x01
.regSide:
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    jmp .done

.withImm:
    ; an accumulator destination may use the 1-byte short opcode
    mov edi, 0
    call asmf_op_is_reg
    jnc .general
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    ; a byte accumulator is always the shortest form: `add al, 1` is 04 01
    cmp r13d, SZ_B
    je .accForm
    ; `83 /d ib` (opcode + modrm + byte) beats the accumulator `05 id`
    ; (opcode + imm32) whenever the immediate fits a signed byte, and the
    ; accumulator form only wins beyond that
    mov edi, 1
    call asmf_op_val
    cmp rax, -128
    jl .accForm
    cmp rax, 127
    jg .accForm
    jmp .general
.accForm:
    mov edi, 0
    call asmf_op_reg
    test eax, eax             ; only eax/ax, never r8 or esp
    jz .shortForm
    jmp .general

.shortForm:
    mov eax, [g_alu_base]
    cmp r13d, SZ_B
    jne .wide
    add al, 0x04
    jmp .haveOp
.wide:
    add al, 0x05
.haveOp:
    mov [g_desc_opcode], al
    cmp r13d, SZ_Q
    je .w64
    cmp r13d, SZ_W
    je .w16
    jmp .have66
.w64:
    mov al, 0x48
    call asmf_emit_b
    jmp .have66
.w16:
    mov al, 0x66
    call asmf_emit_b
.have66:
    mov al, [g_desc_opcode]
    call asmf_emit_b
    ; no ModRM here: the accumulator forms are [opcode][imm], and the byte the
    ; reg<<3 computation used to emit landed in front of the immediate
    mov rdi, 1
    cmp r13d, SZ_B
    je .sf1
    mov esi, 4
    jmp .sfGo
.sf1:
    mov esi, 1
.sfGo:
    call asmf_emit_immval
    jmp .done

.general:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_val
    mov [g_immval], rax
    mov dword [g_desc_0f], 0
    mov eax, [g_param]
    mov esi, eax                 ; reg field = the group /digit
    mov edi, 0                   ; r/m = operand 0
    mov edx, r13d
    ; the group opcodes are literals: g_alu_base is the /digit << 3 and
    ; belongs in the ModRM reg field, so adding it here turned `cmp` (digit 7)
    ; into 0x38+0x83 = 0xBB instead of 0x83
    cmp r13d, SZ_B
    je .op80
    mov rax, [g_immval]
    cmp rax, -128
    jl .imm32
    cmp rax, 127
    jg .imm32
    mov al, 0x83                 ; 83 /digit ib, sign-extended
    mov [g_desc_opcode], al
    call asmf_enc
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    jmp .done
.op80:
    mov al, 0x80                 ; 80 /digit ib
    mov [g_desc_opcode], al
    call asmf_enc
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    jmp .done
.imm32:
    mov al, 0x81                 ; 81 /digit id
    mov [g_desc_opcode], al
    call asmf_enc
    mov rdi, 1
    mov esi, 4
    call asmf_emit_immval
.done:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_shift -- shared shift/rotate body. g_param is the /digit.
; ---------------------------------------------------------------------------
asmf_shift:
    push rbx
    mov edi, 0
    call asmf_op_size
    mov r12d, eax
    mov edi, 1
    call asmf_op_is_imm
    jc .imm

    ; a count in cl
    mov edi, 1
    call asmf_op_reg
    cmp eax, 1
    jne .bad
    mov dword [g_desc_0f], 0
    mov esi, [g_param]
    xor edi, edi
    mov edx, r12d
    cmp r12d, SZ_B
    je .clGo
    mov byte [g_desc_opcode], 0xD3
    call asmf_enc
    jmp .done
.clGo:
    mov byte [g_desc_opcode], 0xD2
    call asmf_enc
    jmp .done

.imm:
    mov edi, 1
    call asmf_op_val
    mov [g_immval], rax
    mov dword [g_desc_0f], 0
    mov esi, [g_param]
    xor edi, edi
    mov edx, r12d
    cmp rax, 1
    jne .imm8
    cmp r12d, SZ_B
    je .oneGo
    mov byte [g_desc_opcode], 0xD1
    call asmf_enc
    jmp .done
.oneGo:
    mov byte [g_desc_opcode], 0xD0
    call asmf_enc
    jmp .done
.imm8:
    cmp r12d, SZ_B
    je .i8Go
    mov byte [g_desc_opcode], 0xC1
    call asmf_enc
    jmp .emitCount
.i8Go:
    mov byte [g_desc_opcode], 0xC0
    call asmf_enc
.emitCount:
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    jmp .done

.bad:
    mov rdi, E_FORM
    call asmf_err_code
.done:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_misc -- an operand-less instruction, encoded as a byte string in
; misc_tbl. g_param is the byte offset of that entry.
; ---------------------------------------------------------------------------
asmf_misc:
    push rbx
    push r12
    lea rbx, [rel misc_tbl]
    mov r12d, [g_param]
    ; the length is the first byte of the slot; the opcode bytes follow it
    movzx edx, byte [rbx + r12]
    test edx, edx
    jz .done
    lea rdi, [rbx + r12 + 1]
    xor ecx, ecx
.loop:
    cmp ecx, edx
    jae .done
    mov al, [rdi + rcx]
    call asmf_emit_b
    inc ecx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_data -- db / dw / dd / dq. g_param is the element size.
; ---------------------------------------------------------------------------
asmf_data:
    push rbx
    push r12
    mov r12d, [g_param]
    xor ebx, ebx
.loop:
    cmp ebx, [g_nops]
    jae .done
    mov edi, ebx
    call asmf_op_kind
    cmp eax, K_STR
    je .string
    mov rdi, rbx
    mov esi, r12d
    call asmf_emit_immval
    inc ebx
    jmp .loop
.string:
    ; a string contributes one element per whole chunk of the element size
    REC rdi, rbx, 6, g_ops, r11
    mov rdi, [rdi + OP_STRPTR]
    REC rsi, rbx, 6, g_ops, r11
    mov rsi, [rsi + OP_STREND]
    call asmf_emit_str
    inc ebx
    jmp .loop
.done:
    pop r12
    pop rbx
    ret

; rdi = first byte, rsi = one past the last -> emit them as data elements
asmf_emit_str:
    push rbx
    mov rbx, rdi
    mov r12d, [g_param]
.loop:
    cmp rbx, rsi
    jae .done
    xor eax, eax
    xor r8d, r8d              ; byte position inside the element
.bytes:
    cmp r8d, r12d
    jae .emit
    xor edx, edx
    cmp rbx, rsi
    jae .pad                  ; a partial trailing group is zero padded
    movzx edx, byte [rbx]
    inc rbx
.pad:
    ; the first byte of the group is the least significant one: shifting the
    ; accumulator instead put 'a' at the top and `dw "ab"` came out as 6261
    mov ecx, r8d
    shl ecx, 3               ; byte position -> bit shift
    shl rdx, cl
    or rax, rdx
    inc r8d
    jmp .bytes
.emit:
    mov edi, r12d
    call asmf_emit_n
    jmp .loop
.done:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; asmf_emit_insn -- dispatch on the mnemonic id
;
; The outer entry point does the per-instruction bookkeeping the dispatch
; itself must not be littered with: a pending RIP fixup, because the
; [rel ...] displacement is written before a trailing immediate goes out, so
; the distance is only final once the whole instruction is out.
; ---------------------------------------------------------------------------
asmf_emit_insn:
    push rbx
    mov qword [g_rip_patch], -1
    call asmf_emit_insn_go
    mov rcx, [g_rip_patch]
    cmp rcx, -1
    je .nofix
    mov rbx, [g_out]
    test rbx, rbx
    jz .nofix                    ; sizing pass: there is no buffer to patch
    mov rax, [g_rip_target]
    sub rax, [g_pos]             ; g_pos is now the end of the instruction
    mov [rbx + rcx], eax
.nofix:
    pop rbx
    ret

asmf_emit_insn_go:
    mov eax, [g_mnemonic_id]
    cmp eax, H_MOV
    je .h_mov
    cmp eax, H_MOVZX
    je .h_movzx
    cmp eax, H_MOVSX
    je .h_movsx
    cmp eax, H_MOVSXD
    je .h_movsxd
    cmp eax, H_LEA
    je .h_lea
    cmp eax, H_XCHG
    je .h_xchg
    cmp eax, H_PUSH
    je .h_push
    cmp eax, H_POP
    je .h_pop
    cmp eax, H_ALU
    je .h_alu
    cmp eax, H_TEST
    je .h_test
    cmp eax, H_UNARY
    je .h_unary
    cmp eax, H_IMUL
    je .h_imul
    cmp eax, H_INCDEC
    je .h_incdec
    cmp eax, H_SHIFT
    je .h_shift
    cmp eax, H_JMP
    je .h_jmp
    cmp eax, H_CALL
    je .h_call
    cmp eax, H_RET
    je .h_ret
    cmp eax, H_LEAVE
    je .h_leave
    cmp eax, H_JCC
    je .h_jcc
    cmp eax, H_SETCC
    je .h_setcc
    cmp eax, H_CMOVCC
    je .h_cmovcc
    cmp eax, H_XADD
    je .h_xadd
    cmp eax, H_CMPXCHG
    je .h_cmpxchg
    cmp eax, H_BSFBSR
    je .h_bsfbsr
    cmp eax, H_BSWAP
    je .h_bswap
    cmp eax, H_BT
    je .h_bt
    cmp eax, H_NOP
    je .h_nop
    cmp eax, H_MISC
    je .h_misc
    cmp eax, H_INT
    je .h_int
    cmp eax, H_DATA
    je .h_data
    cmp eax, H_POPCNT
    je .h_popcnt
    cmp eax, H_TZCNT
    je .h_tzcnt
    cmp eax, H_LOOP
    je .h_loop
    jmp .bad
.bad:
    mov rdi, E_MNEM
    call asmf_err_code
    ret
.h_mov:
    call asmf_h_mov
    ret
.h_movzx:
    call asmf_h_movzx
    ret
.h_movsx:
    call asmf_h_movsx
    ret
.h_movsxd:
    call asmf_h_movsxd
    ret
.h_lea:
    call asmf_h_lea
    ret
.h_xchg:
    call asmf_h_xchg
    ret
.h_push:
    call asmf_h_push
    ret
.h_pop:
    call asmf_h_pop
    ret
.h_alu:
    call asmf_h_alu
    ret
.h_test:
    call asmf_h_test
    ret
.h_unary:
    call asmf_h_unary
    ret
.h_imul:
    call asmf_h_imul
    ret
.h_incdec:
    call asmf_h_incdec
    ret
.h_shift:
    call asmf_h_shift
    ret
.h_jmp:
    call asmf_h_jmp
    ret
.h_call:
    call asmf_h_call
    ret
.h_ret:
    call asmf_h_ret
    ret
.h_leave:
    call asmf_h_leave
    ret
.h_jcc:
    call asmf_h_jcc
    ret
.h_setcc:
    call asmf_h_setcc
    ret
.h_cmovcc:
    call asmf_h_cmovcc
    ret
.h_xadd:
    call asmf_h_xadd
    ret
.h_cmpxchg:
    call asmf_h_cmpxchg
    ret
.h_bsfbsr:
    call asmf_h_bsfbsr
    ret
.h_bswap:
    call asmf_h_bswap
    ret
.h_bt:
    call asmf_h_bt
    ret
.h_nop:
    call asmf_h_nop
    ret
.h_misc:
    call asmf_h_misc
    ret
.h_int:
    call asmf_h_int
    ret
.h_data:
    call asmf_h_data
    ret
.h_popcnt:
    call asmf_h_popcnt
    ret
.h_tzcnt:
    call asmf_h_tzcnt
    ret
.h_loop:
    call asmf_h_loop
    ret
; ===========================================================================
; mov
; ===========================================================================
asmf_h_mov:
    ; source (operand 1) is an immediate
    mov edi, 1
    call asmf_op_is_imm
    jc .imm
    ; destination (operand 0) is a register -> mov r, r/m
    mov edi, 0
    call asmf_op_is_reg
    jc .dstReg
    ; destination is memory: the source must be a register -> mov r/m, r
    mov edi, 1
    call asmf_op_is_reg
    jnc .bad
    mov edi, 1
    call asmf_op_reg
    mov esi, eax                 ; reg field = source
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0x89
    cmp r13d, SZ_B
    jne .memOp
    mov byte [g_desc_opcode], 0x88   ; mov r/m8, r8
.memOp:
    mov dword [g_desc_0f], 0
    xor edi, edi                 ; r/m = destination (memory)
    mov edx, r13d
    call asmf_enc
    ret

.dstReg:
    ; destination is a register, source is a register or memory
    mov edi, 1
    call asmf_op_is_reg
    jc .bothReg
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0x8B
    cmp r13d, SZ_B
    jne .loadOp
    mov byte [g_desc_opcode], 0x8A   ; mov r8, r/m8: 0x8B has no byte form
.loadOp:
    mov dword [g_desc_0f], 0
    mov edi, 1                   ; r/m = source
    jmp .enc
.bothReg:
    ; reg,reg goes through `mov r/m, r`, which is what NASM picks: the
    ; destination belongs in the r/m field and the source in reg
    mov edi, 1
    call asmf_op_reg
    mov esi, eax                 ; reg field = source
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0x89
    cmp r13d, SZ_B
    jne .storeOp
    mov byte [g_desc_opcode], 0x88
.storeOp:
    mov dword [g_desc_0f], 0
    xor edi, edi                 ; r/m = destination
.enc:
    mov edx, r13d
    call asmf_enc
    ret

.imm:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_is_reg
    jc .regImm
    mov edi, 0
    call asmf_emit_rm_imm
    ret

.regImm:
    mov edi, 0
    call asmf_emit_reg_imm
    ret

.bad:
    mov rdi, E_FORM
    call asmf_err_code
    ret

; ===========================================================================
; movzx / movsx / movsxd
; ===========================================================================
asmf_h_movzx:
    mov edi, 0                   ; the reg field is the destination register
    call asmf_op_reg
    mov esi, eax
    mov edi, 0
    call asmf_op_size
    mov edx, eax                 ; destination size drives REX.W and 66
    call asmf_movx_common
    ret

asmf_h_movsx:
    mov edi, 0                   ; the reg field is the destination register
    call asmf_op_reg
    mov esi, eax
    mov edi, 0
    call asmf_op_size
    mov edx, eax                 ; destination size drives REX.W and 66
    call asmf_movx_common
    ret

asmf_h_movsxd:
    mov edi, 0                   ; reg field = destination, r/m = source
    call asmf_op_reg
    mov esi, eax
    mov byte [g_desc_opcode], 0x63
    mov dword [g_desc_0f], 0
    xor edi, edi
    call asmf_op_size
    mov edx, eax                 ; the 64-bit destination brings the REX.W
    mov edi, 1
    call asmf_enc
    ret

; ===========================================================================
; lea
; ===========================================================================
asmf_h_lea:
    mov edi, 1
    call asmf_op_is_mem
    jnc .bad                   ; the address is the second operand
    ; asmf_op_size reuses edx, so the size has to be read before the reg
    mov edi, 0
    call asmf_op_size
    mov edx, eax               ; the destination's size drives REX.W / 66
    mov edi, 0
    call asmf_op_reg
    mov esi, eax               ; reg field = destination
    mov byte [g_desc_opcode], 0x8D
    mov dword [g_desc_0f], 0
    mov edi, 1                 ; r/m = the effective address
    call asmf_enc
    ret
.bad:
    mov rdi, E_FORM
    call asmf_err_code
    ret

; ===========================================================================
; xchg
; ===========================================================================
asmf_h_xchg:
    mov edi, 0
    call asmf_op_is_reg
    jnc .general
    mov edi, 1
    call asmf_op_is_reg
    jnc .general
    mov edi, 0
    call asmf_op_size
    cmp eax, SZ_B
    je .general             ; `xchg al, bl` has no 90+r form
    ; exactly one operand has to be the accumulator; the other one supplies
    ; rd (`xchg eax, ebx` is 93, i.e. 90+ebx, and `xchg eax, eax` is not
    ; the short form at all because it would assemble to a bare 90/nop)
    mov edi, 0
    call asmf_op_reg
    test eax, eax
    jnz .notAcc0
    mov edi, 1
    call asmf_op_reg
    test eax, eax
    jnz .short              ; eax = rd
    ; Both operands are the accumulator.  The 90+r form would be a bare nop
    ; for the dword size, so `xchg eax,eax` is `87 c0`, but the REX.W form
    ; is a real `xchg rax,rax` and NASM gives it `48 90`.
    mov edi, 0
    call asmf_op_size
    cmp eax, SZ_Q
    jne .general
    xor eax, eax                ; rd = rax
    jmp .short
.notAcc0:
    mov edi, 1
    call asmf_op_reg
    test eax, eax
    jnz .general
    mov edi, 0
    call asmf_op_reg
.short:
    mov [g_enc_reg], eax    ; rd
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    cmp r13d, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    xor edx, edx
    cmp r13d, SZ_Q
    jne .rexWdone
    or edx, 8               ; REX.W
.rexWdone:
    mov eax, [g_enc_reg]
    test al, 8
    jz .rexBdone
    or edx, 1               ; REX.B
.rexBdone:
    test edx, edx
    jz .noRex
    mov eax, edx
    or al, 0x40
    call asmf_emit_b
.noRex:
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0x90
    call asmf_emit_b
    ret

.general:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = operand 0
    mov dword [g_desc_0f], 0
    mov edi, 1                   ; r/m = operand 1
    mov edx, r13d
    cmp rdx, SZ_B
    jne .wide
    mov byte [g_desc_opcode], 0x86
    call asmf_enc
    ret
.wide:
    mov byte [g_desc_opcode], 0x87
    call asmf_enc
    ret

; ===========================================================================
; push / pop
; ===========================================================================
asmf_h_push:
    mov edi, 0
    call asmf_op_is_imm
    jc .imm
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    cmp eax, SZ_D
    je .badSize
    cmp eax, SZ_B
    je .badSize
    mov edi, 0
    call asmf_op_is_reg
    jnc .rm
    cmp r13d, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    mov edi, 0
    call asmf_op_reg
    mov ecx, eax
    shr ecx, 3
    test ecx, ecx
    jz .goPush
    mov al, 0x41
    call asmf_emit_b
.goPush:
    mov edi, 0
    call asmf_op_reg
    and al, 7
    add al, 0x50
    call asmf_emit_b
    ret
.rm:
    ; FF /6: the reg field is the opcode extension, never the operand's
    ; OP_REG (which is 0 for a memory operand)
    mov esi, 6
    mov byte [g_desc_opcode], 0xFF
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    cmp edx, SZ_Q
    jne .pushEnc
    mov edx, SZ_D              ; push r/m is already 64-bit; no REX.W
.pushEnc:
    call asmf_enc
    ret
.badSize:
    mov rdi, E_OPERAND          ; push takes a 16- or 64-bit operand only
    call asmf_err_code
    ret
.imm:
    call asmf_op_val
    mov [g_immval], rax
    mov rdx, rax
    cmp rdx, -128
    jl .long
    cmp rdx, 127
    jg .long
    mov al, 0x6A
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    ret
.long:
    ; `68 id` already pushes a sign-extended 32-bit value, so REX.W would only
    ; add a byte
    mov al, 0x68
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 4
    call asmf_emit_n
    ret

asmf_h_pop:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    cmp r13d, SZ_D
    je .popBad
    cmp r13d, SZ_B
    je .popBad
    cmp r13d, SZ_W
    jne .no66
    mov al, 0x66
    call asmf_emit_b
.no66:
    mov edi, 0
    call asmf_op_is_reg
    jnc .rm
    mov edi, 0
    call asmf_op_reg
    mov ecx, eax
    shr ecx, 3
    test ecx, ecx
    jz .goPop
    mov al, 0x41
    call asmf_emit_b
.goPop:
    mov edi, 0
    call asmf_op_reg
    and al, 7
    add al, 0x58
    call asmf_emit_b
    ret
.popBad:
    mov rdi, E_OPERAND          ; pop takes a 16- or 64-bit operand only
    call asmf_err_code
    ret
.rm:
    mov edi, 0
    call asmf_op_reg
    mov esi, eax
    mov byte [g_desc_opcode], 0x8F
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    cmp edx, SZ_Q
    jne .popEnc
    mov edx, SZ_D              ; pop r/m is already 64-bit; no REX.W
.popEnc:
    call asmf_enc
    ret

; ===========================================================================
; ALU group
; ===========================================================================
asmf_h_alu:
    call asmf_alu
    ret

; ===========================================================================
; test
; ===========================================================================
asmf_h_test:
    mov edi, 1
    call asmf_op_is_imm
    jc .withImm
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_reg
    mov esi, eax
    mov byte [g_desc_opcode], 0x84
    cmp r13d, SZ_B
    je .goTest
    mov byte [g_desc_opcode], 0x85
.goTest:
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret

.withImm:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_is_reg
    jnc .rm
    mov edi, 0
    call asmf_op_reg
    test eax, eax             ; only the real accumulator
    jnz .rm
    ; accumulator short form
    cmp r13d, SZ_B
    je .acc8
    cmp r13d, SZ_W
    je .acc16
    cmp r13d, SZ_Q
    je .acc64
    mov al, 0xA9
    jmp .accGo
.acc8:
    mov al, 0xA8
    jmp .accGo
.acc16:
    mov al, 0x66
    call asmf_emit_b
    mov al, 0xA9
    jmp .accGo
.acc64:
    mov al, 0x48
    call asmf_emit_b
    mov al, 0xA9
.accGo:
    call asmf_emit_b
    mov rdi, 1
    cmp r13d, SZ_B
    je .acc1
    mov esi, 4
    jmp .accIn
.acc1:
    mov esi, 1
.accIn:
    call asmf_emit_immval
    ret

.rm:
    mov byte [g_desc_opcode], 0xF6
    cmp r13d, SZ_B
    je .rmGo
    mov byte [g_desc_opcode], 0xF7
.rmGo:
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    mov rdi, 1
    cmp r13d, SZ_B
    je .rm1
    mov esi, 4
    jmp .rmIn
.rm1:
    mov esi, 1
.rmIn:
    call asmf_emit_immval
    ret

; ===========================================================================
; not / neg / mul / div / idiv   (F6 /digit, F7 /digit)
; ===========================================================================
asmf_h_unary:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0xF6
    cmp r13d, SZ_B
    je .go
    mov byte [g_desc_opcode], 0xF7
.go:
    mov esi, [g_param]
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret

; ===========================================================================
; imul
; ===========================================================================
asmf_h_imul:
    cmp dword [g_nops], 1
    je .one
    cmp dword [g_nops], 2
    je .two
    ; three operands: reg <- r/m * imm
    mov edi, 2
    call asmf_op_val
    mov [g_immval], rax
    ; the third operand is always the immediate multiplier
    mov edi, 2
    call asmf_op_is_imm
    jnc .bad
    mov edi, 1
    call asmf_op_is_reg
    jc .three
    mov edi, 1
    call asmf_op_is_mem
    jc .three
    jmp .bad
.three:
    mov dword [g_imul_rm], 1      ; r/m = the multiplied source
    mov dword [g_imul_immop], 2   ; the multiplier is operand 2
    jmp .immForm
.two:
    mov edi, 1
    call asmf_op_is_imm
    jnc .twoReg
    ; `imul r, imm` is `imul r, r, imm`: the destination doubles as the
    ; source.  Routing the immediate through the memory encoder used to
    ; turn its value into a displacement (`48 0f af 04 25 03 00 00 00`).
    mov edi, 1
    call asmf_op_val
    mov [g_immval], rax
    mov edi, 0
    call asmf_op_is_reg
    jnc .bad
    mov dword [g_imul_rm], 0      ; r/m = the destination itself
    mov dword [g_imul_immop], 1   ; the multiplier is operand 1
    jmp .immForm
.twoReg:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination (operand 0)
    mov byte [g_desc_opcode], 0xAF
    mov dword [g_desc_0f], 1
    mov edi, 1                   ; r/m = source (operand 1)
    mov edx, r13d
    call asmf_enc
    ret
.immForm:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination (operand 0)
    mov dword [g_desc_0f], 0
    mov rax, [g_immval]
    cmp rax, -128
    jl .t32
    cmp rax, 127
    jg .t32
    mov byte [g_desc_opcode], 0x6B
    mov edi, [g_imul_rm]
    mov edx, r13d
    call asmf_enc
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    ret
.t32:
    mov byte [g_desc_opcode], 0x69
    mov edi, [g_imul_rm]
    mov edx, r13d
    call asmf_enc
    mov edi, [g_imul_immop]
    mov esi, 4
    call asmf_emit_immval
    ret
.one:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0xF6
    cmp r13d, SZ_B
    je .oneGo
    mov byte [g_desc_opcode], 0xF7
.oneGo:
    mov esi, 5
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret
.bad:
    mov rdi, E_FORM
    call asmf_err_code
    ret

; ===========================================================================
; inc / dec
; ===========================================================================
asmf_h_incdec:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov eax, [g_param]
    mov [g_id_digit], eax
    ; register and memory take the same group form: 0x40+r is a REX prefix
    ; in long mode, so `inc eax` used to assemble to `40 C0`
    mov byte [g_desc_opcode], 0xFE
    cmp r13d, SZ_B
    je .go
    mov byte [g_desc_opcode], 0xFF
.go:
    mov esi, [g_id_digit]
    mov dword [g_desc_0f], 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret

; ===========================================================================
; shifts and rotates
; ===========================================================================
asmf_h_shift:
    call asmf_shift
    ret

; ===========================================================================
; jmp / call
; ===========================================================================
asmf_h_jmp:
    mov edi, 0
    call asmf_op_is_mem
    jc .indirect
    ; a register target is `FF /4`, never a relative encoding
    mov edi, 0
    call asmf_op_is_reg
    jc .indirect
    mov edi, 0
    call asmf_rel8_ok
    jnc .far
    mov [g_immval], rax
    mov al, 0xEB
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    ret
.far:
    mov al, 0xE9
    call asmf_emit_b
    xor edi, edi
    call asmf_emit_rel32
    ret
.indirect:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0xFF
    mov dword [g_desc_0f], 0
    mov esi, 4                   ; /4 = jmp
    xor edi, edi
    mov edx, r13d
    cmp edx, SZ_Q
    jne .jmpEnc
    mov edx, SZ_D              ; an indirect jmp is already 64-bit
.jmpEnc:
    call asmf_enc
    ret

asmf_h_call:
    mov edi, 0
    call asmf_op_is_mem
    jc .indirect
    mov edi, 0
    call asmf_op_is_reg
    jc .regForm
    mov al, 0xE8
    call asmf_emit_b
    xor edi, edi
    call asmf_emit_rel32
    ret
.regForm:
    mov byte [g_desc_opcode], 0xFF
    mov dword [g_desc_0f], 0
    mov esi, 2                   ; /2 = call
    xor edi, edi
    mov edx, SZ_D                ; `FF /2` needs no REX.W: it is already 64-bit
    call asmf_enc
    ret
.indirect:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0xFF
    mov dword [g_desc_0f], 0
    mov esi, 2
    xor edi, edi
    mov edx, r13d
    cmp edx, SZ_Q
    jne .callEnc
    mov edx, SZ_D              ; an indirect call is already 64-bit
.callEnc:
    call asmf_enc
    ret

; ---------------------------------------------------------------------------
; asmf_emit_rel32 is defined above; jcc uses the same displacement rule.
; ---------------------------------------------------------------------------
asmf_h_ret:
    cmp dword [g_nops], 0
    je .plain
    mov al, 0xC2
    call asmf_emit_b
    xor edi, edi
    mov esi, 2
    call asmf_emit_immval
    ret
.plain:
    mov al, 0xC3
    call asmf_emit_b
    ret

asmf_h_leave:
    mov al, 0xC9
    call asmf_emit_b
    ret

asmf_h_jcc:
    xor edi, edi
    call asmf_rel8_ok
    jnc .near
    mov [g_immval], rax
    mov eax, [g_param]
    add al, 0x70                ; short: 70+cc rel8
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    ret
.near:
    mov al, 0x0F
    call asmf_emit_b
    mov eax, [g_param]
    add al, 0x80
    call asmf_emit_b
    xor edi, edi
    call asmf_emit_rel32
    ret

asmf_h_setcc:
    mov eax, [g_param]
    add al, 0x90
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 1
    mov esi, 0
    xor edi, edi
    mov edx, SZ_B
    call asmf_enc
    ret

asmf_h_cmovcc:
    mov eax, [g_param]
    add al, 0x40
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 1
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination (operand 0)
    mov edi, 1                   ; r/m = source (operand 1)
    mov edx, r13d
    call asmf_enc
    ret

; ===========================================================================
; xadd / cmpxchg / popcnt / bsf / bsr / bswap / bt
; ===========================================================================
asmf_h_xadd:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_reg
    mov esi, eax
    mov byte [g_desc_opcode], 0xC1
    cmp r13d, SZ_B
    jne .xaddOk
    mov byte [g_desc_opcode], 0xC0
.xaddOk:
    mov dword [g_desc_0f], 1
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret

asmf_h_cmpxchg:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_reg
    mov esi, eax
    mov byte [g_desc_opcode], 0xB1
    cmp r13d, SZ_B
    jne .cmpxOk
    mov byte [g_desc_opcode], 0xB0
.cmpxOk:
    mov dword [g_desc_0f], 1
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret

asmf_h_popcnt:
    mov al, 0xF3
    call asmf_emit_b
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination (operand 0)
    mov byte [g_desc_opcode], 0xB8
    mov dword [g_desc_0f], 1
    mov edi, 1                   ; r/m = source
    mov edx, r13d
    call asmf_enc
    ret

; tzcnt/lzcnt are bsf/bsr with a mandatory F3, and the prefix has to leave
; before asmf_enc writes the REX byte
asmf_h_tzcnt:
    mov al, 0xF3
    call asmf_emit_b
    jmp asmf_h_bsfbsr

asmf_h_bsfbsr:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov esi, eax                 ; reg field = destination (operand 0)
    mov eax, [g_param]
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 1
    mov edi, 1                   ; r/m = source
    mov edx, r13d
    call asmf_enc
    ret

; loop / jrcxz: the only encoding is rel8, so an out of range target is an
; error rather than something a wider form can absorb
asmf_h_loop:
    mov edi, 0
    call asmf_rel8_ok
    jnc .far
    mov [g_immval], rax
    movzx eax, word [g_param]
    call asmf_emit_b
    mov rax, [g_immval]
    mov edi, 1
    call asmf_emit_n
    ret
.far:
    mov rdi, E_TOOBIG
    call asmf_err_code
    ret

asmf_h_bswap:
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 0
    call asmf_op_reg
    mov [g_enc_reg], eax
    xor esi, esi                 ; no register field in the opcode
    xor edi, edi                 ; operand 0 still supplies REX.B
    mov edx, r13d
    call asmf_rex_bits
    test eax, eax
    jz .bswapNoRex
    or al, 0x40
    call asmf_emit_b
.bswapNoRex:
    mov al, 0x0F
    call asmf_emit_b
    mov eax, [g_enc_reg]
    and al, 7
    add al, 0xC8
    call asmf_emit_b
    ret

; g_param: low byte = the register-form opcode, high byte = the immediate
; form's /digit.
asmf_h_bt:
    mov edi, 0
    call asmf_op_size
    cmp eax, SZ_B
    jne .szOk
    mov rdi, E_OPERAND         ; bt/bts/btr/btc are 16/32/64 only
    call asmf_err_code
    ret
.szOk:
    mov edi, 1
    call asmf_op_is_imm
    jc .imm
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov edi, 1
    call asmf_op_reg
    mov esi, eax
    mov eax, [g_param]
    mov [g_desc_opcode], al
    mov dword [g_desc_0f], 1
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret
.imm:
    ; 0F BA /digit ib -- the operand sizes the REX.W and the modrm, and the
    ; immediate is operand 1, not operand 0 (which is the r/m side)
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0xBA
    mov dword [g_desc_0f], 1
    mov eax, [g_param]
    shr eax, 8
    mov esi, eax
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    mov rdi, 1
    mov esi, 1
    call asmf_emit_immval
    ret

; ===========================================================================
; nop
; ===========================================================================
asmf_h_nop:
    cmp dword [g_nops], 0
    je .plain
    mov edi, 0
    call asmf_op_size
    mov r13d, eax
    mov byte [g_desc_opcode], 0x1F
    mov dword [g_desc_0f], 1
    mov esi, 0
    xor edi, edi
    mov edx, r13d
    call asmf_enc
    ret
.plain:
    mov al, 0x90
    call asmf_emit_b
    ret

; ===========================================================================
; operand-less, int, data
; ===========================================================================
asmf_h_misc:
    call asmf_misc
    ret

asmf_h_int:
    mov al, 0xCD
    call asmf_emit_b
    xor edi, edi
    mov esi, 1
    call asmf_emit_immval
    ret

asmf_h_data:
    call asmf_data
    ret
