; ===========================================================================
; asmrt.asm -- freestanding position-independent x86-64 two-pass assembler.
;
; NASM source. Built standalone into its own ELF image by
; tools/gen_asm_blob.sh; the flat machine code (plus its .bss arena) is then
; embedded into every Zenith PE/ELF that calls assemble() and entered through
; `call rel32`. Every internal reference is RIP-relative / rel32, so the blob
; is valid at any base address.
;
; ABI (SysV-internal, the same staging style the disasm/js/tls blobs use):
;   long long asm_entry(op=rdi, a1=rsi, a2=rdx, a3=rcx, a4=r8, a5=r9)
;     op 1  a1=dst a2=cap a3=src a4=srcLen a5=origin
;            assembles src into dst (never writing past cap) and returns the
;            exact number of bytes the output needs. The caller compares the
;            return value against cap to learn whether it fit.
;     op 2  a1=errbuf a2=cap
;            copies the last error message (NUL terminated) into errbuf and
;            returns its length (0 = the last assemble succeeded).
;     op 3  same arguments as op 1 but nothing is written; returns the size
;            the output would need (op 1 with cap = 0).
;
; Writes are confined to [dst, dst+cap) and to the blob's own .bss. Every
; callee-saved register is preserved and the red zone is never touched.
; ===========================================================================

BITS 64
default rel

; ---------------------------------------------------------------------------
; Geometry
; ---------------------------------------------------------------------------
%define SYMSZ      32
%define MAXSYM     256
%define NAMEPOOL   4096
%define SCOPESZ    200
%define NAMETMP    260
%define OPSZ       64              ; power of two: addressed as index<<6
%define MAXOPS     8
%define MNEMSZ     16
%define MNEMN      256
; Nesting limit for `( ( ( ... ) ) )` in an expression. asmf_parse_expr and
; asmf_expr_term call each other, so the depth is bounded only by the C
; stack of whoever enters the blob -- at roughly 40 bytes per level an
; unbounded run takes tens of megabytes and dies on the stack guard page
; with a SEGV instead of reporting an error. Real sources nest single
; digits; 4096 leaves two orders of magnitude of headroom.
%define MAXDEPTH   4096

; ---------------------------------------------------------------------------
; Position-independent table addressing.
;
; A RIP-relative displacement cannot carry an index register, and x86 only
; scales an index by 1/2/4/8. So every "base + index*stride" access is split
; into a RIP-relative lea of the base followed by plain register arithmetic.
; All strides below are powers of two, so REC uses a shift.
;
; Every one of these macros loads the base into the destination register
; before it touches the index, so a call that names the same register twice
; silently produces a wild pointer: `RECB rcx, rcx, g_names` expands to
; `lea rcx,[rel g_names] / add rcx,rcx`, which drops the offset and doubles
; the base. The %ifidni guards below turn that into an assembly error.
; ---------------------------------------------------------------------------
; REC dest, index, shift, label, scratch [, extra offset]
; The shift applies to the index only: scaling the base+index sum instead is a
; silent wild-pointer bug, and the caller must name a scratch because the
; index is still live in most places.
%macro REC 5-6
%ifidni %1, %2
    %error "REC: destination register must differ from the index"
%endif
%ifidni %1, %5
    %error "REC: destination register must differ from the scratch"
%endif
%ifidni %5, %2
    %error "REC: scratch register must differ from the index"
%endif
%if %0 >= 6
    lea %1, [rel %4 + %6]
%else
    lea %1, [rel %4]
%endif
    mov %5, %2
    shl %5, %3
    add %1, %5
%endmacro

; RECB dest, byte offset, label [, extra offset] -- offset is already scaled
%macro RECB 3-4
%ifidni %1, %2
    %error "RECB: destination register must differ from the offset"
%endif
%if %0 >= 4
    lea %1, [rel %3 + %4]
%else
    lea %1, [rel %3]
%endif
    add %1, %2
%endmacro

; Table-slot addressing. RIP-relative displacements cannot carry an index, and
; x86 only offers scales of 1/2/4/8, while the record strides are 64/32/16/16
; bytes -- so the index has to be scaled in a scratch register first. Each
; macro therefore takes an explicit scratch the caller knows is dead.
;
;   <T>SLOT dest, index, scratch   ->  table + index*stride

%macro SLOTGUARD 3-4
%ifidni %1, %2
    %error "%1: destination register must differ from the index"
%endif
%ifidni %1, %3
    %error "%1: destination register must differ from the scratch"
%endif
%ifidni %3, %2
    %error "%1: scratch register must differ from the index"
%endif
%endmacro

%macro OPSLOT 3
    SLOTGUARD %1, %2, %3
    lea %1, [rel g_ops]
    mov %3, %2
    shl %3, 6
    add %1, %3
%endmacro

%macro SYMSLOT 3
    SLOTGUARD %1, %2, %3
    lea %1, [rel g_labels_tab]
    mov %3, %2
    shl %3, 5
    add %1, %3
%endmacro

%macro MNEMSLOT 3
    SLOTGUARD %1, %2, %3
    lea %1, [rel mnem_tbl]
    mov %3, %2
    shl %3, 4
    add %1, %3
%endmacro

%macro ERRSLOT 3
    SLOTGUARD %1, %2, %3
    lea %1, [rel err_tbl]
    mov %3, %2
    shl %3, 4
    add %1, %3
%endmacro

; Operand record layout (48 bytes; offsets in bytes)
%define OP_KIND     0          ; K_*
%define OP_SIZE     4          ; SZ_*
%define OP_REG      8          ; register number, 0..15
%define OP_BASE    12          ; memory base register, or -1
%define OP_INDEX   16          ; memory index register, or -1
%define OP_SCALE   20          ; 1 / 2 / 4 / 8
%define OP_FLAGS   24          ; F_*
%define OP_SYM     28          ; symbol index, 0 = none
%define OP_VALUE   36          ; numeric part
%define OP_STRPTR  44          ; quoted literal: first byte
%define OP_STREND  52          ; quoted literal: one past the last

; Symbol record layout (32 bytes)
%define SY_OFF      0
%define SY_NAMELEN  8
%define SY_STAMP   12
%define SY_NAMEOFF 16
%define SY_ABS     20
%define SY_PAD     24

; Operand kinds
%define K_NONE 0
%define K_REG  1
%define K_IMM  2
%define K_MEM  3
%define K_STR  4

; Size codes
%define SZ_NONE 0
%define SZ_B    1
%define SZ_W    2
%define SZ_D    3
%define SZ_Q    4
%define SZ_T    5
%define SZ_X    6
%define SZ_Y    7
%define SZ_Z    8

; Operand flags
%define F_REX8 1              ; 8-bit register needs a REX byte (spl/bpl/sil/dil)
%define F_REL  2              ; RIP-relative memory displacement
%define F_STR  4              ; the literal was a quoted string
%define F_RELOC 8              ; value is position dependent (`$` or a label)
%define F_HI8   16             ; legacy high byte register (ah/ch/dh/bh)
%define F_ABS   32             ; explicit `[abs ...]`: never RIP-relative

; Quoted-string decode arena
%define STRBUF  2048

; Error codes
%define E_ARGS    1
%define E_MNEM    2
%define E_OPERAND 3
%define E_REG     4
%define E_UNDEF   5
%define E_REDEF   6
%define E_NUMBER  7
%define E_MEMORY  8
%define E_MANYLBL 10
%define E_FORM    11
%define E_SIZE    12
%define E_TOOBIG  13

; Handler ids
%define H_MOV      1
%define H_MOVZX    2
%define H_MOVSX    3
%define H_MOVSXD   4
%define H_LEA      5
%define H_XCHG     6
%define H_PUSH     7
%define H_POP      8
%define H_ALU      9
%define H_TEST    10
%define H_UNARY   11
%define H_IMUL    12
%define H_INCDEC  13
%define H_SHIFT   14
%define H_JMP     15
%define H_CALL    16
%define H_RET     17
%define H_LEAVE   18
%define H_JCC     19
%define H_SETCC   20
%define H_CMOVCC  21
%define H_XADD    22
%define H_CMPXCHG 23
%define H_BSFBSR  24
%define H_BSWAP   25
%define H_BT      26
%define H_NOP     27
%define H_MISC    28
%define H_INT     29
%define H_DATA    30
%define H_POPCNT  31
%define H_TZCNT   32
%define H_LOOP    33

; ALU group indices
%define G_ADD 0
%define G_OR  1
%define G_ADC 2
%define G_SBB 3
%define G_AND 4
%define G_SUB 5
%define G_XOR 6
%define G_CMP 7

; ---------------------------------------------------------------------------
; State (all in .bss; the codegen zero-fills the blob up to __bss_end)
; ---------------------------------------------------------------------------
section .bss align=32
g_src:        resq 1
g_srclen:     resq 1
g_dst:        resq 1
g_cap:        resq 1
g_org:        resq 1
g_out:        resq 1
g_pos:        resq 1
g_pass:       resd 1
g_line:       resd 1
g_err:        resd 1
g_errname:    resq 1
g_errnamelen: resd 1
g_cur:        resq 1
g_end:        resq 1
g_labels:     resd 1
g_namelen:    resd 1
g_firstlab:   resd 1
g_nops:       resd 1
g_param:      resd 1
g_sizehint:   resd 1
g_strptr:     resq 1
g_strend:     resq 1
g_size1:      resq 1

; error message scratch
g_fmtcur:     resq 1
g_fmtend:     resq 1

; encoder scratch
g_desc_opcode:  resd 1
g_desc_0f:      resd 1
g_desc_forcerex: resd 1
g_enc_rm:       resd 1
g_enc_reg:      resd 1
g_enc_form:     resd 1
g_immval:       resq 1
g_rel_target:   resq 1
g_movx_op:      resd 1
g_alu_grp:      resd 1
g_alu_base:     resd 1
g_id_digit:     resd 1
g_sh_digit:     resd 1
g_imul_rm:      resd 1              ; r/m operand index of the current imul form
g_imul_immop:   resd 1              ; immediate operand index of that form

; RIP fixup: the disp32 of a [rel ...] operand is not necessarily the last
; field of the instruction (an immediate may follow it), so the distance is
; recomputed from g_pos once the whole instruction has gone out.
g_rip_patch:  resq 1              ; byte offset of the disp32, -1 = none
g_rip_target: resq 1              ; absolute address the field points at
g_hi8_any:    resd 1              ; ah/ch/dh/bh seen in this instruction

; memory encoding scratch
g_ri_base:    resd 1
g_ri_index:   resd 1
g_ri_32:      resd 1                ; a 32-bit address register was seen in the brackets
g_rm_base:    resd 1
g_rm_low:     resd 1
g_rm_reg:     resd 1
g_rm_force:   resd 1
g_need_sib:   resd 1
g_disp_kind:  resd 1
g_iter:       resd 1
g_prevhash:   resq 1

; lexer / parser scratch
g_htmp:       resd 1
g_strlen:     resd 1
g_reloc:      resd 1
g_tokend:     resq 1
g_times_left: resq 1
g_times_from: resq 1
g_op_size:    resd 1
g_oprec:      resd 1
g_expr_sym:   resd 1
g_expr_first: resd 1
g_expr_net:   resd 1
g_expr_sign:  resd 1
g_depth:      resd 1              ; expression-paren nesting, see MAXDEPTH
g_defrel:     resd 1              ; `default rel`: bare [symbol] is RIP-relative
g_paren_first:resd 1
g_paren_net:  resd 1
g_paren_val:  resq 1
g_reg_num:    resd 1
g_reg_size:   resd 1
g_reg_flags:  resd 1
g_mnembuf:    resb 8
g_mnem_idx:   resd 1
g_mnemonic_id: resd 1
g_minops:     resd 1
g_maxops:     resd 1

; string literal arena
g_strbuf:     resb STRBUF
g_strfill:    resd 1

g_ops:        resb OPSZ*MAXOPS
g_labels_tab: resb SYMSZ*MAXSYM
g_names:      resb NAMEPOOL
g_scopelen:   resd 1
g_scopebuf:   resb SCOPESZ
g_nametmp:    resb NAMETMP

; ---------------------------------------------------------------------------
; Read-only tables
; ---------------------------------------------------------------------------
section .rodata align=32

; One name in an 8-byte NUL-padded slot.
; asmf_reg_match addresses every register table as base + index*8, so a slot
; has to be exactly 8 bytes. Padding these by hand gave `'r10'` ten bytes
; instead of eight and slid every later slot, which is how r11..r15 stopped
; matching and came out as plain immediates.
%macro N8 1
    %strlen _n8len %1
    db %1
    times 8 - _n8len db 0
%endmacro

; 64-bit register names, hardware numbering
regname:
    N8 'rax'
    N8 'rcx'
    N8 'rdx'
    N8 'rbx'
    N8 'rsp'
    N8 'rbp'
    N8 'rsi'
    N8 'rdi'
    N8 'r8'
    N8 'r9'
    N8 'r10'
    N8 'r11'
    N8 'r12'
    N8 'r13'
    N8 'r14'
    N8 'r15'
; 32-bit register names
; All four tables are exactly 16 slots: asmf_reg_match always walks 0..15, and
; a short table runs straight into the next one, so `ax` used to match at
; regname32[8] and come back as a 32-bit register.
regname32:
    N8 'eax'
    N8 'ecx'
    N8 'edx'
    N8 'ebx'
    N8 'esp'
    N8 'ebp'
    N8 'esi'
    N8 'edi'
    N8 'r8d'
    N8 'r9d'
    N8 'r10d'
    N8 'r11d'
    N8 'r12d'
    N8 'r13d'
    N8 'r14d'
    N8 'r15d'
; 16-bit register names
regname16:
    N8 'ax'
    N8 'cx'
    N8 'dx'
    N8 'bx'
    N8 'sp'
    N8 'bp'
    N8 'si'
    N8 'di'
    N8 'r8w'
    N8 'r9w'
    N8 'r10w'
    N8 'r11w'
    N8 'r12w'
    N8 'r13w'
    N8 'r14w'
    N8 'r15w'
; 8-bit register names: 0-3 legacy low, 4-7 spl/bpl/sil/dil, 8-15 r8b..r15b
regname8:
    N8 'al'
    N8 'cl'
    N8 'dl'
    N8 'bl'
    N8 'spl'
    N8 'bpl'
    N8 'sil'
    N8 'dil'
    N8 'r8b'
    N8 'r9b'
    N8 'r10b'
    N8 'r11b'
    N8 'r12b'
    N8 'r13b'
    N8 'r14b'
    N8 'r15b'

; legacy high byte registers. They occupy hardware numbers 4..7 exactly like
; spl/bpl/sil/dil, but a REX prefix must never touch them, so they live in
; their own table and carry F_HI8 instead of F_REX8.
regname8h:
    N8 'ah'
    N8 'ch'
    N8 'dh'
    N8 'bh'
    times 12 db 0

; operand size keywords, exactly 8 bytes each
sz_names:
    N8 'byte'
    N8 'word'
    N8 'dword'
    N8 'qword'
    N8 'tbyte'
    N8 'xmmword'
    N8 'ymmword'
    N8 'zmmword'

; ignored directives
dir_bits:    db 'bits'
dir_section: db 'section'
dir_global:  db 'global'
dir_extern:  db 'extern'
dir_default: db 'default'
dir_cpu:     db 'cpu'
dir_org:     db 'org'
dir_times:   db 'times'

; ---------------------------------------------------------------------------
; Operand-less instructions: len, bytes..., zero padding to 8 bytes.
; The mnemonic table stores the byte offset into this table in `param`.
; ---------------------------------------------------------------------------
%macro MISC 1-4
    db %0
    db %1
%if %0 >= 2
    db %2
%endif
%if %0 >= 3
    db %3
%endif
%if %0 >= 4
    db %4
%endif
    times 7-%0 db 0
%endmacro
%define M(x) ((x)*8)

misc_tbl:
    MISC 0xF4                 ;  0 hlt
    MISC 0x0F,0x0B            ;  1 ud2
    MISC 0x0F,0x05            ;  2 syscall
    MISC 0x0F,0xA2            ;  3 cpuid
    MISC 0xF3,0x90             ;  4 pause
    MISC 0xFA                 ;  5 cli
    MISC 0xFB                 ;  6 sti
    MISC 0xF8                 ;  7 clc
    MISC 0xF9                 ;  8 stc
    MISC 0xF5                 ;  9 cmc
    MISC 0xFC                 ; 10 cld
    MISC 0xFD                 ; 11 std
    MISC 0x9F                 ; 12 lahf
    MISC 0x9E                 ; 13 sahf
    MISC 0x66,0x98            ; 14 cbw
    MISC 0x98                 ; 15 cwde
    MISC 0x48,0x98            ; 16 cdqe
    MISC 0x66,0x99            ; 17 cwd
    MISC 0x99                 ; 18 cdq
    MISC 0x48,0x99            ; 19 cqo
    MISC 0x0F,0x06            ; 20 clts
    MISC 0x0F,0x09            ; 21 wbinvd
    MISC 0x0F,0x08            ; 22 invd
    MISC 0x0F,0x31            ; 23 rdtsc
    MISC 0xA4                 ; 24 movsb
    MISC 0x66,0xA5            ; 25 movsw
    MISC 0xA5                 ; 26 movsd (string form)
    MISC 0x48,0xA5            ; 27 movsq
    MISC 0xAA                 ; 28 stosb
    MISC 0x66,0xAB            ; 29 stosw
    MISC 0xAB                 ; 30 stosd
    MISC 0x48,0xAB            ; 31 stosq
    MISC 0xAC                 ; 32 lodsb
    MISC 0x66,0xAD            ; 33 lodsw
    MISC 0xAD                 ; 34 lodsd
    MISC 0x48,0xAD            ; 35 lodsq
    MISC 0xAE                 ; 36 scasb
    MISC 0x66,0xAF            ; 37 scasw
    MISC 0xAF                 ; 38 scasd
    MISC 0x48,0xAF            ; 39 scasq
    MISC 0xA6                 ; 40 cmpsb
    MISC 0x66,0xA7            ; 41 cmpsw
    MISC 0xA7                 ; 42 cmpsd
    MISC 0x48,0xA7            ; 43 cmpsq
    MISC 0xD7                 ; 44 xlat
    MISC 0xCC                 ; 45 int3
    MISC 0x0F,0xAE,0xE8       ; 46 lfence
    MISC 0x0F,0xAE,0xF0       ; 47 mfence
    MISC 0x0F,0xAE,0xF8       ; 48 sfence
    MISC 0x0F,0xA8,0x00       ; 49 pushfq
    MISC 0x0F,0xA9,0x00       ; 50 popfq
misc_tbl_end:

; ---------------------------------------------------------------------------
; Mnemonic table: name[8], handler, param, minops, maxops (16 bytes / entry)
; ---------------------------------------------------------------------------
%macro MNEM 2-5
    db %1
    times 8-%strlen(%1) db 0
    dw %2
%if %0 >= 3
    dw %3
%else
    dw 0
%endif
%if %0 >= 4
    dw %4
%else
    dw 2
%endif
%if %0 >= 5
    dw %5
%else
    dw 2
%endif
%endmacro

; All condition codes for jcc / setcc / cmovcc, with their aliases.
;
; The name is built from two separately-quoted pieces rather than by pasting
; parameters together: NASM's parameter substitution does not happen inside a
; string literal, and a bare '%1nae' is re-split into two macro arguments.
; The condition code has to travel with the entry: leaving the param field
; zero meant every jcc / setcc / cmovcc assembled as condition 0 (`setz`
; came out as `seto`). The codes are the hardware encoding, with aliases
; sharing their primary's value.  The operand counts come from CC_MIN /
; CC_MAX, which the caller assigns before expanding CCGRP -- a single
; `dw 1, dw 1` here made `cmovz eax, ebx` fail as an unsupported form.
%macro CCN 4                 ; prefix, suffix, handler, condition code
    db %1
    db %2
    times 8-(%strlen(%1)+%strlen(%2)) db 0
    dw %3
    dw %4
    dw CC_MIN
    dw CC_MAX
%endmacro

%macro CCGRP 2
    CCN %1, 'o',   %2, 0
    CCN %1, 'no',  %2, 1
    CCN %1, 'b',   %2, 2
    CCN %1, 'c',   %2, 2
    CCN %1, 'nae', %2, 2
    CCN %1, 'ae',  %2, 3
    CCN %1, 'nb',  %2, 3
    CCN %1, 'nc',  %2, 3
    CCN %1, 'e',   %2, 4
    CCN %1, 'z',   %2, 4
    CCN %1, 'ne',  %2, 5
    CCN %1, 'nz',  %2, 5
    CCN %1, 'be',  %2, 6
    CCN %1, 'na',  %2, 6
    CCN %1, 'a',   %2, 7
    CCN %1, 'nbe', %2, 7
    CCN %1, 's',   %2, 8
    CCN %1, 'ns',  %2, 9
    CCN %1, 'p',   %2, 10
    CCN %1, 'pe',  %2, 10
    CCN %1, 'np',  %2, 11
    CCN %1, 'po',  %2, 11
    CCN %1, 'l',   %2, 12
    CCN %1, 'nge', %2, 12
    CCN %1, 'ge',  %2, 13
    CCN %1, 'nl',  %2, 13
    CCN %1, 'le',  %2, 14
    CCN %1, 'ng',  %2, 14
    CCN %1, 'g',   %2, 15
    CCN %1, 'nle', %2, 15
%endmacro

mnem_tbl:
    MNEM 'mov',      H_MOV,     0,      2, 3
    MNEM 'movzx',    H_MOVZX,   0,      2, 2
    MNEM 'movsx',    H_MOVSX,   0,      2, 2
    MNEM 'movsxd',   H_MOVSXD,  0,      2, 2
    MNEM 'lea',      H_LEA,     0,      2, 2
    MNEM 'xchg',     H_XCHG,    0,      2, 2
    MNEM 'push',     H_PUSH,    0,      1, 1
    MNEM 'pop',      H_POP,     0,      1, 1
    MNEM 'add',      H_ALU,     G_ADD,  2, 2
    MNEM 'or',       H_ALU,     G_OR,   2, 2
    MNEM 'adc',      H_ALU,     G_ADC,  2, 2
    MNEM 'sbb',      H_ALU,     G_SBB,  2, 2
    MNEM 'and',      H_ALU,     G_AND,  2, 2
    MNEM 'sub',      H_ALU,     G_SUB,  2, 2
    MNEM 'xor',      H_ALU,     G_XOR,  2, 2
    MNEM 'cmp',      H_ALU,     G_CMP,  2, 2
    MNEM 'test',     H_TEST,    0,      2, 2
    MNEM 'not',      H_UNARY,   2,      1, 1
    MNEM 'neg',      H_UNARY,   3,      1, 1
    MNEM 'mul',      H_UNARY,   4,      1, 1
    MNEM 'div',      H_UNARY,   6,      1, 1
    MNEM 'idiv',     H_UNARY,   7,      1, 1
    MNEM 'imul',     H_IMUL,    0,      1, 3
    MNEM 'inc',      H_INCDEC,  0,      1, 1
    MNEM 'dec',      H_INCDEC,  1,      1, 1
    MNEM 'shl',      H_SHIFT,   4,      2, 2
    MNEM 'sal',      H_SHIFT,   4,      2, 2
    MNEM 'shr',      H_SHIFT,   5,      2, 2
    MNEM 'sar',      H_SHIFT,   7,      2, 2
    MNEM 'rol',      H_SHIFT,   0,      2, 2
    MNEM 'ror',      H_SHIFT,   1,      2, 2
    MNEM 'rcl',      H_SHIFT,   2,      2, 2
    MNEM 'rcr',      H_SHIFT,   3,      2, 2
    MNEM 'jmp',      H_JMP,     0,      1, 1
    MNEM 'call',     H_CALL,    0,      1, 1
    MNEM 'ret',      H_RET,     0,      0, 1
    MNEM 'leave',    H_LEAVE,   0,      0, 0
    MNEM 'nop',      H_NOP,     0,      0, 1
    MNEM 'int',      H_INT,     0,      1, 1
    %assign CC_MIN 1
    %assign CC_MAX 1
    CCGRP 'j',  H_JCC
    %assign CC_MIN 1
    %assign CC_MAX 1
    CCGRP 'set',  H_SETCC
    %assign CC_MIN 2
    %assign CC_MAX 2
    CCGRP 'cmov', H_CMOVCC
    MNEM 'xadd',     H_XADD,    0,      2, 2
    MNEM 'cmpxchg',  H_CMPXCHG, 0,      2, 2
    MNEM 'popcnt',   H_POPCNT,  0,      2, 2
    MNEM 'tzcnt',    H_TZCNT,   0xBC,   2, 2
    MNEM 'lzcnt',    H_TZCNT,   0xBD,   2, 2
    MNEM 'loop',     H_LOOP,    0xE2,   1, 1
    MNEM 'loope',    H_LOOP,    0xE1,   1, 1
    MNEM 'loopz',    H_LOOP,    0xE1,   1, 1
    MNEM 'loopne',   H_LOOP,    0xE0,   1, 1
    MNEM 'loopnz',   H_LOOP,    0xE0,   1, 1
    MNEM 'jrcxz',    H_LOOP,    0xE3,   1, 1
    MNEM 'bsf',      H_BSFBSR,  0xBC,   2, 2
    MNEM 'bsr',      H_BSFBSR,  0xBD,   2, 2
    MNEM 'bswap',    H_BSWAP,   0,      1, 1
    MNEM 'bt',       H_BT,      0x04A3, 2, 2
    MNEM 'bts',      H_BT,      0x05AB, 2, 2
    MNEM 'btr',      H_BT,      0x06B3, 2, 2
    MNEM 'btc',      H_BT,      0x07BB, 2, 2
    MNEM 'hlt',      H_MISC,    M(0),   0, 0
    MNEM 'ud2',      H_MISC,    M(1),   0, 0
    MNEM 'syscall',  H_MISC,    M(2),   0, 0
    MNEM 'cpuid',    H_MISC,    M(3),   0, 0
    MNEM 'pause',    H_MISC,    M(4),   0, 0
    MNEM 'cli',      H_MISC,    M(5),   0, 0
    MNEM 'sti',      H_MISC,    M(6),   0, 0
    MNEM 'clc',      H_MISC,    M(7),   0, 0
    MNEM 'stc',      H_MISC,    M(8),   0, 0
    MNEM 'cmc',      H_MISC,    M(9),   0, 0
    MNEM 'cld',      H_MISC,    M(10),  0, 0
    MNEM 'std',      H_MISC,    M(11),  0, 0
    MNEM 'lahf',     H_MISC,    M(12),  0, 0
    MNEM 'sahf',     H_MISC,    M(13),  0, 0
    MNEM 'cbw',      H_MISC,    M(14),  0, 0
    MNEM 'cwde',     H_MISC,    M(15),  0, 0
    MNEM 'cdqe',     H_MISC,    M(16),  0, 0
    MNEM 'cwd',      H_MISC,    M(17),  0, 0
    MNEM 'cdq',      H_MISC,    M(18),  0, 0
    MNEM 'cqo',      H_MISC,    M(19),  0, 0
    MNEM 'clts',     H_MISC,    M(20),  0, 0
    MNEM 'wbinvd',   H_MISC,    M(21),  0, 0
    MNEM 'invd',     H_MISC,    M(22),  0, 0
    MNEM 'rdtsc',    H_MISC,    M(23),  0, 0
    MNEM 'movsb',    H_MISC,    M(24),  0, 0
    MNEM 'movsw',    H_MISC,    M(25),  0, 0
    MNEM 'movsd',    H_MISC,    M(26),  0, 0
    MNEM 'movsq',    H_MISC,    M(27),  0, 0
    MNEM 'stosb',    H_MISC,    M(28),  0, 0
    MNEM 'stosw',    H_MISC,    M(29),  0, 0
    MNEM 'stosd',    H_MISC,    M(30),  0, 0
    MNEM 'stosq',    H_MISC,    M(31),  0, 0
    MNEM 'lodsb',    H_MISC,    M(32),  0, 0
    MNEM 'lodsw',    H_MISC,    M(33),  0, 0
    MNEM 'lodsd',    H_MISC,    M(34),  0, 0
    MNEM 'lodsq',    H_MISC,    M(35),  0, 0
    MNEM 'scasb',    H_MISC,    M(36),  0, 0
    MNEM 'scasw',    H_MISC,    M(37),  0, 0
    MNEM 'scasd',    H_MISC,    M(38),  0, 0
    MNEM 'scasq',    H_MISC,    M(39),  0, 0
    MNEM 'cmpsb',    H_MISC,    M(40),  0, 0
    MNEM 'cmpsw',    H_MISC,    M(41),  0, 0
    MNEM 'cmpsd',    H_MISC,    M(42),  0, 0
    MNEM 'cmpsq',    H_MISC,    M(43),  0, 0
    MNEM 'xlat',     H_MISC,    M(44),  0, 0
    MNEM 'int3',     H_MISC,    M(45),  0, 0
    MNEM 'lfence',   H_MISC,    M(46),  0, 0
    MNEM 'mfence',   H_MISC,    M(47),  0, 0
    MNEM 'sfence',   H_MISC,    M(48),  0, 0
    MNEM 'pushfq',   H_MISC,    M(49),  0, 0
    MNEM 'popfq',    H_MISC,    M(50),  0, 0
    MNEM 'db',       H_DATA,    1,      1, MAXOPS
    MNEM 'dw',       H_DATA,    2,      1, MAXOPS
    MNEM 'dd',       H_DATA,    4,      1, MAXOPS
    MNEM 'dq',       H_DATA,    8,      1, MAXOPS
mnem_tbl_end:
    %define MNEM_COUNT ((mnem_tbl_end - mnem_tbl) / MNEMSZ)

; ---------------------------------------------------------------------------
; Error text table. 16 bytes per row indexed by the E_* codes above, so every
; row stays a constant size and the lookup needs no arithmetic beyond a shift.
; ---------------------------------------------------------------------------
%macro EROW 2
    dd %1 - err_blob
    dd %2
    dd 0
    dd 0
%endmacro
err_tbl:
    EROW e_ok,    2
    EROW e_args,  %strlen('bad arguments')
    EROW e_mnem,  %strlen('unknown mnemonic')
    EROW e_oper,  %strlen('bad operand')
    EROW e_reg,   %strlen('bad register')
    EROW e_undef, %strlen('undefined symbol')
    EROW e_redef, %strlen('symbol redefined')
    EROW e_num,   %strlen('bad number')
    EROW e_mem,   %strlen('bad memory operand')
    EROW 0,       0                       ; 9 unused
    EROW e_lbl,   %strlen('too many labels')
    EROW e_form,  %strlen('unsupported form')
    EROW e_size,  %strlen('operand size mismatch')
    EROW e_big,   %strlen('source too large')
err_blob:
e_ok:    db 'ok'
e_args:  db 'bad arguments'
e_mnem:  db 'unknown mnemonic'
e_oper:  db 'bad operand'
e_reg:   db 'bad register'
e_undef: db 'undefined symbol'
e_redef: db 'symbol redefined'
e_num:   db 'bad number'
e_mem:   db 'bad memory operand'
e_lbl:   db 'too many labels'
e_form:  db 'unsupported form'
e_size:  db 'operand size mismatch'
e_big:   db 'source too large'

; ---------------------------------------------------------------------------
; Implementation
; ---------------------------------------------------------------------------
section .text align=32
BITS 64
global asm_entry          ; ENTRY(asm_entry) in tools/asmrt.ld
%include "asmrt_core.inc"
%include "asmrt_num.inc"
%include "asmrt_parse.inc"
%include "asmrt_oper.inc"
%include "asmrt_mem.inc"
%include "asmrt_enc.inc"
%include "asmrt_ops.inc"
