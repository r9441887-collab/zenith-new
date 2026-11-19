# SysV -> Win64 bridge stubs for raw socket I/O.
# The blob (SysV-internal) calls these with SysV args; each stub rebuilds the
# Win64 register args (rcx/rdx/r8/r9 + reserve stack, 16-byte aligned call),
# then jumps through a function pointer stored in blob .bss by TLS_OP_IO_INIT.
#
# SysV args:        rdi = sock, rsi = buf, rdx = len, rcx = flags
# Win64 args:       rcx = sock, rdx = buf, r8  = len, r9  = flags
#
# Stack: SysV entry rsp%16 == 8. Sub 40 -> rsp%16 == 0 at the call, leaving
# 32 bytes of shadow space for the callee (caller-cleanup, add back after).

.text
.globl tlsrt_send_stub
tlsrt_send_stub:
    movq %rcx, %r9          # flags -> r9 (rcx will be clobbered)
    movq %rdx, %r8          # len   -> r8
    movq %rsi, %rdx         # buf   -> rdx
    movq %rdi, %rcx         # sock  -> rcx
    movq tlsrt_io_send(%rip), %rax
    subq $40, %rsp
    callq *%rax
    addq $40, %rsp
    ret

.globl tlsrt_recv_stub
tlsrt_recv_stub:
    movq %rcx, %r9          # flags -> r9
    movq %rdx, %r8          # len   -> r8
    movq %rsi, %rdx         # buf   -> rdx
    movq %rdi, %rcx         # sock  -> rcx
    movq tlsrt_io_recv(%rip), %rax
    subq $40, %rsp
    callq *%rax
    addq $40, %rsp
    ret

# SysV: rdi = sock; Win64: rcx = sock
.globl tlsrt_close_stub
tlsrt_close_stub:
    movq %rdi, %rcx
    movq tlsrt_io_close(%rip), %rax
    subq $40, %rsp
    callq *%rax
    addq $40, %rsp
    ret

.section .note.GNU-stack,"",@progbits
