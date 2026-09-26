# Win64-ABI trampolines for the TLS blob's io-slot pointers (tlsrt_io_send /
# tlsrt_io_recv / tlsrt_io_close). The blob calls these with the Win64
# register convention (rcx=sock, rdx=buf, r8=len, r9=flags) and 32 bytes of
# shadow space (caller-cleanup). We translate to Linux SysV and call the real
# libc send/recv/close.

.text
.globl win_send
win_send:                       # rcx=sock rdx=buf r8=len r9=flags ; SysV rsp%16==8
    movq %r9,  %rax             # flags
    movq %r8,  %r10             # len
    movq %rdx, %r11             # buf
    movq %rcx, %rdi             # sock  -> rdi
    movq %r11, %rsi             # buf   -> rsi
    movq %r10, %rdx             # len   -> rdx
    movq %rax, %rcx             # flags -> rcx
    subq $8, %rsp               # align for the call (SysV needs rsp%16==0 at call)
    call send
    addq $8, %rsp
    ret

.globl win_recv
win_recv:                       # rcx=sock rdx=buf r8=len r9=flags
    movq %r9,  %rax             # flags
    movq %r8,  %r10             # len
    movq %rdx, %r11             # buf
    movq %rcx, %rdi             # sock  -> rdi
    movq %r11, %rsi             # buf   -> rsi
    movq %r10, %rdx             # len   -> rdx
    movq %rax, %rcx             # flags -> rcx
    subq $8, %rsp
    call recv
    addq $8, %rsp
    ret

.globl win_close
win_close:                      # rcx=sock
    movq %rcx, %rdi             # sock -> rdi
    subq $8, %rsp
    call close
    addq $8, %rsp
    ret