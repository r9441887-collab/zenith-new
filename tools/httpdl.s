# Win64-ABI raw syscall wrappers used as the TLS blob's io slots.
#
# The TLS blob performs record I/O through tlsrt_send_stub/recv_stub/close_stub
# (tlsrt.s): each translates the blob's SysV args into Win64 registers
# (rcx=sock, rdx=buf, r8=len, r9=flags) and jumps through a pointer stored in
# blob .bss. httpdl.c seeds those slots with these functions so a raw-syscall
# Linux build has real socket I/O with no libc and no WinSock.
#
# x86-64 syscall ABI: nr in rax, args rdi/rsi/rdx/r10/r8/r9, return in rax.
#   sys_call send    = 44  -> send(fd, buf, len, flags)
#   sys_call recv    = 45  -> recv(fd, buf, len, flags)
#   sys_call close   = 3   -> close(fd)

.text

# long httpdl_io_send(long sock /*rcx*/, const void* buf /*rdx*/,
#                     long len /*r8*/, long flags /*r9*/)
# __NR_sendto is reused as plain send(); r8/r9 (src_addr/addrlen) MUST be
# zeroed, else the Win64 shim's leftover len/flags make the kernel treat the
# len value as a sockaddr pointer.
.globl httpdl_io_send
httpdl_io_send:
    movq %rcx, %rdi          # fd
    movq %rdx, %rsi          # buf
    movq %r8, %rdx           # len
    movq %r9, %r10           # flags
    xorq %r8, %r8            # src_addr = NULL
    xorq %r9, %r9            # addrlen  = 0
    movq $44, %rax           # __NR_sendto (covers plain send)
    syscall
    ret

# long httpdl_io_recv(long sock /*rcx*/, void* buf /*rdx*/,
#                     long len /*r8*/, long flags /*r9*/)
# Same r8/r9 zeroing as sendto: __NR_recvfrom must be called with NULL
# src_addr/addrlen or the leftover Win64 args produce EFAULT.
.globl httpdl_io_recv
httpdl_io_recv:
    movq %rcx, %rdi          # fd
    movq %rdx, %rsi          # buf
    movq %r8, %rdx           # len
    movq %r9, %r10           # flags
    xorq %r8, %r8            # src_addr = NULL
    xorq %r9, %r9            # addrlen  = 0
    movq $45, %rax           # __NR_recvfrom (covers plain recv)
    syscall
    ret

# long httpdl_io_close(long sock /*rcx*/)
.globl httpdl_io_close
httpdl_io_close:
    movq %rcx, %rdi          # fd
    movq $3, %rax            # __NR_close
    syscall
    ret

# void httpdl_io_seed(void)
# Point the TLS blob's io slots (tlsrt_io_send/recv/close, defined in
# tlsrt.c) at the raw-syscall wrappers above. Every reference here is
# RIP-relative so the combined httpdl+tlsrc image stays position-independent:
# absolute addresses (which gcc produced from C `&httpdl_io_send`) would be
# invalid once the blob is embedded at a nonzero VMA inside the final ELF.
.globl httpdl_io_seed
httpdl_io_seed:
    leaq httpdl_io_send(%rip), %rcx
    leaq tlsrt_io_send(%rip), %rdx
    movq %rcx, (%rdx)
    leaq httpdl_io_recv(%rip), %rcx
    leaq tlsrt_io_recv(%rip), %rdx
    movq %rcx, (%rdx)
    leaq httpdl_io_close(%rip), %rcx
    leaq tlsrt_io_close(%rip), %rdx
    movq %rcx, (%rdx)
    ret

.section .note.GNU-stack,"",@progbits

# ---------------------------------------------------------------------------
# Raw syscall wrappers used from httpdl.c (freestanding, no libc).
# SysV ABI: args in rdi/rsi/rdx/rcx/r8/r9, syscall nr in rax.
# Warning: the `syscall` instruction clobbers rcx and r11, so any argument that
# arrives in rcx must be moved to r10 first.
# ---------------------------------------------------------------------------
.text

# i64 httpdl_sys_read(fd /*rdi*/, buf /*rsi*/, len /*rdx*/)
.globl httpdl_sys_read
httpdl_sys_read:
    movq $0, %rax
    syscall
    ret

# i64 httpdl_sys_write(fd /*rdi*/, buf /*rsi*/, len /*rdx*/)
.globl httpdl_sys_write
httpdl_sys_write:
    movq $1, %rax
    syscall
    ret

# i64 httpdl_sys_open(path /*rdi*/, flags /*rsi*/, mode /*rdx*/)
.globl httpdl_sys_open
httpdl_sys_open:
    movq $2, %rax
    syscall
    ret

# i64 httpdl_sys_close(fd /*rdi*/)
.globl httpdl_sys_close
httpdl_sys_close:
    movq $3, %rax
    syscall
    ret

.globl httpdl_sys_pread
httpdl_sys_pread:
    movq %rcx, %r10
    movq $17, %rax
    syscall
    ret

.globl httpdl_sys_rename
httpdl_sys_rename:
    movq $82, %rax
    syscall
    ret

.globl httpdl_sys_unlink
httpdl_sys_unlink:
    movq $87, %rax
    syscall
    ret

.globl httpdl_sys_getpid
httpdl_sys_getpid:
    movq $39, %rax
    syscall
    ret

.globl httpdl_sys_mkdir
httpdl_sys_mkdir:
    movq $83, %rax
    syscall
    ret

# i64 httpdl_sys_nanosleep(req /*rdi*/, rem /*rsi*/)
.globl httpdl_sys_nanosleep
httpdl_sys_nanosleep:
    movq $35, %rax
    syscall
    ret

# i64 httpdl_sys_socket(domain /*rdi*/, type /*rsi*/, proto /*rdx*/)
.globl httpdl_sys_socket
httpdl_sys_socket:
    movq $41, %rax
    syscall
    ret

# i64 httpdl_sys_connect(fd /*rdi*/, addr /*rsi*/, len /*rdx*/)
.globl httpdl_sys_connect
httpdl_sys_connect:
    movq $42, %rax
    syscall
    ret

# i64 httpdl_sys_sendto(fd /*rdi*/, buf /*rsi*/, len /*rdx*/, flags /*rcx*/,
#                       addr /*r8*/, addrlen /*r9*/)
.globl httpdl_sys_sendto
httpdl_sys_sendto:
    movq %rcx, %r10          # flags (syscall clobbers rcx)
    movq $44, %rax
    syscall
    ret

# i64 httpdl_sys_recvfrom(fd /*rdi*/, buf /*rsi*/, len /*rdx*/, flags /*rcx*/,
#                         addr /*r8*/, addrlen /*r9*/)
.globl httpdl_sys_recvfrom
httpdl_sys_recvfrom:
    movq %rcx, %r10          # flags
    movq $45, %rax
    syscall
    ret

# i64 httpdl_sys_setsockopt(fd /*rdi*/, level /*rsi*/, opt /*rdx*/, val /*rcx*/,
#                           vlen /*r8*/)
.globl httpdl_sys_setsockopt
httpdl_sys_setsockopt:
    movq %rcx, %r10          # val
    movq $54, %rax
    syscall
    ret

# i64 httpdl_sys_clock_gettime(clk /*rdi*/, tp /*rsi*/)
.globl httpdl_sys_clock_gettime
httpdl_sys_clock_gettime:
    movq $228, %rax
    syscall
    ret

# i64 httpdl_sys_bind(fd /*rdi*/, addr /*rsi*/, len /*rdx*/)
.globl httpdl_sys_bind
httpdl_sys_bind:
    movq $49, %rax
    syscall
    ret

# i64 httpdl_sys_listen(fd /*rdi*/, backlog /*rsi*/)
.globl httpdl_sys_listen
httpdl_sys_listen:
    movq $50, %rax
    syscall
    ret

# i64 httpdl_sys_accept(fd /*rdi*/, addr /*rsi*/, addrlen /*rdx*/)  (the
# socket may be O_NONBLOCK on some servers; for our blocking loop accept
# blocks until a peer connects, so no edge handling is needed here)
.globl httpdl_sys_accept
httpdl_sys_accept:
    movq $43, %rax
    syscall
    ret

# i64 httpdl_sys_fstat(fd /*rdi*/, stat /*rsi*/)  (http_server: file size)
.globl httpdl_sys_fstat
httpdl_sys_fstat:
    movq $5, %rax
    syscall
    ret

# i64 httpdl_sys_getdents64(fd /*rdi*/, buf /*rsi*/, len /*rdx*/)  (directory listing)
.globl httpdl_sys_getdents64
httpdl_sys_getdents64:
    movq $217, %rax
    syscall
    ret

.section .note.GNU-stack,"",@progbits
