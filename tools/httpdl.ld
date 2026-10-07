/* Zenith HTTP-download blob linker script.
   Same layout policy as tlsrt.ld: all allocatable sections contiguously from
   VMA 0 so `objcopy -O binary` yields a flat image where offset == VMA and
   every internal reference is RIP-relative / rel32 (valid at any base). The
   image links the freestanding download engine (httpdl.o/.s) together with the
   TLS core (tlsrt.o/.s) so httpdl can drive TLS 1.2 through tlsrt_entry. */
ENTRY(httpdl_entry)
SECTIONS
{
  . = 0;
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  .bss : {
    . = ALIGN(8);
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    __bss_end = .;
  }
  /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) *(.interp) *(.dyn*) }
}