/* asmrt blob linker script.
   Layouts all allocatable sections contiguously starting at VMA 0 so that
   `objcopy -O binary` produces a flat image where byte offset == runtime VMA.
   All internal references are RIP-relative / rel32, valid at any base. */
ENTRY(asm_entry)
SECTIONS
{
  . = 0;
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  .bss : {
    . = ALIGN(16);
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(16);
    __bss_end = .;
  }
  /DISCARD/ : { *(.note*) *(.comment) *(.eh_frame*) *(.interp) *(.dyn*) }
}
