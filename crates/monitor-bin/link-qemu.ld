/* Linker script for QEMU `virt` machine, riscv32.
 * RAM is modeled by QEMU starting at 0x8000_0000; `-bios <elf>` loads the
 * ELF and jumps to its entry point in M-mode. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwx): ORIGIN = 0x80000000, LENGTH = 8M
}

SECTIONS {
  . = 0x80000000;
  .text : {
    *(.text._start)
    *(.text*)
  } >RAM

  .rodata : { *(.rodata*) } >RAM
  .data : { *(.data*) } >RAM
  .bss : { *(.bss*) } >RAM

  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
