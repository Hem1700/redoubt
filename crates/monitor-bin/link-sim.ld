/* Linker script for the Redoubt Phase-2 sim SoC (LiteX VexRiscv "secure",
 * rv32ima, in Verilator). Addresses are the canonical Ch 3 §3.5 map — the
 * single source of truth is sim/redoubt_soc.py / sim/memory_map.json:
 *
 *   MON_CODE  0x1000_0000  32 KiB  (R-X)  .text + .rodata + entry
 *   MON_DATA  0x1000_8000  96 KiB  (RW-)  .data + .bss + M-mode stack
 *
 * The CPU reset vector is MON_CODE (0x1000_0000); redoubt_soc.py bakes this
 * image into the MON RAM so Verilator fetches _start from reset. Both regions
 * are backed by one 128 KiB RAM in the sim SoC (see redoubt_soc.py). */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  MON_CODE (rx)  : ORIGIN = 0x10000000, LENGTH = 32K
  MON_DATA (rw)  : ORIGIN = 0x10008000, LENGTH = 96K
}

SECTIONS {
  . = 0x10000000;
  .text : {
    *(.text._start)
    *(.text*)
  } >MON_CODE

  .rodata : { *(.rodata*) } >MON_CODE

  .data : { *(.data*) } >MON_DATA
  .bss  : { *(.bss*) *(COMMON) } >MON_DATA

  /* M-mode stack grows down from the top of MON_DATA. */
  _stack_top = ORIGIN(MON_DATA) + LENGTH(MON_DATA);
}
