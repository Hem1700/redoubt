/* Linker script for the Redoubt Phase-2 measured-boot ROM (BROM).
 *
 * The BROM is the reset vector on the sim SoC: LiteX/VexRiscv "secure" (rv32ima,
 * Verilator) resets to 0x0. This image measures the monitor at MON_CODE and
 * either jumps to it (match) or halts (tamper). It is baked into the BROM RAM
 * slave (sim/redoubt_soc.py) and reached from reset.
 *
 * Canonical map (sim/memory_map.json): BROM 0x0000_0000, 16 KiB. The whole image
 * — .text/.rodata/.data/.bss and the descending stack — must fit that window.
 * (16 KiB, not 8: even a release-optimised BLAKE2s compression function plus its
 * SIGMA/IV .rodata is ~12 KiB; the extra headroom holds the descending stack.)
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  BROM (rwx) : ORIGIN = 0x00000000, LENGTH = 16K
}

SECTIONS {
  . = 0x00000000;
  .text : {
    *(.text._start)
    *(.text*)
  } >BROM

  .rodata : { *(.rodata*) } >BROM
  .data   : { *(.data*) } >BROM
  .bss    : { *(.bss*) *(COMMON) } >BROM

  /* Stack grows DOWN from the top of the BROM window. If the image ever grows
   * into the stack, the MEMORY region overflows and the linker errors. */
  _stack_top = ORIGIN(BROM) + LENGTH(BROM);
}
