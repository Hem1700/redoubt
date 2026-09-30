/* Linker script for the Redoubt Phase-2 sim SoC (LiteX VexRiscv "secure",
 * rv32ima, in Verilator). Canonical Ch 3 §3.5 map (single source of truth:
 * sim/redoubt_soc.py / sim/memory_map.json):
 *
 *   MON_CODE  0x1000_0000  32 KiB  (R-X, M-only)   .text + .rodata + entry
 *   MON_DATA  0x1000_8000  96 KiB  (RW-, M-only)   .data + .bss + M-mode stack
 *
 * Both are one 128 KiB block RAM in the sim SoC (`mon_ram`). The CPU reset
 * vector is MON_CODE (0x1000_0000); redoubt_soc.py bakes this image into that
 * RAM so Verilator fetches _start from reset.
 *
 * Phase-2 V2 note on the single region below: the `secure` core is plain-PMP
 * (no Smepmp), so MON_CODE and MON_DATA are BOTH realised as M-only *by
 * omission* — neither gets a PMP entry, so both are denied to U and reached by
 * M by exemption (see crates/monitor-bin/src/pmp.rs). The MON_CODE/MON_DATA
 * split is therefore invisible to the PMP in V2, and the debug `build-std`
 * image's .text exceeds 32 KiB; so we link against the whole 128 KiB mon_ram
 * as one region. The logical split still stands in memory_map.json for V3/V4. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  MON_RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 128K
}

SECTIONS {
  . = 0x10000000;
  .text : {
    *(.text._start)
    *(.text*)
  } >MON_RAM

  .rodata : { *(.rodata*) } >MON_RAM

  .data : { *(.data*) } >MON_RAM
  .bss  : { *(.bss*) *(COMMON) } >MON_RAM

  /* The U-mode prober window (UTEXT): a 2 KiB R-X window near mon_ram's tail.
   * This core's NAPOT encoding requires a region's base be aligned to 4x its
   * size, so a 2 KiB window sits at the 8 KiB-aligned 0x1001E000. U needs its
   * own executable region to fetch the prober from; the rest of mon_ram stays
   * undescribed (U-denied). pmp.rs reads the `.utext` `_uprobe_entry` label for
   * the base; 0x1001E000 is the one place it is spelled. */
  .utext 0x1001E000 : { KEEP(*(.utext)) } >MON_RAM

  /* M-mode stack grows DOWN from just below UTEXT (away from it). If the image
   * (.text/.rodata/.data/.bss) ever reaches 0x1001E000, the MON_RAM region
   * overflows into .utext and the linker errors on region overflow. */
  _stack_top = 0x1001E000;
}
