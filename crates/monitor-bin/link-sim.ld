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

  /* V3 (measured-boot completeness): the U-mode prober window (UTEXT) is placed
   * at a fixed 8 KiB-aligned address JUST above .rodata/.data, so the whole
   * EXECUTED/READ image — .text, .rodata, .data and .utext (U executes it) —
   * lies in one measured extent [0x1000_0000, _image_end). .bss
   * (runtime-mutable, not executed) is placed AFTER the UTEXT window, deliberately
   * OUTSIDE the measured range, so the measurement never spans the non-deterministic
   * .bss. (The small placement gap between .data and the 8 KiB-aligned .utext is
   * deterministic zero fill, loaded identically by the sim and hashed identically
   * by redoubt_soc.py.) This core's NAPOT needs the window base aligned to 4x its
   * size (2 KiB window -> 8 KiB align). pmp.rs reads `_uprobe_entry` for the base.
   * 0x1001_0000 leaves ~4 KiB headroom over the current image; the linker errors
   * loudly (region/overlap) if .text+.rodata ever grow past it. */
  .utext 0x10010000 : { KEEP(*(.utext)) KEEP(*(.utext.*)) } >MON_RAM
  _image_end = .;                 /* end of the measured (executed/read) image */

  /* .bss starts past the FULL UTEXT NAPOT window (0x800 = pmp::UTEXT_SIZE) so no
   * monitor data lands inside a U-readable window. */
  .bss 0x10010800 : { *(.bss*) *(COMMON) } >MON_RAM
  _bss_end = .;

  /* Phase-2 V3 (carry V3-2) — M-stack guard page.
   *
   * The M stack grows DOWN from _stack_top (0x1001E000). This LOCKED, no-access
   * PMP guard sits below the stack's lowest safe extent so a stack OVERFLOW hits
   * it (M-mode store fault) before it can corrupt .bss/.data — the first proof a
   * locked entry faults M (pmp::lock_regions programs it, sim_trap_rust HALTs on
   * an M-origin fault). This core's nonstandard NAPOT needs the region base
   * aligned to 4x its size, so a 4 KiB guard must be 16 KiB-aligned: 0x10018000
   * (inside MON_DATA, which is undescribed elsewhere so nothing else grants it).
   * Single source of truth: pmp.rs reads _stack_guard_base; sizes must agree
   * with pmp::STACK_GUARD_SIZE. */
  _stack_guard_size = 0x1000;   /* 4 KiB */
  _stack_guard_base = 0x10018000;

  /* M-mode stack grows DOWN from 0x1001E000. If the image (.text/.rodata/.data/
   * .utext/.bss) ever reaches the guard, the ASSERTs below fire. */
  _stack_top = 0x1001E000;
}

/* Guard-page placement invariants (outside SECTIONS so lld parses cleanly):
 * the guard must sit above .bss/.data and below the live M stack, so a stack
 * overflow hits it without ever overlapping real data. */
ASSERT(_stack_guard_base >= _bss_end,
       "stack guard overlaps .bss/.data (image too large)")
ASSERT(_stack_guard_base + _stack_guard_size <= _stack_top,
       "stack guard overlaps the live M stack")
