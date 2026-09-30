//! Redoubt Phase-2 V3 — the measured-boot ROM (BROM).
//!
//! The smallest trust element in the system. On the LiteX/VexRiscv-secure sim
//! SoC the CPU resets to `0x0000_0000` (this image). Before a single monitor
//! instruction runs, the BROM:
//!
//!   1. computes BLAKE2s-256 over the monitor's MON_CODE bytes
//!      (`[0x1000_0000, 0x1000_0000 + HASH_LEN)`),
//!   2. compares the digest to the baked-in `H_EXPECTED` (constant-time),
//!   3. **match**  → jumps to the monitor entry at `0x1000_0000`,
//!      **mismatch** → prints `BROM-TAMPER-HALT` and spins in `wfi` FOREVER —
//!      it never falls through and never reaches the monitor.
//!
//! `no_std` / `no_main`. All `unsafe` (reset asm, MMIO, the raw MON_CODE view,
//! the jump) is confined to this crate; `monitor`/`abi` stay
//! `#![forbid(unsafe_code)]`. There is no panic path: every loop is bounded (the
//! hash is over a fixed byte range) and the compare is branch-uniform.
#![no_std]
#![no_main]

use blake2::{Blake2s256, Digest};

// H_EXPECTED: [u8; 32] — baked by build.rs from $REDOUBT_H_EXPECTED (the
// BLAKE2s-256 of the monitor image built first; see the xtask `measure` flow).
include!(concat!(env!("OUT_DIR"), "/h_expected_gen.rs"));

/// Monitor code window base (canonical map MON_CODE) and its entry point.
const MON_CODE_BASE: usize = 0x1000_0000;
/// Bytes measured: the MON_CODE region size (0x8000). A fixed, bounded range;
/// the `H_EXPECTED` baked at build time covers exactly these bytes.
const HASH_LEN: usize = 0x0000_8000;
/// Monitor reset/entry (the monitor's `_start`), reached only on a good match.
const MON_ENTRY: usize = 0x1000_0000;

// LiteX "sim" UART CSRs, inside EGRESS_MMIO (0xF000_0000). Same fixed addresses
// the monitor's uart driver uses (sim/memory_map.json `csr`).
const UART_RXTX: *mut u32 = 0xF000_1800 as *mut u32;
const UART_TXFULL: *const u32 = 0xF000_1804 as *const u32;

core::arch::global_asm!(
    ".section .text._start
     .globl _start
    _start:
        la sp, _stack_top
        call brom_main
    1:
        wfi
        j 1b"
);

fn putc(byte: u8) {
    // Busy-wait while the TX FIFO is full, then push the byte.
    unsafe {
        while core::ptr::read_volatile(UART_TXFULL) != 0 {}
        core::ptr::write_volatile(UART_RXTX, byte as u32);
    }
}

/// Write a byte string to the UART. Walked as an iterator (no indexing) so no
/// bounds-check / panic path is emitted.
fn puts(s: &str) {
    for &b in s.as_bytes() {
        putc(b);
    }
}

/// Halt forever, fail closed. Interrupts are not enabled in the BROM.
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Constant-time-enough equality: fold every byte difference into one
/// accumulator so the compare time does not depend on where a mismatch is.
fn digests_equal(a: &[u8], b: &[u8; 32]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[no_mangle]
extern "C" fn brom_main() -> ! {
    puts("BROM: measuring monitor\n");

    // SAFETY: MON_CODE is a live, readable RAM window ([MON_CODE_BASE, +HASH_LEN)
    // fits the 32 KiB MON_CODE region); we form a read-only view and never write
    // through it. Bounded: exactly HASH_LEN bytes.
    let code = unsafe { core::slice::from_raw_parts(MON_CODE_BASE as *const u8, HASH_LEN) };

    let mut hasher = Blake2s256::new();
    hasher.update(code);
    let digest = hasher.finalize();

    if digests_equal(digest.as_slice(), &H_EXPECTED) {
        puts("BROM-MEASURE-OK\n");
        // Jump to the measured monitor. Never returns here.
        unsafe {
            core::arch::asm!("jr {0}", in(reg) MON_ENTRY, options(noreturn, nostack));
        }
    } else {
        // Tamper: the loaded monitor does not match the baked measurement.
        // Fail closed — announce and halt before the monitor can run.
        puts("BROM-TAMPER-HALT\n");
        halt();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No panic path is reachable, but a panic handler is mandatory. Fail closed.
    halt();
}
