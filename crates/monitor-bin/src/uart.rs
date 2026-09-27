//! Minimal polled UART driver. This is the only place in the crate (besides
//! the boot asm, the finisher, and the trap trampoline) that touches raw MMIO;
//! all `unsafe` is confined here.
//!
//! Dual-target (ruling P2-1):
//! - default: QEMU `virt` NS16550 at 0x1000_0000.
//! - `sim`  : the LiteX "sim" UART, a CSR block inside the EGRESS_MMIO window.
//!   Its register addresses are fixed by the SoC config in sim/redoubt_soc.py
//!   and mirrored in sim/memory_map.json (`csr.uart_rxtx` / `csr.uart_txfull`).

#[cfg(not(feature = "sim"))]
mod imp {
    /// QEMU `virt` NS16550 transmit-holding register.
    const UART_THR: *mut u8 = 0x1000_0000 as *mut u8;

    pub fn putc(byte: u8) {
        // QEMU's 16550 always accepts a byte for `-serial mon:stdio`; no
        // line-status busy-wait needed for this boot-time use.
        unsafe {
            core::ptr::write_volatile(UART_THR, byte);
        }
    }
}

#[cfg(feature = "sim")]
mod imp {
    // LiteX "sim" UART CSRs, inside EGRESS_MMIO (0xF000_0000). Deterministic
    // for the redoubt_soc.py config; see sim/memory_map.json `csr`.
    const UART_RXTX: *mut u32 = 0xF000_1800 as *mut u32; // write to transmit
    const UART_TXFULL: *const u32 = 0xF000_1804 as *const u32; // nonzero if TX FIFO full

    pub fn putc(byte: u8) {
        unsafe {
            // Busy-wait while the TX FIFO is full, then push the byte.
            while core::ptr::read_volatile(UART_TXFULL) != 0 {}
            core::ptr::write_volatile(UART_RXTX, byte as u32);
        }
    }
}

/// Write a byte string to the UART, one byte at a time.
///
/// Walked with raw pointers rather than slice indexing so no bounds-check /
/// `panic_bounds_check` path is emitted: that would drag core's formatting
/// machinery into the tiny sim image (which must fit MON_CODE, 32 KiB) and, on
/// the compressed-free `secure` core, is dead weight. On the sim target the
/// whole image is built for `riscv32ima` (no C extension) via `build-std`, so
/// there are no compressed opcodes to fetch regardless; see sim/README.md.
pub fn puts(s: &str) {
    let bytes = s.as_bytes();
    let mut p = bytes.as_ptr();
    // SAFETY: `p` is walked over exactly `bytes.len()` valid bytes of `s`.
    let end = unsafe { p.add(bytes.len()) };
    while p < end {
        imp::putc(unsafe { *p });
        p = unsafe { p.add(1) };
    }
}
