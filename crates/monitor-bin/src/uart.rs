//! Minimal polled driver for the NS16550-compatible UART that QEMU's
//! `virt` machine exposes at 0x1000_0000.
//!
//! This is the only place in this crate that touches raw MMIO; all
//! `unsafe` is confined to this module.

const UART_BASE: *mut u8 = 0x1000_0000 as *mut u8;

/// Write a single byte to the UART transmit-holding register (THR).
///
/// QEMU's 16550 model always accepts a byte (it does not model FIFO
/// backpressure for `-serial mon:stdio`), so no busy-wait on the line
/// status register is required for this boot-time use.
fn putc(byte: u8) {
    unsafe {
        core::ptr::write_volatile(UART_BASE, byte);
    }
}

/// Write a `\n`-terminated ASCII string to the UART, one byte at a time.
pub fn puts(s: &str) {
    for byte in s.bytes() {
        putc(byte);
    }
}
