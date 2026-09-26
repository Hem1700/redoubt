//! Bootable M-mode "hello" image for QEMU's `riscv32` `virt` machine.
//!
//! This proves the boot toolchain end to end: linked at RAM base
//! (0x8000_0000) per `link-qemu.ld`, entered directly by QEMU's
//! `-bios` loader in M-mode, prints a banner over the 16550 UART, and
//! signals success (or failure, on panic) via the `sifive_test`
//! finisher device so `cargo xtask qemu` can assert a clean exit
//! without a human watching the console.
#![no_std]
#![no_main]

mod uart;

core::arch::global_asm!(
    ".section .text._start
     .globl _start
    _start:
        la sp, _stack_top
        call main
    1:
        wfi
        j 1b"
);

/// QEMU `virt` machine's `sifive_test` finisher device. Writing 0x5555
/// exits QEMU with status 0 (pass); writing 0x3333 exits with a nonzero
/// status (fail). This is the only other MMIO in the crate besides the
/// UART driver in `uart.rs`, and the writes are localized here.
const FINISHER: *mut u32 = 0x0010_0000 as *mut u32;

#[no_mangle]
extern "C" fn main() -> ! {
    uart::puts("redoubt: monitor online\n");
    unsafe {
        core::ptr::write_volatile(FINISHER, 0x5555); // PASS -> qemu exits 0
    }
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::ptr::write_volatile(FINISHER, 0x3333); // FAIL -> qemu exits nonzero
    }
    loop {}
}
