//! Bootable M-mode "hello" image for the Redoubt monitor.
//!
//! Dual-target (ruling P2-1), same sources, two linked images:
//!
//! - **default (QEMU)**: linked at RAM base 0x8000_0000 (`link-qemu.ld`),
//!   entered by QEMU's `-bios` loader in M-mode. Prints the banner, installs
//!   the trap vector, drives the Task-14 `mediate` containment pipeline from
//!   `ecall` traps, and signals PASS/FAIL via the `sifive_test` finisher so
//!   `cargo xtask qemu` asserts a clean exit unattended.
//!
//! - **`sim`**: linked at MON_CODE 0x1000_0000 (`link-sim.ld`), booted by the
//!   LiteX/VexRiscv-secure SoC in Verilator (`cargo xtask verilator -- boot`).
//!   This is the Phase-2 V1 boot proof: reset -> MON_CODE, print the banner on
//!   the LiteX UART, then idle. Hardware PMP (V2), measured boot (V3) and the
//!   Warden round-trip that re-lights the `mediate` pipeline (V4) build on top.
#![no_std]
#![no_main]

// The trap trampoline + `mediate` driver + QEMU MMIO (CLINT/finisher) are the
// QEMU image only. The sim image (V1) is a pure boot-banner proof; its trap
// path arrives with PMP in V2. Gating the module out also keeps the sim image
// tiny (the 128 KiB trap stack static never exists), well within MON_DATA.
#[cfg(not(feature = "sim"))]
mod arch;
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

const BANNER: &str = "redoubt: monitor online\n";

/// QEMU `virt` `sifive_test` finisher: write 0x5555 to exit(0) (pass), 0x3333
/// to exit nonzero (fail). QEMU image only.
#[cfg(not(feature = "sim"))]
const FINISHER: *mut u32 = 0x0010_0000 as *mut u32;

#[cfg(not(feature = "sim"))]
#[no_mangle]
extern "C" fn main() -> ! {
    uart::puts(BANNER);

    // Install the M-mode trap vector + seed the monitor statics, then drive
    // the Task-14 `mediate` pipeline from `ecall` traps. Signal PASS only if
    // every containment scenario matched its expected verdict.
    arch::init();
    let all_passed = arch::run_demo();

    let code = if all_passed { 0x5555 } else { 0x3333 };
    unsafe {
        core::ptr::write_volatile(FINISHER, code);
    }
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

#[cfg(feature = "sim")]
#[no_mangle]
extern "C" fn main() -> ! {
    // Phase-2 V1: prove the monitor boots on the Verilated SoC at the SoC
    // memory map and reaches its banner over the LiteX UART. The mediate
    // pipeline is re-lit here in V4 once the Warden + PMP are in place.
    uart::puts(BANNER);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

#[cfg(not(feature = "sim"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::ptr::write_volatile(FINISHER, 0x3333); // FAIL -> qemu exits nonzero
    }
    loop {}
}

#[cfg(feature = "sim")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No finisher on the LiteX sim; fail closed by halting. The harness times
    // out (no banner / no clean state) and reports failure.
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}
