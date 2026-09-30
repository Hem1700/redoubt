//! Phase-2 V2 — the M→U privilege drop, the baked-in U-mode prober, and the
//! M-mode PMP fault handler for the `cargo xtask verilator -- pmp` scenario.
//!
//! This is the fault-injection evidence that the PMP walls programmed by
//! `pmp::lock_regions()` are unbypassable: a U-mode stub performs forbidden
//! loads at the secrets, the monitor's own code/data, the Warden region, an
//! undescribed gap, and a region boundary — each must fault — and one control
//! load at its OWN region (SHARED_REQ) must succeed. (Egress MMIO is in the
//! uncached IO window and is not PMP-deniable on this core; see the probe-list
//! note below and pmp.rs fact 1b.)
//!
//! `sim`-only; all `unsafe` (trap trampoline, CSR reads, privilege drop) lives
//! here in the binary crate. `monitor`/`abi` stay `#![forbid(unsafe_code)]`.
//!
//! ## Flow (single hart, interrupts masked in the handler)
//!   1. install the M trap vector + M trap stack, `pmp::lock_regions()`
//!   2. seed a magic word into SHARED_REQ (M may write it: entry 0 = locked RW)
//!   3. lock-immutability check (M rewrite of a locked entry is a no-op)
//!   4. `mret` down to U at the baked-in prober in the UTEXT window
//!   5. every U load that violates PMP faults → mcause 5 → M prints one
//!      `PMP-FAULT mcause=<d> addr=<hex>` line and resumes the prober past the
//!      faulting load; the own-region load succeeds → U `ecall`s the value → M
//!      verifies it and prints `PMP-OWN=OK`; the final `ecall` prints
//!      `PMP-DONE` and the monitor idles. The handler never panics; any
//!      unexpected cause fails closed (`PMP-FAIL`, then halt).

use crate::pmp;
use crate::uart;

// Map-derived probe targets (ruling P2-2: all from memory_map.json via pmp).
//
// NOTE: EGRESS_MMIO (0xF000_0000) is deliberately NOT probed. It is in the
// uncached IO window (addr[31]=1), and this core's DataCache bypasses the PMP
// permission check for uncached accesses (`bypassCache = isIoAccess`; the
// bypass `accessError` ignores `badPermissions`). So U's access to the egress
// MMIO is not PMP-deniable on this core — egress containment is by monitor
// mediation (Phase-1 `mediate` demo), not PMP. See pmp.rs (fact 1b) and the V2
// report. PMP walls only the CACHED TCB memory below 0x8000_0000, exercised
// below.
const P_SECRETS: u32 = pmp::SECRETS_BASE + 0x100; // 0x1002_0100 (brief)
const P_MON_DATA: u32 = pmp::MON_DATA_BASE; // 0x1000_8000
const P_MON_CODE: u32 = pmp::MON_CODE_BASE; // 0x1000_0000
const P_WARDEN: u32 = pmp::WARDEN_BASE; // 0x2000_0000
const P_GAP: u32 = 0x5000_0000; // undescribed hole (Review-Focus 2)
const P_SECRETS_LAST: u32 = pmp::SECRETS_END - 1; // 0x1002_3fff (boundary)
const P_SHARED_OK: u32 = pmp::SHARED_REQ_BASE + 0x800; // own-region control read
const P_SHARED_PAST: u32 = pmp::SHARED_REQ_END; // 0x4000_1000 (NAPOT edge)

/// Magic seeded into SHARED_REQ and read back by the U prober to prove its own
/// region truly works (a skipped/faulted load would leave a wrong value).
const MAGIC: u32 = 0xA5A5_1234;

// ecall function selectors the prober passes in a7.
const FN_OK: u32 = 1; // a1 = value read from own region
const FN_DONE: u32 = 2;

// --- trap frame layout (matches the trampoline below; x_N at word N-1) -----
const FR_A1: usize = 10; // x11
const FR_A7: usize = 16; // x17
const FR_MEPC: usize = 31;

// --- M trap stack ----------------------------------------------------------
const TRAP_STACK_WORDS: usize = 1024; // 4 KiB — the handler only calls uart::*
#[repr(align(16))]
struct TrapStack([u32; TRAP_STACK_WORDS]);
static mut TRAP_STACK: TrapStack = TrapStack([0; TRAP_STACK_WORDS]);

fn trap_stack_top() -> usize {
    unsafe { core::ptr::addr_of!(TRAP_STACK.0).cast::<u32>().add(TRAP_STACK_WORDS) as usize }
}

// --- CSR helpers -----------------------------------------------------------
#[inline]
fn write_mtvec(handler: usize) {
    unsafe { core::arch::asm!("csrw mtvec, {0}", in(reg) handler, options(nomem, nostack)) };
}
#[inline]
fn write_mscratch(v: usize) {
    unsafe { core::arch::asm!("csrw mscratch, {0}", in(reg) v, options(nomem, nostack)) };
}
#[inline]
fn read_mcause() -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("csrr {0}, mcause", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn read_mtval() -> u32 {
    // mtval = 0x343 (a.k.a. mbadaddr); VexRiscv loads the faulting access
    // address here on an access fault.
    let v: u32;
    unsafe { core::arch::asm!("csrr {0}, 0x343", out(reg) v, options(nomem, nostack)) };
    v
}

// --- the assembly trampoline (saves x1..x31 + mepc + mstatus) --------------
core::arch::global_asm!(
    "
    .section .text
    .globl sim_trap_entry
    .align 4
sim_trap_entry:
    csrrw sp, mscratch, sp
    addi  sp, sp, -144
    sw    x1,   0(sp)
    sw    x3,   8(sp)
    sw    x4,  12(sp)
    sw    x5,  16(sp)
    sw    x6,  20(sp)
    sw    x7,  24(sp)
    sw    x8,  28(sp)
    sw    x9,  32(sp)
    sw    x10, 36(sp)
    sw    x11, 40(sp)
    sw    x12, 44(sp)
    sw    x13, 48(sp)
    sw    x14, 52(sp)
    sw    x15, 56(sp)
    sw    x16, 60(sp)
    sw    x17, 64(sp)
    sw    x18, 68(sp)
    sw    x19, 72(sp)
    sw    x20, 76(sp)
    sw    x21, 80(sp)
    sw    x22, 84(sp)
    sw    x23, 88(sp)
    sw    x24, 92(sp)
    sw    x25, 96(sp)
    sw    x26, 100(sp)
    sw    x27, 104(sp)
    sw    x28, 108(sp)
    sw    x29, 112(sp)
    sw    x30, 116(sp)
    sw    x31, 120(sp)
    csrr  t0, mscratch
    sw    t0, 4(sp)
    csrr  t0, mepc
    sw    t0, 124(sp)
    csrr  t0, mstatus
    sw    t0, 128(sp)
    mv    a0, sp
    call  sim_trap_rust
    lw    t0, 124(sp)
    csrw  mepc, t0
    lw    t0, 128(sp)
    csrw  mstatus, t0
    addi  t0, sp, 144
    csrw  mscratch, t0
    lw    x1,   0(sp)
    lw    x3,   8(sp)
    lw    x4,  12(sp)
    lw    x5,  16(sp)
    lw    x6,  20(sp)
    lw    x7,  24(sp)
    lw    x8,  28(sp)
    lw    x9,  32(sp)
    lw    x10, 36(sp)
    lw    x11, 40(sp)
    lw    x12, 44(sp)
    lw    x13, 48(sp)
    lw    x14, 52(sp)
    lw    x15, 56(sp)
    lw    x16, 60(sp)
    lw    x17, 64(sp)
    lw    x18, 68(sp)
    lw    x19, 72(sp)
    lw    x20, 76(sp)
    lw    x21, 80(sp)
    lw    x22, 84(sp)
    lw    x23, 88(sp)
    lw    x24, 92(sp)
    lw    x25, 96(sp)
    lw    x26, 100(sp)
    lw    x27, 104(sp)
    lw    x28, 108(sp)
    lw    x29, 112(sp)
    lw    x30, 116(sp)
    lw    x31, 120(sp)
    lw    x2,   4(sp)
    mret
    "
);

extern "C" {
    fn sim_trap_entry();
}

/// Halt forever (fail closed). Interrupts are already masked on trap entry.
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

fn print_fault(cause: u32, addr: u32) {
    uart::puts("PMP-FAULT mcause=");
    uart::put_u32_dec(cause);
    uart::puts(" addr=0x");
    uart::put_u32_hex(addr);
    uart::puts("\n");
}

/// Rust side of the trap. Runs in M with interrupts masked; never panics.
///
/// # Safety
/// Called only from `sim_trap_entry`, which hands a valid, uniquely-owned
/// frame pointer. Single hart, non-reentrant.
#[no_mangle]
extern "C" fn sim_trap_rust(frame: *mut u32) {
    let cause = read_mcause();

    // Ignore any interrupt (high bit) — none are armed in this scenario.
    if cause & (1u32 << 31) != 0 {
        return;
    }

    match cause {
        // Load/store access fault = a PMP denial on a data access. Print the
        // deterministic line and RESUME the prober past the faulting load
        // (all instructions are 4 bytes; the `secure` core has no C decoder).
        5 | 7 => {
            print_fault(cause, read_mtval());
            unsafe {
                *frame.add(FR_MEPC) = frame.add(FR_MEPC).read().wrapping_add(4);
            }
        }
        // Instruction access fault — not expected from this prober (it never
        // fetches from a forbidden region). Print, then fail closed.
        1 => {
            print_fault(cause, read_mtval());
            halt();
        }
        // U-mode environment call: the prober's success/DONE sentinels.
        8 => {
            let a7 = unsafe { *frame.add(FR_A7) };
            match a7 {
                FN_OK => {
                    let val = unsafe { *frame.add(FR_A1) };
                    if val == MAGIC {
                        uart::puts("PMP-OWN=OK\n");
                    } else {
                        uart::puts("PMP-OWN=BAD\n");
                    }
                    unsafe {
                        *frame.add(FR_MEPC) = frame.add(FR_MEPC).read().wrapping_add(4);
                    }
                }
                FN_DONE => {
                    uart::puts("PMP-DONE\n");
                    halt();
                }
                _ => {
                    uart::puts("PMP-FAIL\n");
                    halt();
                }
            }
        }
        // Anything else inside the TCB is unrecoverable → fail closed.
        _ => {
            uart::puts("PMP-FAIL\n");
            halt();
        }
    }
}

// --- the baked-in U-mode prober -------------------------------------------
//
// Position-independent straight-line code (only `li`/`lw`/`lb`/`ecall` and a
// local self-branch), placed by the linker at the `UTEXT_SIZE`-aligned
// `.utext` window so U has an executable region distinct from the rest of
// MON_CODE. Each forbidden load faults (handler prints + skips it); the
// own-region load succeeds and its value is handed to M via `ecall`.
core::arch::global_asm!(
    ".section .utext,\"ax\",@progbits",
    ".globl _uprobe_entry",
    ".align 4",
    "_uprobe_entry:",
    "li a0, {secrets}",      "lw t0, 0(a0)",   // SECRETS       -> fault
    "li a0, {mon_data}",     "lw t0, 0(a0)",   // MON_DATA      -> fault
    "li a0, {mon_code}",     "lw t0, 0(a0)",   // MON_CODE      -> fault
    "li a0, {warden}",       "lw t0, 0(a0)",   // WARDEN        -> fault
    "li a0, {gap}",          "lw t0, 0(a0)",   // undescribed   -> fault
    "li a0, {secrets_last}", "lb t0, 0(a0)",   // SECRETS edge  -> fault
    "li a0, {shared_ok}",    "lw t0, 0(a0)",   // OWN region    -> success
    "mv a1, t0",             "li a7, {fn_ok}", "ecall", // report value to M
    "li a0, {shared_past}",  "lw t0, 0(a0)",   // NAPOT edge+1  -> fault
    "li a7, {fn_done}",      "ecall",
    "1:", "j 1b",
    secrets = const P_SECRETS,
    mon_data = const P_MON_DATA,
    mon_code = const P_MON_CODE,
    warden = const P_WARDEN,
    gap = const P_GAP,
    secrets_last = const P_SECRETS_LAST,
    shared_ok = const P_SHARED_OK,
    shared_past = const P_SHARED_PAST,
    fn_ok = const FN_OK,
    fn_done = const FN_DONE,
);

/// Drop from M to U at `entry` via `mret` (MPP←U). Never returns: U runs the
/// prober and all subsequent control flow arrives through `sim_trap_entry`.
fn drop_to_user(entry: u32) -> ! {
    unsafe {
        // `noreturn` forbids output operands; `mepc` is read from {e} before
        // t0 is clobbered, and after `mret` this hart never resumes here, so
        // clobbering t0 undeclared is sound.
        core::arch::asm!(
            "csrw mepc, {e}",
            "li   t0, 0x1800",   // mstatus.MPP mask (bits 12:11)
            "csrc mstatus, t0",  // MPP = 00 => next mret enters U-mode
            "mret",
            e = in(reg) entry,
            options(noreturn, nostack),
        );
    }
}

/// Entry point for the `pmp` scenario (called from `main` on the sim image).
pub fn run_pmp_demo() -> ! {
    // 1. M trap vector + trap stack.
    write_mscratch(trap_stack_top());
    write_mtvec(sim_trap_entry as *const () as usize);

    // 2. Program + lock the PMP walls (first M-mode security act).
    pmp::lock_regions();

    // 3. Seed the own-region magic (entry 0 = locked RW, so M may write it).
    unsafe { core::ptr::write_volatile(P_SHARED_OK as *mut u32, MAGIC) };
    uart::puts("PMP-LOCK=OK\n");

    // 4. Lock immutability (Review-Focus 4).
    if pmp::immutability_check() {
        uart::puts("PMP-IMMUTABLE=OK\n");
    } else {
        uart::puts("PMP-IMMUTABLE=FAIL\n");
    }

    // 5. Drop to the U prober; the DONE handler halts the monitor in M.
    drop_to_user(pmp::utext_base());
}
