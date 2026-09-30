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
#[cfg(feature = "mediate")]
pub(crate) const FR_A0: usize = 9; // x10
pub(crate) const FR_A1: usize = 10; // x11
#[cfg(feature = "mediate")]
pub(crate) const FR_A2: usize = 11; // x12
const FR_A7: usize = 16; // x17
pub(crate) const FR_MEPC: usize = 31;
const FR_MSTATUS: usize = 32; // saved mstatus (128(sp)); MPP = bits 12:11

/// `mstatus.MPP` (bits 12:11) == M (0b11): the trapped context was M-mode.
/// The trampoline saved `mstatus` into the frame; read it there.
fn trapped_from_machine(frame: *mut u32) -> bool {
    let mstatus = unsafe { *frame.add(FR_MSTATUS) };
    ((mstatus >> 11) & 0b11) == 0b11
}

// --- M trap stack ----------------------------------------------------------
// The pmp/measure handlers only call uart::*, so 4 KiB is plenty. The `mediate`
// image runs the whole (debug, stack-hungry) `monitor::mediate` pipeline on this
// stack, so it gets 24 KiB (still well inside the .bss..stack-guard gap).
#[cfg(not(feature = "mediate"))]
const TRAP_STACK_WORDS: usize = 1024; // 4 KiB
#[cfg(feature = "mediate")]
const TRAP_STACK_WORDS: usize = 6144; // 24 KiB
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
pub(crate) fn halt() -> ! {
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

/// A fault that originated in M-mode (a monitor bug, or the M-stack guard).
/// Deterministic line for the harness; carry V3-1 requires we HALT after it and
/// never resume M past its own fault.
fn print_m_fault(cause: u32, addr: u32) {
    uart::puts("M-FAULT mcause=");
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

    // Carry V3-1 (fail closed): before treating an access fault as the U-mode
    // prober's, check whether it came from M-mode. If it did (a monitor bug or
    // the M-stack guard), print a self-fault line and HALT — resuming M past its
    // own fault would be a fail-OPEN bug. Only U-mode faults resume.
    if matches!(cause, 1 | 5 | 7) && trapped_from_machine(frame) {
        print_m_fault(cause, read_mtval());
        // Terminal sentinel AFTER the full fault line, so a harness that waits
        // for it always sees a complete `M-FAULT ...` line first. Then HALT.
        uart::puts("M-HALT\n");
        halt();
    }

    match cause {
        // Load/store access fault = a PMP denial on a U-mode data access. Print
        // the deterministic line and RESUME the prober past the faulting load
        // (all instructions are 4 bytes; the `secure` core has no C decoder).
        5 | 7 => {
            print_fault(cause, read_mtval());
            unsafe {
                *frame.add(FR_MEPC) = frame.add(FR_MEPC).read().wrapping_add(4);
            }
        }
        // U-mode instruction access fault — not expected from this prober (it
        // never fetches from a forbidden region). Print, then fail closed.
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
                    // V4: the U compartment's mediation ecalls (MEDIATE / request
                    // fetch / verdict report). Additive to the pmp prober arms.
                    #[cfg(feature = "mediate")]
                    if crate::simmediate::handle_ecall(frame, a7) {
                        unsafe {
                            *frame.add(FR_MEPC) = frame.add(FR_MEPC).read().wrapping_add(4);
                        }
                        return;
                    }
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

/// Install the M trap vector + M trap stack (first step of every sim scenario).
pub(crate) fn install_trap() {
    write_mscratch(trap_stack_top());
    write_mtvec(sim_trap_entry as *const () as usize);
}

/// Drop from M to U at `entry` via `mret` (MPP<-U). Never returns: U runs from
/// `entry` and all subsequent control flow arrives through `sim_trap_entry`.
///
/// Register hygiene (V2 deferred minor, fixed in V4): U must not inherit any of
/// M's register state. `sp` is set to a FRESH U stack (`user_sp`, inside U's own
/// SHARED_REQ grant) and every other general register x1,x3..x31 is zeroed
/// before `mret`. `entry`/`user_sp` travel in t1/t2, which are consumed first and
/// zeroed last.
pub(crate) fn drop_to_user(entry: u32, user_sp: u32) -> ! {
    unsafe {
        // `noreturn` forbids output operands; after `mret` this hart never
        // resumes here, so clobbering registers undeclared is sound.
        core::arch::asm!(
            "csrw mepc, t1",
            "li   t0, 0x1800",   // mstatus.MPP mask (bits 12:11)
            "csrc mstatus, t0",  // MPP = 00 => next mret enters U-mode
            "mv   sp, t2",       // fresh U stack pointer (not M's)
            "li x1, 0",
            "li x3, 0",
            "li x4, 0",
            "li x5, 0",
            "li x6, 0",
            "li x7, 0",
            "li x8, 0",
            "li x9, 0",
            "li x10, 0",
            "li x11, 0",
            "li x12, 0",
            "li x13, 0",
            "li x14, 0",
            "li x15, 0",
            "li x16, 0",
            "li x17, 0",
            "li x18, 0",
            "li x19, 0",
            "li x20, 0",
            "li x21, 0",
            "li x22, 0",
            "li x23, 0",
            "li x24, 0",
            "li x25, 0",
            "li x26, 0",
            "li x27, 0",
            "li x28, 0",
            "li x29, 0",
            "li x30, 0",
            "li x31, 0",
            "mret",
            in("t1") entry,
            in("t2") user_sp,
            options(noreturn, nostack),
        );
    }
}

/// Entry point for the `pmp` scenario (called from `main` on the sim image).
#[allow(dead_code)] // unused in the `mediate` sub-image
pub fn run_pmp_demo() -> ! {
    // 1. M trap vector + trap stack.
    install_trap();

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
    drop_to_user(pmp::utext_base(), pmp::SHARED_REQ_END);
}

// --- V3-2 / Review-Focus 6: M-stack overflow self-fault demo ---------------
//
// Deliberately overflow the M stack so it grows down INTO the locked no-access
// guard page (pmp entry 2). The store in a recursion frame that lands in the
// guard raises an M-mode store/access fault; `sim_trap_rust` sees MPP==M and
// HALTs with an `M-FAULT` line instead of corrupting .bss/.data or resuming.
// This is the FIRST demonstration that a locked PMP entry faults M on this core.

/// Unbounded, non-tail recursion that touches a per-frame buffer so the compiler
/// cannot elide the frame or turn it into a loop; each call marches `sp` down by
/// a frame until it crosses into the guard page.
#[cfg(feature = "stackflow")]
#[inline(never)]
fn overflow_recurse(depth: u32) -> u32 {
    let mut buf = [0u8; 128];
    let mut i = 0usize;
    while i < buf.len() {
        // Volatile so the stores are real memory traffic into the frame.
        unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(i), depth as u8) };
        i += 1;
    }
    let mut sum = 0u32;
    i = 0;
    while i < buf.len() {
        sum = sum.wrapping_add(unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) } as u32);
        i += 1;
    }
    // Not a tail call: we combine the recursive result with this frame's sum, so
    // the frame must stay live and `sp` keeps descending.
    overflow_recurse(depth.wrapping_add(1)).wrapping_add(sum)
}

/// Entry point for the `--stack-overflow` measure sub-scenario (sim image built
/// with the `stackflow` feature). Locks the PMP (incl. the guard) then overflows
/// the M stack; control never returns here — it lands in `sim_trap_rust` at the
/// guard and HALTs.
#[cfg(feature = "stackflow")]
pub fn run_stack_overflow_demo() -> ! {
    write_mscratch(trap_stack_top());
    write_mtvec(sim_trap_entry as *const () as usize);
    pmp::lock_regions();
    uart::puts("STACK-GUARD-ARMED\n");
    let _ = overflow_recurse(0);
    // Unreachable in practice (the guard fault halts first); fail closed.
    halt();
}
