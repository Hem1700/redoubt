//! Phase-5 H1 -- the `egress-gate` scenario: a U-mode prober tries to reach the
//! EGRESS_MMIO window and the custom RTL egress mediation gate (sim/redoubt_soc.py,
//! `EgressGate`) must stop it at the bus, while the monitor's own (M-mode) egress
//! still passes. Closes the Phase-2 gap that uncached MMIO bypasses PMP (pmp.rs,
//! fact 1b).
//!
//! What U does (all inside the baked-in `.utext` window, no PMP grant to egress):
//!   1. STORE to the egress record (`egress_rec00`)  -> gate swallows it (no trap:
//!      this core's DataCache cannot fault an uncached store on a bus error).
//!   2. LOAD  from the egress record                  -> gate returns ERR -> load
//!      access fault (mcause 5); M prints `EGRESS-GATE-FAULT`.
//!   3. STORE to the UART data register (same window) -> swallowed; nothing is
//!      transmitted (a `~` leaking onto the UART fails the scenario).
//!   4. LOAD  from the gate's own audit counter       -> faults (U cannot read or
//!      reset the audit state).
//!   5. `ecall` -> M.
//! M then proves the effect did not happen (egress record still zero), reads the
//! gate's blocked counter (4 = the four U transactions above) and proves its own
//! egress through the gate still works (write + read back).
//!
//! `sim`-only. The prober symbol `_uprobe_entry` replaces the PMP prober in this
//! image (simtrap.rs cfg-gates that one out). All `unsafe` is confined here.

use crate::pmp;
use crate::simtrap;
use crate::uart;

/// `ecall` selector: U finished probing.
const FN_U_DONE: u32 = 0x40;

/// Word U tries to plant in the egress record.
const U_PAYLOAD: u32 = 0xDEAD_BEEF;
/// Word M writes through the gate to prove M egress still works.
const M_PAYLOAD: u32 = 0xA5A5_A5A5;
/// Byte U tries to push out of the UART through the gated window.
const U_UART_BYTE: u32 = b'~' as u32;

/// Number of U transactions the gate must have blocked (the four listed above).
const EXPECTED_BLOCKED: u32 = 4;

const EGRESS_REC0: u32 = pmp::EGRESS_REC;
const UART_DATA: u32 = pmp::UART_RXTX;
const GATE_BLOCKED: u32 = pmp::EGRESS_GATE_BLOCKED;

core::arch::global_asm!(
    ".section .utext,\"ax\",@progbits",
    ".globl _uprobe_entry",
    ".align 4",
    "_uprobe_entry:",
    "li a0, {rec}",     "li t0, {payload}", "sw t0, 0(a0)", // store -> dropped
    "li a0, {rec}",     "lw t0, 0(a0)",                     // load  -> fault (5)
    "li a0, {uart}",    "li t0, {ubyte}",   "sw t0, 0(a0)", // UART store -> dropped
    "li a0, {gate}",    "lw t0, 0(a0)",                     // audit counter -> fault (5)
    "li a7, {fn_done}", "ecall",
    "1:", "j 1b",
    rec = const EGRESS_REC0,
    payload = const U_PAYLOAD,
    uart = const UART_DATA,
    ubyte = const U_UART_BYTE,
    gate = const GATE_BLOCKED,
    fn_done = const FN_U_DONE,
);

/// A U load the gate faulted (called from the shared trap handler).
pub(crate) fn print_fault(cause: u32, addr: u32) {
    uart::puts("EGRESS-GATE-FAULT mcause=");
    uart::put_u32_dec(cause);
    uart::puts(" addr=0x");
    uart::put_u32_hex(addr);
    uart::puts("\n");
}

fn rd(addr: u32) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}
fn wr(addr: u32, v: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, v) }
}

/// Handle the prober's `ecall`; runs the M-side checks, then halts. Returns
/// false for selectors that are not ours.
pub(crate) fn handle_ecall(_frame: *mut u32, a7: u32) -> bool {
    if a7 != FN_U_DONE {
        return false;
    }
    // (1) U's store never reached the sink.
    if rd(EGRESS_REC0) == 0 {
        uart::puts("EGRESS-GATE-U-WRITE=DROPPED\n");
    } else {
        uart::puts("EGRESS-GATE-U-WRITE=LEAK\n");
    }
    // (2) audit counter (read by M through the gate: allowed).
    let blocked = rd(GATE_BLOCKED);
    uart::puts("EGRESS-GATE-BLOCKED=");
    uart::put_u32_dec(blocked);
    uart::puts("\n");
    if blocked != EXPECTED_BLOCKED {
        uart::puts("EGRESS-GATE-FAIL blocked-count\n");
    }
    // (3) M egress still works through the gate.
    wr(EGRESS_REC0, M_PAYLOAD);
    if rd(EGRESS_REC0) == M_PAYLOAD {
        uart::puts("EGRESS-M=OK\n");
    } else {
        uart::puts("EGRESS-M=BAD\n");
    }
    uart::puts("EGRESS-GATE-DONE\n");
    simtrap::halt();
}

/// Entry point for the `egress-gate` scenario (called from `main`).
pub fn run_egress_gate_demo() -> ! {
    simtrap::install_trap();
    pmp::lock_regions();
    uart::puts("EGRESS-GATE-ARMED\n");
    simtrap::drop_to_user(pmp::utext_base(), pmp::SHARED_REQ_END);
}
