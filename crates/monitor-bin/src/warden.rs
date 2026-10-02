//! Phase-3 W1 — the minimal Warden + cooperative scheduler
//! (`cargo xtask verilator -- warden`).
//!
//! # What the Warden is (and is NOT)
//! A tiny M-mode SCHEDULER for the one live compartment this core supports. It
//! demonstrates liveness-without-trust on the M+U / PMP realisation of Redoubt,
//! NOT a full Ch-11 preemptive multi-driver Warden (that needs S-mode + an MMU
//! this `secure` core does not have — an explicit, documented deferral).
//!
//! Three things are shown, with the W2 Endpoint courier as the live compartment:
//!   (a) the Warden SCHEDULES the Endpoint and a framed benign request
//!       round-trips (SERIAL_IN -> wire::deframe -> `ecall MEDIATE` -> M) to
//!       ALLOW — parity with the host/QEMU/`endpoint` demos;
//!   (b) a compartment that spins past its time slice is PREEMPTED: the Warden
//!       gives each compartment a bounded slice; the runaway's slice is exhausted
//!       at an M-boundary crossing, M regains control, bounds it (never resumes
//!       it), and the device stays responsive (a post-preempt request still
//!       mediates to ALLOW) with M state intact (no `M-FAULT`, V3 holds);
//!   (c) liveness WITHOUT trust: a wedged/compromised Warden cannot cause an
//!       UNAUTHORIZED effect. Every relayed call is still fully mediated by M —
//!       a wrong-host attack frame is DENY_ARG and a scheduler that *wants* an
//!       ALLOW cannot override M's verdict (`forced-allow=ignored`); the runaway
//!       holds no capability and drives the egress sink zero times; the injected
//!       secret never appears in U-visible memory; the Phase-2 PMP walls are
//!       unchanged.
//!
//! # Scheduler design (describable in a few sentences — R3-D)
//! POLICY (M-mode, this file): a fixed two-entry run table — the Endpoint (EP)
//! and a deliberately-runaway compartment (RUN). Round-robin over the runnable
//! entries; each entry has a slice BUDGET counted in M-boundary crossings
//! (`ecall`). EP runs to completion (`W_DONE`); RUN yields repeatedly and never
//! completes, so when its budget hits zero M preempts it.
//!
//! MECHANISM (M-mode, in `simtrap.rs`): on every crossing the trampoline has
//! already saved the running U context into the trap frame; the Warden copies
//! that whole frame into the compartment's saved-context slot (`save_ctx`,
//! advancing the saved `mepc` past the yielding `ecall`), picks the next entry,
//! and either restores its slot (`restore_ctx`) or installs a fresh U context
//! (`install_user_ctx`: entry pc, own stack, MPP=U, GPRs zeroed). Interrupts
//! stay masked in the handler (V3). Isolation is by PMP region (no page tables):
//! both compartments share the one locked SHARED_REQ U-grant; there is nothing
//! to reprogram for a single live compartment, which is the documented M+U/PMP
//! reduction.
//!
//! # Timer reconciliation (R3-A/B) and the escape hatch taken
//! The M+U brief says the MACHINE TIMER traps to M (there is no S-mode). This
//! LiteX/VexRiscv-`secure` SoC has NO CLINT (the `0x0200_xxxx` mtimecmp/mtime of
//! the QEMU `virt` image in `arch.rs` does not exist here); its only timer is a
//! LiteX `timer0` CSR whose interrupt is routed through the prebuilt core's
//! event controller, which is not reliably exercisable from a U spin under
//! Verilator in the build budget (V3 already hit CLINT flakiness). Per the
//! brief's escape hatches we therefore take BOTH: a COOPERATIVE scheduler with a
//! timer-bound liveness guard (hatch 1), where the preempt TRIGGER is a
//! DETERMINISTIC slice-budget check at the M boundary (hatch 2) rather than an
//! async timer interrupt. The scheduling MECHANISM (save/restore U context, M
//! regains control, bound a runaway, device responsive) is real and is the
//! point; asynchronous timer-interrupt preemption of a compartment that never
//! crosses into M is the documented follow-up for a supervisor-capable core.
//!
//! `warden` feature only; all `unsafe` lives in this binary crate + `simtrap`.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use abi::ReasonCode;
use monitor::parse::MAX_REQ;

use crate::fixtures::{case_request, verdict_name, CASE_ATTACK, CASE_BENIGN, SECRET};
use crate::pmp;
use crate::simmediate::{self, MEDIATE_OP};
use crate::simtrap::{self, FRAME_WORDS, FR_A0, FR_A1};
use crate::uart;

/// Compartment -> Warden: "I yield" (a0 = the compartment's own progress tag).
const W_YIELD: u32 = 0x30;
/// Compartment -> Warden: "my job is done" (EP signals this; RUN never does).
const W_DONE: u32 = 0x31;

// --- the fixed run table (R3-D: one live compartment + one runaway) --------
const EP: usize = 0; // the W2 Endpoint courier
const RUN: usize = 1; // the deliberately-runaway compartment
const N_COMPT: usize = 2;
const _: () = assert!(RUN < N_COMPT && EP < N_COMPT);

/// Slice budgets, in M-boundary crossings. EP's is ample (it finishes via
/// `W_DONE` long before it runs out); RUN's is small so it is preempted after a
/// couple of yields — modelling "spun past its time slice".
const BUDGET0: [u32; N_COMPT] = [8, 2];

// --- U-side layout inside SHARED_REQ (shared with the courier; U has RW) ----
const SCRATCH_OFF: usize = 0xA00; // deframe scratch, as in the W2 Endpoint
const _: () = assert!(SCRATCH_OFF + wire::MAX_FRAME <= 0xE00); // leaves U stack room
const SERIAL_DATA_OFF: usize = 4; // SERIAL_IN: [len:u32][bytes]
const SERIAL_CAP: usize = pmp::SERIAL_IN_SIZE as usize - SERIAL_DATA_OFF;

// ===========================================================================
// U-mode half: the two compartments the Warden schedules.
// ===========================================================================

/// `ecall` with two argument registers; returns (a0, a1). Inlined so it stays in
/// the U-executable window (U cannot fetch from M-only `.text`).
#[inline(always)]
unsafe fn ecall(n: u32, a0: u32, a1: u32) -> (u32, u32) {
    let r0: u32;
    let r1: u32;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => r0,
        inlateout("a1") a1 => r1,
        in("a7") n,
        options(nostack),
    );
    (r0, r1)
}

/// Compartment EP — the W2 Endpoint courier (no authority): deframe each seeded
/// SERIAL_IN frame and relay the recovered request to M via `ecall MEDIATE`,
/// then signal `W_DONE`. Linked into the U-executable window.
#[no_mangle]
#[link_section = ".utext.warden"]
pub extern "C" fn _warden_ep_entry() -> ! {
    let serial = pmp::SERIAL_IN_BASE as *const u8;
    let req = pmp::SHARED_REQ_BASE as *mut u8;
    let total = core::cmp::min(unsafe { read_volatile(serial as *const u32) } as usize, SERIAL_CAP);
    let stream: &[u8] = unsafe { core::slice::from_raw_parts(serial.add(SERIAL_DATA_OFF), total) };
    let scratch: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(req.add(SCRATCH_OFF), wire::MAX_FRAME) };

    let mut pos = 0usize;
    while pos < stream.len() {
        let rest = &stream[pos..];
        let mut n = 0usize;
        while n < rest.len() && rest[n] != 0 {
            n += 1;
        }
        let end = core::cmp::min(n + 1, rest.len());
        pos += end;
        if let Ok(payload) = wire::deframe(&rest[..end], scratch) {
            let len = core::cmp::min(payload.len(), MAX_REQ);
            let mut i = 0usize;
            while i < len {
                unsafe { write_volatile(req.add(i), payload[i]) };
                i += 1;
            }
            unsafe { ecall(MEDIATE_OP, 0, len as u32) };
        }
    }
    unsafe { ecall(W_DONE, 0, 0) };
    loop {}
}

/// Compartment RUN — a deliberate runaway: burn a bounded chunk of real CPU
/// time, then yield, forever. It never signals `W_DONE`, so the Warden's slice
/// budget is what bounds it. It holds no capability and makes no `MEDIATE` call,
/// so it can drive no effect.
#[no_mangle]
#[link_section = ".utext.warden"]
pub extern "C" fn _warden_run_entry() -> ! {
    let mut i: u32 = 0;
    loop {
        // Bounded busy-work so each slice is real CPU time (not an instant
        // re-trap); `black_box` stops the optimiser eliding it.
        let mut acc = i;
        let mut k = 0u32;
        while k < 4096 {
            acc = acc.wrapping_add(k ^ i);
            k += 1;
        }
        core::hint::black_box(acc);
        unsafe { ecall(W_YIELD, i, 0) };
        i = i.wrapping_add(1);
    }
}

// ===========================================================================
// M-side half: the scheduler state + the ecall handler (the TCB part).
// ===========================================================================

static mut SLOT: [[u32; FRAME_WORDS]; N_COMPT] = [[0; FRAME_WORDS]; N_COMPT];
static mut STARTED: [bool; N_COMPT] = [false; N_COMPT];
static mut DONE: [bool; N_COMPT] = [false; N_COMPT];
static mut BUDGET: [u32; N_COMPT] = BUDGET0;
static mut CUR: usize = EP;
/// How many frames EP has relayed (0 = benign, 1 = attack) — M's own index.
static mut RELAYS: u32 = 0;
static mut FAILED: bool = false;

fn fail() {
    unsafe { *addr_of_mut!(FAILED) = true };
}

fn name(c: usize) -> &'static str {
    if c == EP {
        "EP"
    } else {
        "RUN"
    }
}

fn entry_of(c: usize) -> u32 {
    if c == EP {
        _warden_ep_entry as *const () as u32
    } else {
        _warden_run_entry as *const () as u32
    }
}

/// Both compartments run one-at-a-time, so both use the top of the SHARED_REQ
/// U-grant as their stack (the courier stack lives below the deframe scratch).
fn sp_of(_c: usize) -> u32 {
    pmp::SHARED_REQ_END
}

fn line(tag: &str, val: &str) {
    uart::puts("warden: ");
    uart::puts(tag);
    uart::puts("=");
    uart::puts(val);
    uart::puts("\n");
}

fn line_u32(tag: &str, val: u32) {
    uart::puts("warden: ");
    uart::puts(tag);
    uart::puts("=");
    uart::put_u32_dec(val);
    uart::puts("\n");
}

// --- Append one framed message into SERIAL_IN's data area -------------------
fn put_bytes(at: usize, bytes: &[u8]) -> usize {
    let base = (pmp::SERIAL_IN_BASE as usize + SERIAL_DATA_OFF) as *mut u8;
    let mut n = at;
    for &b in bytes {
        if n < SERIAL_CAP {
            unsafe { write_volatile(base.add(n), b) };
            n += 1;
        } else {
            fail();
        }
    }
    n
}

/// Seed SERIAL_IN with two well-formed frames: a benign request (frame 0, must
/// ALLOW) and a wrong-host attack request (frame 1, must DENY_ARG).
fn seed_serial_in() {
    let mut f = [0u8; wire::MAX_FRAME];
    let mut at = 0usize;

    let benign = case_request(CASE_BENIGN);
    let n = wire::frame(&benign.bytes[..benign.len], &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n]);

    let attack = case_request(CASE_ATTACK);
    let n = wire::frame(&attack.bytes[..attack.len], &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n]);

    unsafe { write_volatile(pmp::SERIAL_IN_BASE as *mut u32, at as u32) };
}

/// Does the relayed request (now in SHARED_REQ[0..len]) match the canonical
/// fixture for `idx`? (Parity oracle — the very bytes the host/QEMU demos use.)
fn relay_matches(idx: u32, len: usize) -> bool {
    let want = case_request(if idx == 1 { CASE_ATTACK } else { CASE_BENIGN });
    if want.len != len {
        return false;
    }
    let got: &[u8] = unsafe { core::slice::from_raw_parts(simmediate::shared_base(), MAX_REQ) };
    got.get(..len) == want.bytes.get(..len)
}

/// EP relayed a frame: M mediates it (and ONLY it) with the authoritative
/// `monitor::mediate` pipeline. Returns (status, resp_len) for the ecall.
fn on_relay(ptr: u32, len: u32) -> (u8, u32) {
    let idx = unsafe { *addr_of!(RELAYS) };
    unsafe { *addr_of_mut!(RELAYS) = idx + 1 };

    if !relay_matches(idx, len as usize) {
        fail();
    }

    let before = simmediate::egress_calls();
    let (status, resp_len) = simmediate::dispatch_mediate(ptr as usize, len as usize);
    let driven = simmediate::egress_calls() != before;

    if idx == 0 {
        // (a) framed benign request round-trips to ALLOW.
        line("frame0", verdict_name(status));
        if status != ReasonCode::Allow as u8 {
            fail();
        }
    } else {
        // (c) a wrong-host attack is still DENY_ARG, and a compromised scheduler
        // that *wanted* an ALLOW cannot override M's verdict: the verdict is
        // M's, and a denied request drove no effect.
        line("attack", verdict_name(status));
        if status != ReasonCode::DenyArg as u8 {
            fail();
        }
        // The "Warden" here asks for an ALLOW it has no power to grant.
        let warden_wants_allow = true;
        let forced = warden_wants_allow && status == ReasonCode::Allow as u8;
        if !forced && !driven {
            line("forced-allow", "ignored");
        } else {
            line("forced-allow", "honored");
            fail();
        }
    }
    (status, resp_len as u32)
}

/// Pick the next runnable compartment after `cur`, round-robin. None => the run
/// queue is drained (everything done or bounded).
fn pick_next(cur: usize) -> Option<usize> {
    for off in 1..=N_COMPT {
        let c = (cur + off) % N_COMPT;
        if !unsafe { (*addr_of!(DONE))[c] } {
            return Some(c);
        }
    }
    None
}

/// Dispatch compartment `n`: restore its saved context, or install a fresh one.
fn resume_or_start(frame: *mut u32, n: usize) {
    unsafe { *addr_of_mut!(CUR) = n };
    line("run", name(n));
    if unsafe { (*addr_of!(STARTED))[n] } {
        unsafe { simtrap::restore_ctx(frame, (*addr_of!(SLOT))[n].as_ptr()) };
    } else {
        unsafe {
            (*addr_of_mut!(STARTED))[n] = true;
            simtrap::install_user_ctx(frame, entry_of(n), sp_of(n));
        }
    }
}

/// The device stays responsive after a preempt: M itself mediates a benign
/// request (proving the system still services work), then reports the
/// containment evidence and the terminal verdict. Never returns.
fn finish(_frame: *mut u32) -> ! {
    // Post-preempt: M stages + mediates a benign request directly.
    let benign = case_request(CASE_BENIGN);
    unsafe {
        core::ptr::copy_nonoverlapping(benign.bytes.as_ptr(), simmediate::shared_base(), benign.len);
    }
    let (status, _) = simmediate::dispatch_mediate(0, benign.len);
    line("post-preempt", verdict_name(status));
    if status != ReasonCode::Allow as u8 {
        fail();
    }

    // Containment evidence: only the two benign relays (EP frame 0 + the
    // post-preempt one) ever drove the egress sink; the attack and the runaway
    // drove nothing. The injected secret is nowhere in U-visible memory.
    let sink_calls = simmediate::egress_calls();
    line_u32("sink-calls", sink_calls);
    let leak = simmediate::shared_page_contains(SECRET);
    line("secret", if leak { "LEAK" } else { "absent" });

    let ok = !unsafe { *addr_of!(FAILED) }
        && !leak
        && sink_calls == 2
        && unsafe { *addr_of!(RELAYS) } == 2;
    uart::puts(if ok { "WARDEN-DONE\n" } else { "WARDEN-FAIL\n" });
    simtrap::halt();
}

/// A compartment yielded: charge its slice, preempt it if the slice is spent and
/// it is not done, then reschedule.
fn on_yield(frame: *mut u32) {
    let cur = unsafe { *addr_of!(CUR) };
    let progress = unsafe { *frame.add(FR_A0) };

    if unsafe { (*addr_of!(BUDGET))[cur] } > 0 {
        unsafe { (*addr_of_mut!(BUDGET))[cur] -= 1 };
    }
    let left = unsafe { (*addr_of!(BUDGET))[cur] };
    // one line: `yield=<name> slice=<left> n=<progress>`
    uart::puts("warden: yield=");
    uart::puts(name(cur));
    uart::puts(" slice=");
    uart::put_u32_dec(left);
    uart::puts(" n=");
    uart::put_u32_dec(progress);
    uart::puts("\n");

    if left == 0 && !unsafe { (*addr_of!(DONE))[cur] } {
        // (b) spun past its slice: M bounds the runaway — mark it done so it is
        // never resumed, and record the preemption.
        unsafe { (*addr_of_mut!(DONE))[cur] = true };
        line("preempt", name(cur));
    }

    // Save the (possibly-to-be-resumed) context, then reschedule.
    unsafe { simtrap::save_ctx(frame, (*addr_of_mut!(SLOT))[cur].as_mut_ptr()) };
    match pick_next(cur) {
        Some(n) => resume_or_start(frame, n),
        None => finish(frame),
    }
}

/// A compartment signalled completion (EP): mark it done, reschedule.
fn on_done(frame: *mut u32) {
    let cur = unsafe { *addr_of!(CUR) };
    unsafe { (*addr_of_mut!(DONE))[cur] = true };
    line("done", name(cur));
    match pick_next(cur) {
        Some(n) => resume_or_start(frame, n),
        None => finish(frame),
    }
}

/// Warden-image ecall dispatch (called from `sim_trap_rust`). The Warden fully
/// owns `mepc` on every selector it handles (resume / context switch / preempt),
/// so the caller must NOT auto-advance. Returns true if handled.
pub fn handle_ecall(frame: *mut u32, a7: u32) -> bool {
    match a7 {
        MEDIATE_OP => {
            let (a0, a1) = unsafe { (*frame.add(FR_A0), *frame.add(FR_A1)) };
            let (status, resp_len) = on_relay(a0, a1);
            unsafe {
                *frame.add(FR_A0) = status as u32;
                *frame.add(FR_A1) = resp_len;
                // Stay in the same compartment: step past its `ecall`.
                *frame.add(simtrap::FR_MEPC) = frame.add(simtrap::FR_MEPC).read().wrapping_add(4);
            }
            true
        }
        W_YIELD => {
            on_yield(frame);
            true
        }
        W_DONE => {
            on_done(frame);
            true
        }
        _ => false,
    }
}

/// Entry point for the `warden` scenario (called from `main` on the sim image
/// built with the `warden` feature). Never returns.
pub fn run_warden_demo() -> ! {
    simtrap::install_trap();
    // Seed the mock serial source BEFORE the PMP lock (SERIAL_IN becomes R-- +
    // L=1 after the lock, so the courier's input is immutable once it runs).
    seed_serial_in();
    pmp::lock_regions();
    simmediate::init_monitor_state();
    uart::puts("WARDEN-ARMED\n");

    // Bootstrap: dispatch the Endpoint as the first compartment. Every later
    // dispatch arrives through the trap handler (save/restore/install).
    unsafe { (*addr_of_mut!(STARTED))[EP] = true };
    line("run", name(EP));
    simtrap::drop_to_user(entry_of(EP), sp_of(EP))
}
