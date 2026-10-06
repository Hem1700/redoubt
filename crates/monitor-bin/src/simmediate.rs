//! Phase-2 V4 — the U-compartment -> M-monitor `mediate` round trip on the
//! Verilated SoC (`cargo xtask verilator -- mediate`).
//!
//! # Model: M + U (ruling P2-5)
//! This VexRiscv `secure` core has no Supervisor mode (V2 finding F1), so the
//! plan's "U -> S(Warden) -> M -> egress -> U" collapses to
//! **U-compartment -> M-monitor(`mediate`) -> egress -> U**. There is no S-mode
//! Warden here; the Warden's scheduling/IPC role is Phase 3.
//!
//! # Flow (all on the RTL)
//!   1. M installs the trap vector, locks the PMP, drops to the U stub.
//!   2. For each canonical case i in {benign, attack, flow} the U stub
//!      - `ecall FN_REQ(i)`: M stages case i's request wire image (the SAME
//!        `fixtures::case_request` the QEMU/host demos use) in a U-readable
//!        template slot inside SHARED_REQ and returns its address+length;
//!      - copies those bytes into the request slot (SHARED_REQ[0..len]) with
//!        its own loads/stores — U really places the request;
//!      - `ecall MEDIATE(a0=0, a1=len)`: M runs `monitor::mediate` (the
//!        `EgressMmioSink` injecting the secret on the egress leg), stamps the
//!        result, writes the response body into a U-visible slot, and returns
//!        `a0=status`, `a1=resp_len`;
//!      - `ecall FN_REPORT(i, status, resp_len)`: M prints one deterministic
//!        `mediate: <name>=<verdict>` line and verifies the properties below.
//!   3. `ecall FN_MDONE`: M prints `MEDIATE-DONE` (or `MEDIATE-FAIL`) and halts.
//!
//! # What this proves, and what it does NOT (F2 — honest scope)
//! It proves the mediation LOGIC on RTL (correct verdicts at the right stage)
//! and the capability-model properties: the injected secret appears in the
//! egress record (M-driven MMIO) yet NOWHERE in U-visible memory; a denied
//! request never drives the sink. It does NOT prove that U is hardware-blocked
//! from the egress MMIO: on this core CPU MMIO bypasses PMP (`addr[31]=1`), so
//! that bus-level wall needs an IOPMP / RTL egress gate (Phase 5).
//!
//! `sim` + `mediate` only; all `unsafe` lives here in the binary crate.

use core::ptr::{addr_of, addr_of_mut};

use abi::ReasonCode;
use monitor::cap::{Cap, Sessions};
use monitor::egress::{EgressSink, Response, RESP_BODY_MAX};
use monitor::parse::MAX_REQ;
use monitor::predicate::Args;
use monitor::{audit::Audit, mediate};

use crate::fixtures::{
    build_policy, build_sessions, case_expected, case_name, case_request, verdict_name, CASE_BENIGN,
    N_CASES, RESPONSE_BODY, SECRET,
};
use crate::pmp;
use crate::simtrap::{self, FR_A0, FR_A1, FR_A2};
use crate::uart;

pub(crate) const MEDIATE_OP: u32 = abi::Opcode::Mediate as u32;
/// U asks M to stage case `a0`'s request; M returns a0=addr, a1=len.
const FN_REQ: u32 = 3;
/// U reports (a0=case, a1=status, a2=resp_len) for M to print + verify.
const FN_REPORT: u32 = 4;
/// U signals the last case is done.
const FN_MDONE: u32 = 5;

// --- SHARED_REQ layout (4 KiB; U has RW on the whole page) -----------------
const REQ_OFF: usize = 0; // request slot [0, MAX_REQ)
const TMPL_OFF: usize = 0x200; // template i at TMPL_OFF*(i+1)
const RESP_OFF: usize = 0x800; // U-visible response body [0x800, 0xA00)
pub(crate) const SHARED_LEN: usize = pmp::SHARED_REQ_SIZE as usize;
const _: () = assert!(MAX_REQ <= TMPL_OFF);
const _: () = assert!(TMPL_OFF * (N_CASES as usize + 1) <= RESP_OFF);
const _: () = assert!(RESP_OFF + RESP_BODY_MAX <= SHARED_LEN);

pub(crate) fn shared_base() -> *mut u8 {
    pmp::SHARED_REQ_BASE as *mut u8
}

// --- Egress MMIO mock (CSR window at pmp::EGRESS_REC..) --------------------
const REC_BYTES: usize = (pmp::EGRESS_WORDS as usize) * 4;

fn egress_word(i: u32) -> *mut u32 {
    (pmp::EGRESS_REC + 4 * i) as *mut u32
}
pub(crate) fn egress_calls() -> u32 {
    unsafe { core::ptr::read_volatile(pmp::EGRESS_CALLS as *const u32) }
}
fn egress_len() -> usize {
    let n = unsafe { core::ptr::read_volatile(pmp::EGRESS_LEN as *const u32) } as usize;
    core::cmp::min(n, REC_BYTES)
}

/// Copy `bytes` into `rec` starting at `at` (truncating); return the new end.
/// Iterator-based: no indexing, no panic path.
fn append(rec: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    let mut n = at;
    for (dst, &b) in rec.iter_mut().skip(at).zip(bytes.iter()) {
        *dst = b;
        n += 1;
    }
    n
}

/// The sim egress sink: drives the M-only EGRESS_MMIO record buffer with the
/// outbound bytes (host + path + injected secret), then bumps the call counter.
/// The returned body is the fixed non-leaking `RESPONSE_BODY` — the secret goes
/// ONLY to the egress record, never into anything U can read.
pub struct EgressMmioSink;

impl EgressSink for EgressMmioSink {
    fn perform(
        &mut self,
        _cap: &Cap,
        args: &Args,
        secret: Option<&[u8]>,
    ) -> Result<Response, ReasonCode> {
        // Fail closed: no structured target, no dial.
        let parts = args.url_parts().ok_or(ReasonCode::ErrInternal)?;
        let mut rec = [0u8; REC_BYTES];
        let mut n = append(&mut rec, 0, parts.host);
        n = append(&mut rec, n, parts.path);
        if let Some(s) = secret {
            n = append(&mut rec, n, s); // outbound only
        }
        unsafe {
            for (i, c) in rec.chunks_exact(4).enumerate() {
                let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                core::ptr::write_volatile(egress_word(i as u32), w);
            }
            core::ptr::write_volatile(pmp::EGRESS_LEN as *mut u32, n as u32);
            let calls = core::ptr::read_volatile(pmp::EGRESS_CALLS as *const u32);
            core::ptr::write_volatile(pmp::EGRESS_CALLS as *mut u32, calls.wrapping_add(1));
        }
        Ok(Response::with_body(ReasonCode::Allow, abi::Label::UNTRUSTED, RESPONSE_BODY))
    }
}

/// Does the egress record (as read back from the MMIO) contain `needle`?
fn egress_record_contains(needle: &[u8]) -> bool {
    let mut rec = [0u8; REC_BYTES];
    unsafe {
        for (i, c) in rec.chunks_exact_mut(4).enumerate() {
            let w = core::ptr::read_volatile(egress_word(i as u32));
            c.copy_from_slice(&w.to_le_bytes());
        }
    }
    let len = egress_len();
    rec.iter().take(len).copied().collect_window_match(needle)
}

/// Tiny helper trait so the scan reads clearly without allocating.
trait WindowMatch {
    fn collect_window_match(self, needle: &[u8]) -> bool;
}
impl<I: Iterator<Item = u8>> WindowMatch for I {
    fn collect_window_match(self, needle: &[u8]) -> bool {
        // Streaming naive matcher over a byte iterator (needle is short).
        let mut buf = [0u8; 64];
        let nl = needle.len();
        if nl == 0 || nl > buf.len() {
            return false;
        }
        let mut have = 0usize;
        for b in self {
            if have < nl {
                buf[have] = b;
                have += 1;
            } else {
                // slide left by one
                let mut i = 0;
                while i + 1 < nl {
                    buf[i] = buf[i + 1];
                    i += 1;
                }
                buf[nl - 1] = b;
            }
            if have == nl && buf.iter().take(nl).zip(needle.iter()).all(|(a, b)| a == b) {
                return true;
            }
        }
        false
    }
}

// --- monitor state (single hart, interrupts masked in the handler) ---------
static mut SESSIONS: Option<Sessions> = None;
static mut AUDIT: Option<Audit> = None;
/// Verdict of the most recent MEDIATE (M's own view, cross-checked vs U's report).
static mut LAST_STATUS: u8 = 0xFF;
/// Did the most recent MEDIATE drive the egress sink?
static mut LAST_DRIVEN: bool = false;
/// Any check failed (fail closed -> `MEDIATE-FAIL`).
static mut FAILED: bool = false;

fn fail() {
    unsafe { *addr_of_mut!(FAILED) = true };
}

/// Run the safe `monitor::mediate` pipeline against SHARED_REQ[ptr..ptr+len],
/// with the `EgressMmioSink`; write the response body into the U-visible slot.
pub(crate) fn dispatch_mediate(ptr: usize, len: usize) -> (u8, usize) {
    let shared: &[u8] = unsafe { core::slice::from_raw_parts(shared_base(), MAX_REQ) };
    let sessions = match unsafe { (*addr_of_mut!(SESSIONS)).as_mut() } {
        Some(s) => s,
        None => return (ReasonCode::ErrInternal as u8, 0),
    };
    let audit = match unsafe { (*addr_of_mut!(AUDIT)).as_mut() } {
        Some(a) => a,
        None => return (ReasonCode::ErrInternal as u8, 0),
    };
    let policy = build_policy();
    let mut sink = EgressMmioSink;

    let calls_before = egress_calls();
    let (rc, resp) = mediate(shared, ptr, len, 0..MAX_REQ, sessions, &policy, &mut sink, audit);
    let driven = egress_calls() != calls_before;

    let body = resp.bytes();
    let n = core::cmp::min(body.len(), RESP_BODY_MAX);
    unsafe {
        core::ptr::copy_nonoverlapping(body.as_ptr(), shared_base().add(RESP_OFF), n);
        *addr_of_mut!(LAST_STATUS) = rc as u8;
        *addr_of_mut!(LAST_DRIVEN) = driven;
    }
    (rc as u8, n)
}

/// Does the ENTIRE U-visible SHARED_REQ page contain `needle`?
pub(crate) fn shared_page_contains(needle: &[u8]) -> bool {
    let page: &[u8] = unsafe { core::slice::from_raw_parts(shared_base(), SHARED_LEN) };
    page.iter().copied().collect_window_match(needle)
}

fn print_line(name: &str, suffix: &str, value: &str) {
    uart::puts("mediate: ");
    uart::puts(name);
    uart::puts(suffix);
    uart::puts("=");
    uart::puts(value);
    uart::puts("\n");
}

/// FN_REPORT: print U's verdict and verify the containment properties.
fn report(case: u32, status: u8, resp_len: u32) {
    let name = case_name(case);
    print_line(name, "", verdict_name(status));

    let last = unsafe { *addr_of!(LAST_STATUS) };
    let driven = unsafe { *addr_of!(LAST_DRIVEN) };
    if status != case_expected(case) || status != last {
        fail();
    }

    if case == CASE_BENIGN {
        let out = egress_record_contains(SECRET);
        print_line(name, "-secret", if out { "outbound-present" } else { "outbound-MISSING" });
        let leak = shared_page_contains(SECRET);
        print_line(name, "-secret", if leak { "response-LEAK" } else { "response-absent" });
        // The U-visible response is exactly the fixed body.
        let body: &[u8] =
            unsafe { core::slice::from_raw_parts(shared_base().add(RESP_OFF), RESPONSE_BODY.len()) };
        let body_ok = resp_len as usize == RESPONSE_BODY.len() && body == RESPONSE_BODY;
        if !out || leak || !driven || !body_ok {
            fail();
        }
    } else {
        print_line(name, "-sink", if driven { "DRIVEN" } else { "not-driven" });
        if driven {
            fail();
        }
    }
}

/// U-compartment ecall dispatch (called from `sim_trap_rust`'s ecall arm for any
/// selector other than the pmp prober's). Returns true if handled.
pub fn handle_ecall(frame: *mut u32, a7: u32) -> bool {
    let (a0, a1, a2) =
        unsafe { (*frame.add(FR_A0), *frame.add(FR_A1), *frame.add(FR_A2)) };
    match a7 {
        MEDIATE_OP => {
            let (status, resp_len) = dispatch_mediate(a0 as usize, a1 as usize);
            unsafe {
                *frame.add(FR_A0) = status as u32;
                *frame.add(FR_A1) = resp_len as u32;
            }
            true
        }
        FN_REQ => {
            let (addr, len) = if a0 < N_CASES {
                let req = case_request(a0);
                let dst = unsafe { shared_base().add(TMPL_OFF * (a0 as usize + 1)) };
                unsafe { core::ptr::copy_nonoverlapping(req.bytes.as_ptr(), dst, req.len) };
                (dst as u32, req.len as u32)
            } else {
                (0, 0)
            };
            unsafe {
                *frame.add(FR_A0) = addr;
                *frame.add(FR_A1) = len;
            }
            true
        }
        FN_REPORT => {
            report(a0, a1 as u8, a2);
            true
        }
        FN_MDONE => {
            if unsafe { *addr_of!(FAILED) } {
                uart::puts("MEDIATE-FAIL\n");
            } else {
                uart::puts("MEDIATE-DONE\n");
            }
            simtrap::halt();
        }
        _ => false,
    }
}

// --- the U-mode compartment stub -------------------------------------------
//
// Position-independent straight-line code in its own `.utext.b` section, placed
// by the linker INSIDE the same 2 KiB U-executable window as the pmp prober.
// It uses only registers and SHARED_REQ (its own RW grant); s0 = case index,
// s1 = request length (both preserved across the M trap).
core::arch::global_asm!(
    ".section .utext.b,\"ax\",@progbits",
    ".globl _umediate_entry",
    ".align 4",
    "_umediate_entry:",
    "li s0, 0",
    "1:",
    "mv a0, s0",
    "li a7, {fn_req}",
    "ecall",                       // a0 = template addr, a1 = len
    "mv s1, a1",
    "mv t0, a0",
    "li t1, {req_base}",
    "mv t2, s1",
    "2:",
    "beqz t2, 3f",
    "lbu t3, 0(t0)",
    "sb t3, 0(t1)",                // U places the request in SHARED_REQ
    "addi t0, t0, 1",
    "addi t1, t1, 1",
    "addi t2, t2, -1",
    "j 2b",
    "3:",
    "li a0, 0",
    "mv a1, s1",
    "li a7, {mediate}",
    "ecall",                       // a0 = status, a1 = resp_len
    "mv a2, a1",
    "mv a1, a0",
    "mv a0, s0",
    "li a7, {fn_report}",
    "ecall",                       // M prints + verifies this case
    "addi s0, s0, 1",
    "li t0, {n_cases}",
    "blt s0, t0, 1b",
    "li a7, {fn_done}",
    "ecall",
    "4:",
    "j 4b",
    fn_req = const FN_REQ,
    req_base = const pmp::SHARED_REQ_BASE,
    mediate = const MEDIATE_OP,
    fn_report = const FN_REPORT,
    n_cases = const N_CASES,
    fn_done = const FN_MDONE,
);

extern "C" {
    static _umediate_entry: u8;
}

/// Entry point for the `mediate` scenario (called from `main` on the sim image
/// built with the `mediate` feature). Never returns.
pub fn run_mediate_demo() -> ! {
    simtrap::install_trap();
    pmp::lock_regions();
    init_monitor_state();
    uart::puts("MEDIATE-ARMED\n");

    let entry = core::ptr::addr_of!(_umediate_entry) as u32;
    simtrap::drop_to_user(entry, pmp::SHARED_REQ_END);
}

/// Seed the monitor's session/audit state and zero the U-visible SHARED_REQ
/// page (shared with the Phase-3 `endpoint` image).
pub(crate) fn init_monitor_state() {
    unsafe {
        *addr_of_mut!(SESSIONS) = Some(build_sessions());
        *addr_of_mut!(AUDIT) = Some(Audit::default());
        // Start from a clean U-visible page (so a stale byte can't fake a leak
        // or a hit).
        let base = shared_base();
        let mut i = 0usize;
        while i < SHARED_LEN {
            core::ptr::write_volatile(base.add(i), 0);
            i += 1;
        }
    }
}

/// Silence an unused-const warning for the request-slot offset (documented in
/// the layout; the U stub addresses SHARED_REQ base directly).
const _: usize = REQ_OFF;
