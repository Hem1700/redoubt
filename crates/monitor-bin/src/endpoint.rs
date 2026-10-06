//! Phase-3 W2 — the Endpoint compartment (`cargo xtask verilator -- endpoint`).
//!
//! # What the Endpoint is
//! A U-mode COURIER with NO authority (Ch 6 §6.6). Its whole job is clerical:
//! pull framed bytes off the (mock) serial source `SERIAL_IN`, recover whole
//! frames with `wire::deframe` (COBS + CRC32), copy a recovered inner request
//! into SHARED_REQ and `ecall MEDIATE`. It reads no policy, resolves no
//! capability and holds no secret: every field is re-derived and every call is
//! fully mediated by M (`monitor::mediate`, via the V4 `dispatch_mediate`), so a
//! wholly hostile Endpoint cannot cause an effect policy would deny. A frame
//! that fails to deframe (COBS / CRC / truncated / ...) is DROPPED and counted —
//! it is never relayed, so the request inside it never happened.
//!
//! # Mock serial source
//! `SERIAL_IN` (memory_map.json; RAM-backed because MMIO bypasses PMP on this
//! core) holds `[len: u32 LE][stream bytes...]`. The M-side harness below plays
//! the serial driver / test rig: before dropping to U it seeds a stream of six
//! frames (see `PLAN`). The Endpoint can only READ it (PMP entry 3, `R--`).
//!
//! # Endpoint <-> M ecall ABI (a7 selector; a0..a2 args)
//!  * `MEDIATE` (V4, unchanged): a0=0, a1=len -> a0=status, a1=resp_len.
//!  * `EP_DROP`: a0=frame idx, a1=`wire::DropReason as u32` — "I dropped it".
//!  * `EP_DONE`: a0=frames seen, a1=frames the Endpoint says it dropped.
//!
//! M independently tracks the frame index and the counters, prints one line per
//! frame (`endpoint: frame<i>=<VERDICT|DROPPED ...>`), verifies every relayed
//! payload is byte-identical to the fixture the host/QEMU demos use (parity),
//! and refuses to mediate a frame its plan says must have been dropped.
//!
//! `endpoint` feature only. The U-mode half is `no_std`, panic/unwrap-free and
//! alloc-free; its code is linked into the 2 KiB U-executable window (see
//! `link-sim.ld`), so it cannot call anything M-only.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use abi::ReasonCode;
use monitor::parse::MAX_REQ;

use crate::fixtures::{case_request, verdict_name, CASE_ATTACK, CASE_BENIGN, SECRET};
use crate::pmp;
use crate::simmediate::{self, MEDIATE_OP};
use crate::simtrap::{self, FR_A0, FR_A1};
use crate::uart;

/// Endpoint -> M: "frame `a0` dropped, reason `a1`".
const EP_DROP: u32 = 0x20;
/// Endpoint -> M: "stream finished; saw `a0` frames, dropped `a1`".
const EP_DONE: u32 = 0x21;

// --- U-side layout inside SHARED_REQ (U has RW on the whole page) ----------
const SCRATCH_OFF: usize = 0xA00; // deframe scratch [0xA00, 0xA00+MAX_FRAME)
const _: () = assert!(MAX_REQ <= 0x200); // request slot [0, MAX_REQ) below the resp slot
const _: () = assert!(SCRATCH_OFF + wire::MAX_FRAME <= 0xE00); // leaves U stack room below 0x1000

/// SERIAL_IN: `[len:u32][bytes]`.
const SERIAL_DATA_OFF: usize = 4;
const SERIAL_CAP: usize = pmp::SERIAL_IN_SIZE as usize - SERIAL_DATA_OFF;

// ===========================================================================
// U-mode half: the Endpoint compartment itself.
// ===========================================================================

/// `ecall` with three argument registers; returns (a0, a1).
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

/// The Endpoint's entry (U-mode, linked into the U-executable window). It
/// holds no authority: bytes in, whole frames out, everything else is M's job.
#[no_mangle]
#[link_section = ".utext.ep"]
pub extern "C" fn _uendpoint_entry() -> ! {
    let serial = pmp::SERIAL_IN_BASE as *const u8;
    let req = pmp::SHARED_REQ_BASE as *mut u8;
    // Bounded by the region, whatever the length word claims.
    let total = core::cmp::min(unsafe { read_volatile(serial as *const u32) } as usize, SERIAL_CAP);
    let stream: &[u8] = unsafe { core::slice::from_raw_parts(serial.add(SERIAL_DATA_OFF), total) };
    // U-local scratch (inside U's own RW grant; already zero from boot).
    let scratch: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(req.add(SCRATCH_OFF), wire::MAX_FRAME) };

    let mut pos = 0usize;
    let mut idx = 0u32;
    let mut dropped = 0u32;
    while pos < stream.len() {
        // One frame = bytes up to and including the next 0x00; an unterminated
        // tail is handed over as-is (deframe rejects it: truncated).
        let rest = &stream[pos..];
        let mut n = 0usize;
        while n < rest.len() && rest[n] != 0 {
            n += 1;
        }
        let end = core::cmp::min(n + 1, rest.len());
        pos += end;
        match wire::deframe(&rest[..end], scratch) {
            Ok(payload) => {
                let len = core::cmp::min(payload.len(), MAX_REQ);
                let mut i = 0usize;
                while i < len {
                    unsafe { write_volatile(req.add(i), payload[i]) };
                    i += 1;
                }
                // Relay to M. The verdict is M's; the Endpoint just carries on.
                unsafe { ecall(MEDIATE_OP, 0, len as u32) };
            }
            Err(e) => {
                dropped += 1;
                unsafe { ecall(EP_DROP, idx, e as u32) };
            }
        }
        idx += 1;
    }
    unsafe { ecall(EP_DONE, idx, dropped) };
    loop {}
}

// ===========================================================================
// M-side half: the seeded stream, the per-frame plan, the ecall handler.
// ===========================================================================

#[derive(Copy, Clone)]
enum Expect {
    /// Must reach `mediate` with this verdict.
    Verdict(ReasonCode),
    /// Must be dropped by the Endpoint with this `wire::DropReason` ordinal.
    Drop(wire::DropReason),
}

/// The six seeded frames, in stream order. Frame kinds:
///  0 valid benign request              -> relayed, ALLOW (parity with host/QEMU)
///  1 benign request, wrong CRC         -> DROPPED (Crc)
///  2 valid frame, garbage inner (bad request) -> relayed, DENY_MALFORMED
///  3 valid wrong-host attack request   -> relayed, DENY_ARG
///  4 COBS-invalid frame                -> DROPPED (Cobs)
///  5 valid benign frame, delimiter lost (truncated tail) -> DROPPED (Cobs)
const PLAN: [Expect; 6] = [
    Expect::Verdict(ReasonCode::Allow),
    Expect::Drop(wire::DropReason::Crc),
    Expect::Verdict(ReasonCode::DenyMalformed),
    Expect::Verdict(ReasonCode::DenyArg),
    Expect::Drop(wire::DropReason::Cobs),
    Expect::Drop(wire::DropReason::Cobs),
];

/// Garbage inner payload of frame 2: deframes cleanly, is not a request.
const GARBAGE: [u8; 5] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00];

/// The inner request M expects the Endpoint to have relayed for frame `idx`
/// (parity oracle: the very fixtures the host/QEMU demos mediate).
fn expected_inner(idx: u32, buf: &mut [u8; MAX_REQ]) -> usize {
    let (src, n): (&[u8], usize) = match idx {
        2 => (&GARBAGE, GARBAGE.len()),
        3 => {
            let r = case_request(CASE_ATTACK);
            buf.copy_from_slice(&r.bytes);
            return r.len;
        }
        _ => {
            let r = case_request(CASE_BENIGN);
            buf.copy_from_slice(&r.bytes);
            return r.len;
        }
    };
    buf.iter_mut().zip(src.iter()).for_each(|(d, s)| *d = *s);
    n
}

static mut NEXT_IDX: u32 = 0;
static mut RELAYED: u32 = 0;
static mut DROPPED: u32 = 0;
static mut FAILED: bool = false;

fn fail() {
    unsafe { *addr_of_mut!(FAILED) = true };
}

/// Append one framed message at `at` in SERIAL_IN's data area (volatile stores).
fn put_bytes(at: usize, bytes: &[u8]) -> usize {
    let base = (pmp::SERIAL_IN_BASE as usize + SERIAL_DATA_OFF) as *mut u8;
    let mut n = at;
    for &b in bytes {
        if n < SERIAL_CAP {
            unsafe { write_volatile(base.add(n), b) };
            n += 1;
        } else {
            fail(); // stream does not fit: harness bug, fail closed
        }
    }
    n
}

/// Seed SERIAL_IN with the six frames of `PLAN`; returns the stream length.
fn seed_serial_in() -> usize {
    let mut f = [0u8; wire::MAX_FRAME];
    let mut at = 0usize;

    // 0: valid benign.
    let benign = case_request(CASE_BENIGN);
    let n = wire::frame(&benign.bytes[..benign.len], &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n]);

    // 1: benign with a deliberately wrong CRC (COBS stays well-formed, so the
    // ONLY thing wrong is the checksum): ver ++ payload ++ (crc ^ 1).
    let mut pre = [0u8; 1 + MAX_REQ + 4];
    pre[0] = wire::WIRE_VER;
    pre[1..1 + benign.len].copy_from_slice(&benign.bytes[..benign.len]);
    let crc = wire::crc32(&[&pre[..1 + benign.len]]) ^ 1;
    pre[1 + benign.len..5 + benign.len].copy_from_slice(&crc.to_le_bytes());
    let w = wire::cobs_encode(&pre[..5 + benign.len], &mut f).unwrap_or(0);
    f[w] = 0;
    at = put_bytes(at, &f[..w + 1]);

    // 2: valid frame around a garbage inner payload.
    let n = wire::frame(&GARBAGE, &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n]);

    // 3: valid wrong-host attack request.
    let attack = case_request(CASE_ATTACK);
    let n = wire::frame(&attack.bytes[..attack.len], &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n]);

    // 4: COBS-invalid (code 9 promises 8 more bytes; only 2 follow).
    at = put_bytes(at, &[0x09, 0x01, 0x02, 0x00]);

    // 5: a valid benign frame with its trailing delimiter lost (truncated tail).
    let n = wire::frame(&benign.bytes[..benign.len], &mut f).unwrap_or(0);
    at = put_bytes(at, &f[..n.saturating_sub(1)]);

    unsafe { write_volatile(pmp::SERIAL_IN_BASE as *mut u32, at as u32) };
    at
}

fn drop_name(r: u32) -> &'static str {
    match r {
        x if x == wire::DropReason::Cobs as u32 => "COBS",
        x if x == wire::DropReason::Crc as u32 => "CRC",
        x if x == wire::DropReason::Version as u32 => "VERSION",
        x if x == wire::DropReason::TooLong as u32 => "TOO_LONG",
        _ => "EMPTY",
    }
}

fn frame_line(idx: u32, tail: &str) {
    uart::puts("endpoint: frame");
    uart::put_u32_dec(idx);
    uart::puts("=");
    uart::puts(tail);
    uart::puts("\n");
}

fn count_line(name: &str, v: u32) {
    uart::puts("endpoint: ");
    uart::puts(name);
    uart::puts("=");
    uart::put_u32_dec(v);
    uart::puts("\n");
}

/// The Endpoint relayed a frame: M mediates it (and ONLY it).
fn on_mediate(ptr: u32, len: u32) -> (u8, u32) {
    let idx = unsafe { *addr_of!(NEXT_IDX) };
    unsafe { *addr_of_mut!(NEXT_IDX) = idx + 1 };
    let want = match PLAN.get(idx as usize) {
        Some(Expect::Verdict(v)) => *v,
        _ => {
            // Plan says this frame must never reach M (or there is no such
            // frame): refuse to mediate it, fail closed.
            fail();
            frame_line(idx, "UNEXPECTED-RELAY");
            return (ReasonCode::ErrInternal as u8, 0);
        }
    };
    // Parity: the relayed bytes are exactly the fixture the host/QEMU demos use.
    let mut exp = [0u8; MAX_REQ];
    let exp_len = expected_inner(idx, &mut exp);
    let got: &[u8] = unsafe { core::slice::from_raw_parts(simmediate::shared_base(), MAX_REQ) };
    if ptr != 0 || len as usize != exp_len || got.get(..exp_len) != exp.get(..exp_len) {
        fail();
        frame_line(idx, "RELAY-MISMATCH");
    }
    unsafe { *addr_of_mut!(RELAYED) += 1 };
    let (status, resp_len) = simmediate::dispatch_mediate(ptr as usize, len as usize);
    frame_line(idx, verdict_name(status));
    if status != want as u8 {
        fail();
    }
    (status, resp_len as u32)
}

/// The Endpoint dropped a frame: count it; M mediates nothing.
fn on_drop(idx: u32, reason: u32) {
    let seen = unsafe { *addr_of!(NEXT_IDX) };
    unsafe { *addr_of_mut!(NEXT_IDX) = seen + 1 };
    unsafe { *addr_of_mut!(DROPPED) += 1 };
    uart::puts("endpoint: frame");
    uart::put_u32_dec(idx);
    uart::puts("=DROPPED reason=");
    uart::puts(drop_name(reason));
    uart::puts("\n");
    let ok = idx == seen
        && matches!(PLAN.get(idx as usize), Some(Expect::Drop(r)) if *r as u32 == reason);
    if !ok {
        fail();
    }
}

fn on_done(frames: u32, u_dropped: u32) -> ! {
    let (next, relayed, dropped) =
        unsafe { (*addr_of!(NEXT_IDX), *addr_of!(RELAYED), *addr_of!(DROPPED)) };
    let sink_calls = simmediate::egress_calls();
    count_line("frames", next);
    count_line("relayed", relayed);
    count_line("dropped", dropped);
    count_line("sink-calls", sink_calls);
    let leak = simmediate::shared_page_contains(SECRET);
    uart::puts(if leak { "endpoint: secret=LEAK\n" } else { "endpoint: secret=absent\n" });
    // Only the benign frame (idx 0) may drive the sink; M and the Endpoint
    // must agree on every count.
    let want_relayed = PLAN.iter().filter(|e| matches!(e, Expect::Verdict(_))).count() as u32;
    let want_dropped = PLAN.len() as u32 - want_relayed;
    if frames != next
        || u_dropped != dropped
        || next != PLAN.len() as u32
        || relayed != want_relayed
        || dropped != want_dropped
        || sink_calls != 1
        || leak
        || unsafe { *addr_of!(FAILED) }
    {
        uart::puts("ENDPOINT-FAIL\n");
    } else {
        uart::puts("ENDPOINT-DONE\n");
    }
    simtrap::halt();
}

/// Endpoint-image ecall dispatch (called from `sim_trap_rust`). True if handled.
pub fn handle_ecall(frame: *mut u32, a7: u32) -> bool {
    let (a0, a1) = unsafe { (*frame.add(FR_A0), *frame.add(FR_A1)) };
    match a7 {
        MEDIATE_OP => {
            let (status, resp_len) = on_mediate(a0, a1);
            unsafe {
                *frame.add(FR_A0) = status as u32;
                *frame.add(FR_A1) = resp_len;
            }
            true
        }
        EP_DROP => {
            on_drop(a0, a1);
            true
        }
        EP_DONE => on_done(a0, a1),
        _ => false,
    }
}

/// Entry point for the `endpoint` scenario (called from `main` on the sim image
/// built with the `endpoint` feature). Never returns.
pub fn run_endpoint_demo() -> ! {
    simtrap::install_trap();
    // Seed the mock serial source BEFORE the PMP lock: entry 3 is locked `R--`
    // and `L=1` extends it to M, so after the lock nobody (M included) can write
    // SERIAL_IN — the Endpoint's input is immutable once it starts.
    let _ = seed_serial_in();
    pmp::lock_regions();
    simmediate::init_monitor_state();
    uart::puts("ENDPOINT-ARMED\n");
    simtrap::drop_to_user(_uendpoint_entry as *const () as usize as u32, pmp::SHARED_REQ_END);
}
