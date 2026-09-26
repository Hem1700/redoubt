//! M-mode trap trampoline: the ONLY `unsafe` module in the Redoubt
//! workspace's logic path.
//!
//! # Where this lives and why (RULING R12)
//! The Phase-1 plan called for `crates/monitor/src/arch.rs`, but the
//! `monitor` logic crate is `#![forbid(unsafe_code)]` and `forbid` cannot
//! be locally overridden by `#[allow(unsafe_code)]`. A trap trampoline is
//! irreducibly unsafe: it programs `mtvec`, saves/restores the integer
//! register file across a trap in raw assembly, reads/writes machine CSRs,
//! and touches CLINT MMIO. So the trampoline lives HERE, in the bare-metal
//! binary crate (which already uses `unsafe` for boot asm and the UART/
//! finisher MMIO and carries no `forbid`), and it CALLS the 100%-safe
//! `monitor::mediate` pipeline. The logic crate stays entirely safe.
//!
//! # Single-threaded soundness of the mutable statics
//! There is exactly one hart and the trap handler runs to completion with
//! machine interrupts masked (the hardware clears `mstatus.MIE` on trap
//! entry and we never set it inside the handler — Review-Focus 7). No two
//! flows ever touch `SHARED_REQ`, `RESP_BUF`, `SESSIONS`, `SINK`, or
//! `AUDIT` concurrently, and the handler is not re-entrant, so the
//! `&mut`/`&` references we form from these statics inside the handler are
//! never aliased. `addr_of!`/`addr_of_mut!` are used (never a direct `&`/
//! `&mut` on a `static mut`) to satisfy modern rustc/clippy.

use core::ptr::{addr_of, addr_of_mut};

use abi::ReasonCode;
use monitor::cap::{self, Cap, CapType, Session, Sessions};
use monitor::egress::{EgressSink, Response, RESP_BODY_MAX};
use monitor::flow::FlowRule;
use monitor::parse::MAX_REQ;
use monitor::predicate::{Args, Clause, ConstPool, FieldSel, Op, PoolEntry};
use monitor::{audit::Audit, mediate, Policy};

use crate::uart;

/// The MEDIATE opcode the lower-privilege caller passes in `a7`
/// (`abi::Opcode::Mediate as usize`). Kept as a plain constant so the
/// `ecall` inline-asm can load it with `li`.
const MEDIATE: usize = abi::Opcode::Mediate as u32 as usize;

// ---------------------------------------------------------------------------
// Trap frame layout
//
// The assembly trampoline saves x1..x31 into words 0..30 (x_N at word N-1),
// then `mepc` at word 31 and `mstatus` at word 32. The Rust handler indexes
// the frame it is handed by these word offsets.
// ---------------------------------------------------------------------------
const FR_A0: usize = 9; // x10
const FR_A1: usize = 10; // x11
const FR_A7: usize = 16; // x17
const FR_MEPC: usize = 31;

// ---------------------------------------------------------------------------
// M-mode trap stack (Review-Focus 7 / brief §1)
//
// The handler switches to this stack via `mscratch` on entry so a trap can
// never run on a caller stack of unknown validity. A guard word is reserved
// at the LOW end (`STACK.0[0]`): stack grows downward toward it, so a
// touched guard means overflow. The REAL PMP-backed stack guard is Phase-2
// V3; here the word is only reserved and documented.
// ---------------------------------------------------------------------------
// mediate is stack-hungry in a debug (unoptimized) build: a 512-byte
// `scratch`, a `Response` and a `ResponseView` each carrying a 512-byte body,
// plus the by-value `(ReasonCode, ResponseView)` return, are all live across a
// deep call chain with no slot reuse. 128 KiB gives generous headroom over
// the measured need; RAM is 8 MiB so this is cheap.
const TRAP_STACK_WORDS: usize = 32768; // 128 KiB

#[repr(align(16))]
struct TrapStack([u32; TRAP_STACK_WORDS]);

static mut TRAP_STACK: TrapStack = TrapStack([0; TRAP_STACK_WORDS]);

/// One-past-the-end (top) of the trap stack, 16-byte aligned. Stack grows
/// down from here; word 0 is the reserved guard.
fn trap_stack_top() -> usize {
    // Address arithmetic only; never dereferences the static.
    unsafe { addr_of!(TRAP_STACK.0).cast::<u32>().add(TRAP_STACK_WORDS) as usize }
}

// ---------------------------------------------------------------------------
// CLINT (QEMU `virt`) — machine timer, used only by Scenario B.
// ---------------------------------------------------------------------------
const MTIMECMP_LO: *mut u32 = 0x0200_4000 as *mut u32;
const MTIMECMP_HI: *mut u32 = 0x0200_4004 as *mut u32;

/// QEMU `virt` `sifive_test` finisher (same device `main.rs` uses). Writing
/// 0x3333 exits QEMU nonzero; used here for the fail-closed halt on an
/// unexpected M-mode exception.
const FINISHER: *mut u32 = 0x0010_0000 as *mut u32;

// ---------------------------------------------------------------------------
// Shared / owned statics. See the module-level single-threaded soundness
// note for why the handler's references to these are never aliased.
// ---------------------------------------------------------------------------

/// Models the SHARED_REQ region (Phase-2 SoC address `0x4000_0000`). In this
/// Phase-1 QEMU image, with no PMP yet and everything linked at RAM base,
/// it is simply a static byte buffer in RAM (per the plan).
static mut SHARED_REQ: [u8; MAX_REQ] = [0; MAX_REQ];

/// Where the handler copies the `ResponseView` body so the caller can read
/// it back after `mret` (Phase-1 stand-in for a response ring).
static mut RESP_BUF: [u8; RESP_BODY_MAX] = [0; RESP_BODY_MAX];

/// Session table, seeded once by `init`.
static mut SESSIONS: Option<Sessions> = None;

/// Audit hash-chain, seeded once by `init`.
static mut AUDIT: Option<Audit> = None;

/// The concrete in-image egress sink (see `ImageSink`).
static mut SINK: ImageSink = ImageSink::new();

/// Set by the timer-interrupt arm of the handler in Scenario B; proves the
/// armed timer actually became pending and was serviced (after `mret`),
/// which is exactly the interrupt that stayed masked during the handler.
static mut TIMER_FIRED: bool = false;

// ---------------------------------------------------------------------------
// In-image egress sink.
//
// `egress::MockSink` is `#[cfg(test)]`-private to the logic crate, so this
// is a real `impl EgressSink` here (analogous to the Task-14 host demo's
// `RecordingSink`): it records the exact outbound bytes a real HTTP sink
// would transmit (host + path + any injected secret) and returns a fixed
// body. The injected secret goes ONLY into the outbound record, never the
// returned body (Review-Focus 5, inject-only).
// ---------------------------------------------------------------------------
const OUTBOUND_MAX: usize = 256;

struct ImageSink {
    outbound: [u8; OUTBOUND_MAX],
    outbound_len: usize,
    called: bool,
}

impl ImageSink {
    const fn new() -> Self {
        Self { outbound: [0; OUTBOUND_MAX], outbound_len: 0, called: false }
    }

    fn last_outbound(&self) -> &[u8] {
        &self.outbound[..self.outbound_len]
    }

    fn record(&mut self, bytes: &[u8]) {
        let start = self.outbound_len;
        let remaining = OUTBOUND_MAX - start;
        let n = core::cmp::min(bytes.len(), remaining);
        self.outbound[start..start + n].copy_from_slice(&bytes[..n]);
        self.outbound_len += n;
    }
}

impl EgressSink for ImageSink {
    fn perform(
        &mut self,
        _cap: &Cap,
        args: &Args,
        secret: Option<&[u8]>,
    ) -> Result<Response, ReasonCode> {
        self.called = true;
        // Fail closed: no structured target, no dial (Review-Focus 9).
        let parts = args.url_parts().ok_or(ReasonCode::ErrInternal)?;
        self.outbound_len = 0;
        self.record(parts.host);
        self.record(parts.path);
        if let Some(s) = secret {
            self.record(s); // outbound only — never in the returned body
        }
        Ok(Response::with_body(ReasonCode::Allow, abi::Label::UNTRUSTED, b"OK-RESPONSE-BODY"))
    }
}

// ---------------------------------------------------------------------------
// Phase-1 policy fixture — SAME shape as the Task-14 host demo tests, so the
// QEMU verdicts are parity-by-construction with the host verdicts.
// ---------------------------------------------------------------------------
const SECRET: &[u8] = b"API_KEY_SECRET_VALUE";
static API_HOSTS: [&[u8]; 1] = [b"api.example.com"];
static CLAUSES_HOST_ONLY: [Clause; 1] =
    [Clause { field: FieldSel::URL_HOST, op: Op::HostInSet, operand: 0 }];
static PRED_SETS: [&[Clause]; 1] = [&CLAUSES_HOST_ONLY];
static FLOWS: [FlowRule; 1] = [FlowRule {
    inject: Some(0),
    deny_secret_to_public: true,
    result_label: abi::Label::UNTRUSTED,
}];
static SECRETS: [&[u8]; 1] = [SECRET];

fn build_policy() -> Policy<'static> {
    let pool = ConstPool::new().with(0, PoolEntry::StrSet(&API_HOSTS));
    Policy { preds: &PRED_SETS, flows: &FLOWS, secrets: &SECRETS, pool }
}

fn build_sessions() -> Sessions {
    let empty = Cap {
        ctype: CapType::Empty as u8,
        rights: 0,
        tool_id: 0,
        pred_ref: 0,
        flow_ref: 0,
        secret_ref: 0,
        aux: 0,
        epoch: 1,
        _pad: 0,
    };
    let mut cspace = [empty; cap::CSPACE_LEN];
    // Live Net cap at handle 3, tool_id 0x1000 (matches the host demo).
    cspace[3] = Cap {
        ctype: CapType::Net as u8,
        rights: 0,
        tool_id: 0x1000,
        pred_ref: 0,
        flow_ref: 0,
        secret_ref: 0,
        aux: 0,
        epoch: 1,
        _pad: 0,
    };
    let mut sessions = Sessions::default();
    let _ = sessions.install(1, Session { epoch: 1, cspace });
    sessions
}

// ---------------------------------------------------------------------------
// Wire-format request builder (safe; identical layout to the host demo).
// ---------------------------------------------------------------------------
struct ReqBuf {
    bytes: [u8; MAX_REQ],
    len: usize,
}

impl ReqBuf {
    fn push(&mut self, b: u8) {
        if self.len < MAX_REQ {
            self.bytes[self.len] = b;
            self.len += 1;
        }
    }
    fn extend(&mut self, s: &[u8]) {
        for &b in s {
            self.push(b);
        }
    }
    fn u16(&mut self, v: u16) {
        self.extend(&v.to_le_bytes());
    }
}

/// Build one request. `url` is `(scheme, host, port, path)`; `method` is an
/// optional BYTES arg; `secret_label` adds a one-byte SECRET in_label.
fn build_request(
    session: u16,
    cap_handle: u16,
    tool: u16,
    url: (u8, &[u8], u16, &[u8]),
    method: Option<&[u8]>,
    secret_label: bool,
) -> ReqBuf {
    let mut r = ReqBuf { bytes: [0; MAX_REQ], len: 0 };
    let n_args: u8 = 1 + method.is_some() as u8;
    let labels_len: u16 = secret_label as u16;

    // Header (16 bytes).
    r.extend(&abi::MAGIC.to_le_bytes());
    r.u16(session);
    r.u16(1); // req_id
    r.u16(cap_handle);
    r.u16(tool);
    r.push(n_args);
    r.push(0); // reserved
    r.u16(labels_len);

    // URL TLV (tag 0x01): scheme, host_len, host, port, path_len, path.
    let (scheme, host, port, path) = url;
    let url_val_len = 1 + 2 + host.len() + 2 + 2 + path.len();
    r.push(0x01);
    r.u16(url_val_len as u16);
    r.push(scheme);
    r.u16(host.len() as u16);
    r.extend(host);
    r.u16(port);
    r.u16(path.len() as u16);
    r.extend(path);

    // Optional METHOD arg (tag 0x05, BYTES).
    if let Some(m) = method {
        r.push(0x05);
        r.u16(m.len() as u16);
        r.extend(m);
    }

    // Trailing in_labels blob.
    if secret_label {
        r.push(abi::Label::SECRET.0);
    }
    r
}

// ---------------------------------------------------------------------------
// CSR / MMIO helpers (unsafe, confined here).
// ---------------------------------------------------------------------------
#[inline]
fn write_mtvec(handler: usize) {
    // Direct mode: low 2 bits = 0b00, so `mtvec = handler & !0b11`.
    unsafe { core::arch::asm!("csrw mtvec, {0}", in(reg) handler, options(nomem, nostack)) };
}

#[inline]
fn write_mscratch(v: usize) {
    unsafe { core::arch::asm!("csrw mscratch, {0}", in(reg) v, options(nomem, nostack)) };
}

#[inline]
fn read_mcause() -> usize {
    let v: usize;
    unsafe { core::arch::asm!("csrr {0}, mcause", out(reg) v, options(nomem, nostack)) };
    v
}

/// Seed the runtime statics and install the trap vector. Must run once,
/// before any `ecall`.
pub fn init() {
    unsafe {
        *addr_of_mut!(SESSIONS) = Some(build_sessions());
        *addr_of_mut!(AUDIT) = Some(Audit::default());
    }
    write_mscratch(trap_stack_top());
    write_mtvec(trap_entry as *const () as usize);
}

// ---------------------------------------------------------------------------
// The assembly trampoline.
//
// Interrupt masking (Review-Focus 7): a trap ENTRY clears `mstatus.MIE` in
// hardware (saving the old value in MPIE). We never set MIE inside the
// handler, so machine interrupts stay masked for the entire window — a
// timer that becomes pending mid-handler cannot preempt us and corrupt the
// frame or the verdict. `mret` restores MIE from MPIE on the way out.
//
// The frame saves the full x1..x31 register file plus mepc and mstatus, so
// the interrupted context is preserved byte-for-byte regardless of which
// instruction the (Scenario B) timer interrupt lands on.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    "
    .section .text
    .globl trap_entry
    .align 4
trap_entry:
    csrrw sp, mscratch, sp        # sp -> trap stack top, mscratch -> caller sp
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
    csrr  t0, mscratch            # caller sp
    sw    t0, 4(sp)               # save as x2 slot
    csrr  t0, mepc
    sw    t0, 124(sp)
    csrr  t0, mstatus
    sw    t0, 128(sp)
    mv    a0, sp                  # &mut frame
    call  trap_rust
    lw    t0, 124(sp)             # (possibly advanced) mepc
    csrw  mepc, t0
    lw    t0, 128(sp)
    csrw  mstatus, t0
    addi  t0, sp, 144             # restore mscratch = trap stack top
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
    lw    x2,   4(sp)             # caller sp last
    mret
    "
);

extern "C" {
    fn trap_entry();
}

/// Rust side of the trap. `frame` points at the saved register file on the
/// trap stack. Runs with machine interrupts masked; never panics.
///
/// # Safety
/// Called only from `trap_entry`, which hands a valid, uniquely-owned
/// pointer to the current frame. The single-hart, non-reentrant,
/// interrupts-masked execution model (see the module note) means the
/// static references formed here are never aliased.
#[no_mangle]
extern "C" fn trap_rust(frame: *mut u32) {
    let cause = read_mcause();

    // Interrupt (high bit set): Scenario B's machine timer. Silence it so it
    // cannot refire, record that it fired, and return WITHOUT advancing mepc
    // (an interrupt re-executes the interrupted instruction).
    if cause & (1usize << (usize::BITS - 1)) != 0 {
        let code = cause & !(1usize << (usize::BITS - 1));
        if code == 7 {
            unsafe {
                // Disarm: mtimecmp = u64::MAX (write hi first to avoid a
                // spurious low-half compare), and clear mie.MTIE.
                core::ptr::write_volatile(MTIMECMP_HI, 0xFFFF_FFFF);
                core::ptr::write_volatile(MTIMECMP_LO, 0xFFFF_FFFF);
                core::arch::asm!("csrc mie, {0}", in(reg) 1usize << 7, options(nomem, nostack));
                *addr_of_mut!(TIMER_FIRED) = true;
            }
        }
        return;
    }

    // Exception. Only an environment call from U(8)/S(9)/M(11) is a legitimate
    // trap into this trampoline. ANY other exception cause (illegal
    // instruction, access fault — the latter arrives once Phase-2 adds PMP) is
    // an unexpected fault inside the M-mode TCB: it is unrecoverable, so we
    // FAIL CLOSED. Silently treating it as a DENY_MALFORMED "ecall" and
    // resuming at mepc+4 would be a fail-open recovery (resuming mid-fault into
    // an unknown state), contrary to the project's fail-closed principle. We
    // instead signal failure on the sifive_test finisher (0x3333, mirroring the
    // main.rs panic-handler convention) and halt forever — never advancing mepc,
    // never returning.
    if !matches!(cause, 8 | 9 | 11) {
        unsafe {
            core::ptr::write_volatile(FINISHER, 0x3333);
        }
        loop {
            unsafe { core::arch::asm!("wfi") };
        }
    }

    // Read the ecall's ABI regs out of the saved frame.
    let (a7, a0, a1) = unsafe {
        (
            *frame.add(FR_A7) as usize,
            *frame.add(FR_A0) as usize,
            *frame.add(FR_A1) as usize,
        )
    };

    let (status, resp_len) = if a7 == MEDIATE {
        dispatch_mediate(a0, a1)
    } else {
        (ReasonCode::DenyMalformed as u8, 0usize)
    };

    unsafe {
        *frame.add(FR_A0) = status as u32;
        *frame.add(FR_A1) = resp_len as u32;
        // Advance past the 4-byte ecall so mret resumes the instruction
        // after it (not an infinite ecall loop).
        *frame.add(FR_MEPC) = frame.add(FR_MEPC).read().wrapping_add(4);
    }
}

/// Run the safe `monitor::mediate` pipeline against `SHARED_REQ[ptr..ptr+len]`
/// and copy the response body into `RESP_BUF`. Returns `(status_u8, resp_len)`.
fn dispatch_mediate(ptr: usize, len: usize) -> (u8, usize) {
    // Immutable view of the shared region; mutable refs to the owned sink /
    // audit / session table. Non-reentrant + interrupts masked => not aliased.
    let shared: &[u8] = unsafe { &*addr_of!(SHARED_REQ) };

    let sessions = match unsafe { (*addr_of!(SESSIONS)).as_ref() } {
        Some(s) => s,
        None => return (ReasonCode::ErrInternal as u8, 0),
    };
    let audit = match unsafe { (*addr_of_mut!(AUDIT)).as_mut() } {
        Some(a) => a,
        None => return (ReasonCode::ErrInternal as u8, 0),
    };
    let sink: &mut ImageSink = unsafe { &mut *addr_of_mut!(SINK) };
    let policy = build_policy();

    let (rc, resp) =
        mediate(shared, ptr, len, 0..MAX_REQ, sessions, &policy, sink, audit);

    // Copy the response body somewhere the caller can read it post-mret.
    let body = resp.bytes();
    let n = core::cmp::min(body.len(), RESP_BODY_MAX);
    unsafe {
        let dst = addr_of_mut!(RESP_BUF) as *mut u8;
        core::ptr::copy_nonoverlapping(body.as_ptr(), dst, n);
    }
    (rc as u8, n)
}

/// Issue the MEDIATE `ecall` and return `(status_u8, resp_len)`.
///
/// # Privilege of the caller (S-mode vs M-mode fallback)
/// The brief PREFERS dropping to S-mode so the `ecall` crosses the real
/// privilege boundary (mcause 9). On QEMU `virt` (riscv32) with the 16 PMP
/// entries the machine implements but NONE configured, an S/U-mode access
/// fails closed — so dropping to S-mode without first programming PMP faults
/// on the S stub's very first fetch. PMP is explicitly Phase-2 (V3) work and
/// out of scope here. Per the brief's escape hatch we therefore take the
/// documented M-mode fallback: an M-mode `ecall` (mcause 11), which the
/// handler accepts identically. The exact origin privilege is refined by
/// Phase-2's Warden (V4).
fn mediate_ecall(ptr: usize, len: usize) -> (u8, usize) {
    let mut a0 = ptr;
    let mut a1 = len;
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0,
            inout("a1") a1,
            in("a7") MEDIATE,
            options(nostack),
        );
    }
    (a0 as u8, a1)
}

/// Copy `req` into `SHARED_REQ` and mediate it. Returns `(status, resp_len)`.
fn run_request(req: &ReqBuf) -> (u8, usize) {
    unsafe {
        let dst = addr_of_mut!(SHARED_REQ) as *mut u8;
        core::ptr::copy_nonoverlapping(req.bytes.as_ptr(), dst, req.len);
    }
    mediate_ecall(0, req.len)
}

fn outbound_contains(needle: &[u8]) -> bool {
    let out: &ImageSink = unsafe { &*addr_of!(SINK) };
    out.last_outbound().windows(needle.len()).any(|w| w == needle)
}

fn response_contains(needle: &[u8], resp_len: usize) -> bool {
    let full: &[u8] = unsafe { &*addr_of!(RESP_BUF) };
    full[..resp_len].windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Timer arming (Scenario B).
// ---------------------------------------------------------------------------
fn arm_timer_and_enable() {
    unsafe {
        // mtimecmp = 0 => immediately <= mtime => MTIP pending.
        core::ptr::write_volatile(MTIMECMP_HI, 0);
        core::ptr::write_volatile(MTIMECMP_LO, 0);
        // Enable machine timer interrupt (mie.MTIE, bit 7) and the global
        // machine-interrupt enable (mstatus.MIE, bit 3). With both set, the
        // pending timer will fire the instant `mret` restores MIE=1 after
        // the mediate ecall handler returns — NOT during it.
        core::arch::asm!("csrs mie, {0}", in(reg) 1usize << 7, options(nomem, nostack));
        core::arch::asm!("csrs mstatus, {0}", in(reg) 1usize << 3, options(nomem, nostack));
    }
}

fn disable_global_interrupts() {
    unsafe {
        core::arch::asm!("csrc mstatus, {0}", in(reg) 1usize << 3, options(nomem, nostack));
    }
}

// ---------------------------------------------------------------------------
// Scenario driver. Prints one `mediate: <name>=<verdict>` line per scenario
// and returns true iff every scenario matched its expected verdict.
// ---------------------------------------------------------------------------
const ALLOW: u8 = ReasonCode::Allow as u8;
const DENY_ARG: u8 = ReasonCode::DenyArg as u8;
const DENY_FLOW: u8 = ReasonCode::DenyFlow as u8;

fn verdict_name(status: u8) -> &'static str {
    match status {
        x if x == ALLOW => "ALLOW",
        x if x == DENY_ARG => "DENY_ARG",
        x if x == DENY_FLOW => "DENY_FLOW",
        x if x == ReasonCode::DenyMalformed as u8 => "DENY_MALFORMED",
        x if x == ReasonCode::DenyRevoked as u8 => "DENY_REVOKED",
        x if x == ReasonCode::DenyTool as u8 => "DENY_TOOL",
        x if x == ReasonCode::DenyNoCap as u8 => "DENY_NOCAP",
        x if x == ReasonCode::ErrEgress as u8 => "ERR_EGRESS",
        x if x == ReasonCode::ErrInternal as u8 => "ERR_INTERNAL",
        _ => "UNKNOWN",
    }
}

fn print_verdict(name: &str, status: u8) {
    uart::puts("mediate: ");
    uart::puts(name);
    uart::puts("=");
    uart::puts(verdict_name(status));
    uart::puts("\n");
}

/// Run the four Phase-1 scenarios. Returns true iff all pass.
pub fn run_demo() -> bool {
    let mut ok = true;

    // -- Scenario A.1: benign -> ALLOW, secret injected outbound, absent
    //    from the response body. ---------------------------------------
    let req = build_request(1, 3, 0x1000, (1, b"api.example.com", 443, b"/x"), None, false);
    let (status, resp_len) = run_request(&req);
    print_verdict("benign", status);
    let secret_out = outbound_contains(SECRET);
    let secret_in_resp = response_contains(SECRET, resp_len);
    if secret_out {
        uart::puts("mediate: benign-secret=outbound-present\n");
    } else {
        uart::puts("mediate: benign-secret=outbound-MISSING\n");
    }
    if secret_in_resp {
        uart::puts("mediate: benign-secret=response-LEAK\n");
    } else {
        uart::puts("mediate: benign-secret=response-absent\n");
    }
    ok &= status == ALLOW && secret_out && !secret_in_resp;

    // -- Scenario A.2: wrong host -> DENY_ARG (dies at stage 4). --------
    let req = build_request(1, 3, 0x1000, (1, b"evil.tld", 443, b"/steal"), Some(b"POST"), false);
    let (status, _) = run_request(&req);
    print_verdict("attack", status);
    ok &= status == DENY_ARG;

    // -- Scenario A.3: SECRET input to public sink -> DENY_FLOW (stage 5).
    let req = build_request(1, 3, 0x1000, (1, b"api.example.com", 443, b"/x"), None, true);
    let (status, _) = run_request(&req);
    print_verdict("flow", status);
    ok &= status == DENY_FLOW;

    // -- Scenario B: interrupt masking (Review-Focus 7). ---------------
    // Arm the CLINT timer so MTIP is pending, enable machine interrupts,
    // then run a benign mediate ecall. Because trap entry masks MIE and the
    // handler never re-enables it, the pending timer cannot preempt the
    // handler; it fires only after `mret` restores MIE. A correct ALLOW
    // verdict + an intact return path proves the frame survived.
    unsafe {
        *addr_of_mut!(TIMER_FIRED) = false;
    }
    arm_timer_and_enable();
    let req = build_request(1, 3, 0x1000, (1, b"api.example.com", 443, b"/x"), None, false);
    let (status, _) = run_request(&req);
    disable_global_interrupts();
    let fired = unsafe { *addr_of!(TIMER_FIRED) };
    let irq_ok = status == ALLOW && fired;
    if irq_ok {
        uart::puts("mediate: irq-frame=OK\n");
    } else {
        uart::puts("mediate: irq-frame=FAIL\n");
    }
    ok &= irq_ok;

    ok
}
