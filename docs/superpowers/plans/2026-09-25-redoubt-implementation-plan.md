# Redoubt v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working Redoubt v1: a deterministic, PMP-isolated reference monitor for AI-agent tool calls that runs first in simulation (host + QEMU + Verilator) and finally on a ULX3S FPGA, proving the containment property (a hijacked agent cannot exceed its granted authority).

**Architecture:** A Rust `no_std` M-mode Monitor (the TCB) decides every tool call through six deterministic checks and owns egress and secrets; an S-mode Warden schedules and relays; U-mode compartments do untrusted framing/formatting. Isolation of the TCB is enforced by RISC-V PMP, verified in Verilator. The agent/LLM lives off-device on an untrusted host and talks to Redoubt over a framed serial link.

**Tech Stack:** Rust (stable) `no_std`, target `riscv32imac-unknown-none-elf`; the `riscv` crate for CSR/PMP access; `qemu-system-riscv32` (`virt` machine) for firmware integration; LiteX + VexRiscv (SpinalHDL) + yosys + nextpnr-ecp5 for the SoC; Verilator for RTL-level isolation tests; `openFPGALoader` for the board; `blake2` (no_std) for measured boot and the audit chain; `cargo xtask` for automation.

**Spec:** `docs/architecture/components/` (the 13-chapter manual; index at `components/index.html`) and `docs/design/2026-09-22-redoubt-architecture-v1.md`. This plan argues from those; executors read both. Chapter references below (e.g. "Ch 9 §9.7") point into the manual.

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the spec.

- **ISA / modes:** RV32IMAC; privilege modes M > S > U; isolation via PMP (TOR entries; `Smepmp` preferred, locked `L=1` fallback). Little-endian.
- **Language:** Rust, `#![no_std]` for all firmware crates. Pure-logic modules carry `#![forbid(unsafe_code)]`. Each crate that needs hardware access has exactly **one** module named `arch` holding all `unsafe` (CSR/MMIO/asm), documented. CI runs `cargo-geiger` and fails on `unsafe` outside an `arch` module.
- **TCB budget (CI-gated with `tokei`):** the `monitor` crate ≤ **2,500** lines; the boot ROM ≤ **300** lines. Build fails if exceeded.
- **Monitor runtime discipline (Ch 9 §9.5):** single-threaded, run-to-completion; interrupts masked during a mediation; **no heap on the request path** (the `monitor` crate does not depend on `alloc`); all request-time state is fixed-size.
- **Bounds (Ch 9, Ch 10):** `MAX_REQ = 512` bytes, `MAX_ARGS = 8`, `MAX_CLAUSES = 64`, `CSPACE_LEN = 32`, `MAX_SESSIONS = 8`.
- **Determinism (Ch 2, Ch 9):** the verdict is a pure function of (session state, request bytes). No model, classifier, RNG, clock, or heuristic on the decision path.
- **ABI values (Ch 10) — use exactly:** opcodes `MEDIATE=0x52440001`, `SESSION_OPEN=0x52440010`, `SESSION_REVOKE=0x52440011`, `SESSION_CLOSE=0x52440012`, `ATTEST_READ=0x52440020`. Reason codes `ALLOW=0x00`, `DENY_NO_CAP=0x10`, `DENY_TOOL=0x11`, `DENY_ARG=0x12`, `DENY_FLOW=0x13`, `DENY_MALFORMED=0x14`, `DENY_REVOKED=0x15`, `DENY_QUOTA=0x16`, `ERR_EGRESS=0x20`, `ERR_TIMEOUT=0x21`, `ERR_INTERNAL=0x2F`. Request magic `b"RDBT"` (`0x54424452` LE).
- **Memory map (Ch 7 §7.1 / Ch 4) — FPGA target:** `BROM 0x0000_0000` (M:RX), `MON_CODE/MON_DATA/SECRETS 0x1000_0000` (M-only), `WARDEN 0x2000_0000` (S), `COMPARTMENTS 0x3000_0000` (U), `SHARED_REQ 0x4000_0000` (M+U), `SDRAM 0x8000_0000`, `EGRESS_MMIO 0xF000_0000` (M-only). (QEMU `virt` uses its own map for Phase 0–1; the FPGA map applies from Phase 2.)
- **DMA rule (Ch 4 §4.7):** no DMA-capable master may reach SECRETS/MON_*/WARDEN. In v1 this is enforced by construction (DMA config registers are M-only; the Monitor pins descriptor ranges). IOPMP/RTL gate is later.

## Review Focus

The inputs and failure modes the spec implies that a happy-path test would miss, most-likely-to-bite first. Each line names the condition, the expected behavior, and the task whose test pins it.

1. **Request out of bounds / oversize / truncated:** `ptr..ptr+len` not fully inside SHARED_REQ, `len > MAX_REQ`, `n_args > MAX_ARGS`, or a TypedArg whose declared `len` runs past the buffer → `DENY_MALFORMED`, never a read past the buffer. *(Task 6, Task 12)*
2. **Type-confused argument:** a predicate clause selects `url.host` but the arg at that position is `BYTES`/`INT` → `DENY_MALFORMED`, not a silent pass or coercion. *(Task 9)*
3. **Forged / out-of-range / Empty / stale-epoch handle:** any of these → `DENY_NO_CAP` (Empty/oob/absent) or `DENY_REVOKED` (epoch mismatch); never resolves to a live cap. *(Task 7)*
4. **URL parsing tricks:** `%2e`-encoded host, uppercase host, trailing dot (`api.example.com.`), embedded credentials (`user@evil`), port confusion (`api.example.com:80@evil`) must not pass `HOST_IN_SET{api.example.com}`. The Monitor matches the **typed, host-decoded** field, not re-parsed text. *(Task 9, Task 5)*
5. **Secret confidentiality:** on ALLOW, the response bytes and out-labels never contain the injected secret; no ABI returns secret bytes. *(Task 13)*
6. **IFC violation:** a `SECRET`-labeled arg routed to a sink the cap does not clear → `DENY_FLOW`; egress results are stamped `UNTRUSTED`; declassification requires an explicit cap. *(Task 10)*
7. **Reentrancy / interrupt during mediation:** a timer interrupt mid-mediation must not corrupt state; interrupts are masked and the handler runs to completion; a second `MEDIATE` before the first returns is impossible by construction (single-threaded). *(Task 15)*
8. **Session epoch reuse:** revoking a session and reissuing the same `session_id` must not resurrect old handles (epoch advanced). *(Task 11, Phase 3)*
9. **Egress fault/timeout:** device error or watchdog expiry → `ERR_EGRESS`/`ERR_TIMEOUT`, never a partial or unlabeled result. *(Task 13)*
10. **PMP actually faults:** an S- or U-mode load/store/fetch into an M-only region raises `mcause` 5/7/1. *(Phase 2, Task V2)*
11. **Audit continuity:** every verdict (ALLOW and every DENY) appends one hash-chained entry; the head hash advances; a dropped/edited entry is detectable. *(Task 14)*
12. **Monitor stack overflow:** deep call/corruption faults at the PMP guard sub-region below the M-stack rather than overwriting policy tables. *(Phase 2, Task V3)*

---

## Milestone map (every phase, with exit criteria)

| Phase | Deliverable (working, testable) | Exit criteria |
|-------|-------------------------------|---------------|
| **0. Scaffold + boot** | Rust workspace; `cargo xtask qemu` boots an M-mode "hello" in `qemu-system-riscv32 -machine virt`; CI runs it headless. | Banner prints; QEMU exits 0 via the finisher; CI green; `tokei` gate wired. |
| **1. Monitor decision core** | The full six-stage pipeline (ABI, parser, caps, predicates, flow, audit, secret injection to a mock egress) as host-tested pure logic, then driven behind the QEMU `ecall` path; the containment scenario passes headless. | All Review-Focus items 1–9, 11 have green tests; `demo_attack` → `DENY_ARG`, `demo_flow` → `DENY_FLOW`, `demo_benign` → `ALLOW` (secret injected, absent from response) in QEMU. |
| **2. PMP + measured boot (Verilator)** | LiteX SoC (VexRiscv M/S/U + PMP) in Verilator; BROM measured boot (BLAKE2s) + PMP lockdown; Warden drops to U. | Verilator asserts S/U access to SECRETS/EGRESS faults (item 10); stack-guard fault (item 12); a mediation round-trips M↔U on the sim SoC; boot halts on a tampered Monitor image. |
| **3. Warden, compartments, sessions, wire** | Warden scheduler + rendezvous IPC; Endpoint compartment; COBS/CRC wire; host SDK; session lifecycle + epoch revoke. | Host SDK sends a framed tool call over the sim UART, gets the right verdict; `SESSION_REVOKE` stales live handles (item 8); malformed frames dropped, counted. |
| **4. FPGA bring-up (ULX3S)** | Synthesize with yosys/nextpnr; flash; run on hardware; ESP32 as mediated network egress; OLED shows DENIED/ALLOWED. | The Phase-1 containment scenario runs on the board driving a real HTTPS GET through the Monitor; exfil attempt denied on hardware; verdict shown on the OLED. |
| **5. Hardening** | DMA/IOPMP construction rules enforced + tested; encrypted+authenticated ECP5 bitstream; formal-ish model of the pipeline. | DMA masters provably cannot reach trusted regions; bitstream key provisioned; a machine-checked model of stages 1–6 (stretch). |

Phases 2–5 are specified at task granularity below and expanded into their own bite-sized plans (`docs/superpowers/plans/`) when reached, because their interfaces are shaped by Phase 1's concrete types.

---

## File structure

Rust workspace at the repo root (new; the repo currently holds only docs).

```
Cargo.toml                      # [workspace]; members below
rust-toolchain.toml             # channel = "stable"; targets = ["riscv32imac-unknown-none-elf"]
xtask/                          # std bin: qemu run, verilator run, flash, loc-gate
  src/main.rs
crates/
  abi/                          # #![no_std] #![forbid(unsafe_code)] — shared types (host + target)
    src/lib.rs                  #   ReasonCode, Opcode, TypedArg, Request/Response codecs, Label
  monitor/                      # #![no_std] — the TCB (≤2500 loc)
    src/lib.rs                  #   pipeline wiring (mediate())
    src/parse.rs                #   request parser (bounds, TLV) [forbid unsafe]
    src/cap.rs                  #   Cap, CapSpace, resolver, derive, revoke [forbid unsafe]
    src/predicate.rs            #   compiled clauses + eval [forbid unsafe]
    src/flow.rs                 #   Denning lattice + flow_check [forbid unsafe]
    src/policy.rs               #   compiled tables (built from a manifest; Phase 3 adds the parser)
    src/egress.rs               #   EgressSink trait + secret injection (mock sink for host/QEMU)
    src/audit.rs                #   hash-chained log [forbid unsafe]
    src/arch.rs                 #   ALL unsafe: trap vector, CSR, PMP, mtvec/mepc/mstatus (target only)
    src/reason.rs               #   Status/ReasonCode (re-exported from abi)
  monitor-bin/                  # #![no_std] #![no_main] — the bootable M-mode image (QEMU/FPGA)
    src/main.rs                 #   _start, UART, ecall trampoline -> monitor::mediate
    link-qemu.ld / link-fpga.ld
  warden/                       # Phase 3 (S-mode)
  compartments/                 # Phase 3 (U-mode: endpoint, drivers)
  host-sdk/                     # std lib: build + COBS/CRC-frame requests (host side)
sim/                            # Phase 2: LiteX SoC generator (python) + verilator harness
tests/
  host/                         # cargo integration tests (pure logic + scenarios)
  qemu/                         # scripts + expected output for headless QEMU runs
```

Rationale: pure-logic modules (`parse`, `cap`, `predicate`, `flow`, `audit`) forbid `unsafe` and test on the host with `cargo test` — the fastest loop and where the edge cases live. `arch.rs` quarantines every `unsafe`. `monitor` (the logic library, TCB) is separate from `monitor-bin` (the bootable wrapper) so the TCB line count is measured cleanly.

---

# Phase 0 — Scaffold + boot

### Task 1: Workspace, toolchain, and the LOC gate

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `xtask/Cargo.toml`, `xtask/src/main.rs`, `crates/abi/Cargo.toml`, `crates/abi/src/lib.rs`
- Test: `xtask` self-check (the gate runs)

**Interfaces:**
- Produces: `cargo xtask loc-gate` (fails if `crates/monitor` > 2500 lines or `crates/monitor-bin` boot ROM > 300); `cargo xtask qemu` (defined in Task 3).

- [ ] **Step 1: Create the workspace manifest**
```toml
# Cargo.toml
[workspace]
resolver = "2"
members = ["xtask", "crates/abi", "crates/monitor", "crates/monitor-bin", "crates/host-sdk"]
[workspace.package]
edition = "2021"
license = "MIT"
```
- [ ] **Step 2: Pin the toolchain and target**
```toml
# rust-toolchain.toml
[toolchain]
channel = "stable"
targets = ["riscv32imac-unknown-none-elf"]
components = ["rustfmt", "clippy"]
```
- [ ] **Step 3: Write the LOC gate in xtask**
```rust
// xtask/src/main.rs (excerpt)
fn loc_gate() -> anyhow::Result<()> {
    let mon = count_rust_lines("crates/monitor/src")?;      // excludes tests via cfg
    assert!(mon <= 2500, "monitor TCB {mon} > 2500 LoC budget");
    let brom = count_rust_lines("crates/monitor-bin/src/boot.rs").unwrap_or(0);
    assert!(brom <= 300, "boot ROM {brom} > 300 LoC budget");
    println!("loc-gate ok: monitor={mon} brom={brom}");
    Ok(())
}
```
- [ ] **Step 4: Verify it runs** — Run: `cargo run -p xtask -- loc-gate` → Expected: prints `loc-gate ok: monitor=0 brom=0`.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "chore: rust workspace, pinned riscv target, TCB loc-gate"`

### Task 2: The `abi` crate — reason codes, opcodes, labels

**Files:** Create `crates/abi/src/lib.rs`; Test: inline `#[cfg(test)]`.

**Interfaces:**
- Produces: `enum ReasonCode` (repr u8, values from Global Constraints), `enum Opcode` (repr u32), `struct Label(u8)` with `PUBLIC/SECRET/UNTRUSTED/TRUSTED` accessors, `const MAGIC: u32`.

- [ ] **Step 1: Failing test**
```rust
#[test]
fn reason_codes_have_spec_values() {
    assert_eq!(ReasonCode::Allow as u8, 0x00);
    assert_eq!(ReasonCode::DenyArg as u8, 0x12);
    assert_eq!(ReasonCode::DenyFlow as u8, 0x13);
    assert_eq!(ReasonCode::ErrTimeout as u8, 0x21);
    assert_eq!(Opcode::Mediate as u32, 0x5244_0001);
    assert_eq!(MAGIC, u32::from_le_bytes(*b"RDBT"));
}
```
- [ ] **Step 2: Run, expect fail** — `cargo test -p abi` → FAIL (types undefined).
- [ ] **Step 3: Implement**
```rust
#![no_std]
#![forbid(unsafe_code)]
pub const MAGIC: u32 = u32::from_le_bytes(*b"RDBT");
#[repr(u8)] #[derive(Copy,Clone,PartialEq,Eq,Debug)]
pub enum ReasonCode { Allow=0x00, DenyNoCap=0x10, DenyTool=0x11, DenyArg=0x12,
  DenyFlow=0x13, DenyMalformed=0x14, DenyRevoked=0x15, DenyQuota=0x16,
  ErrEgress=0x20, ErrTimeout=0x21, ErrInternal=0x2F }
#[repr(u32)] #[derive(Copy,Clone,PartialEq,Eq,Debug)]
pub enum Opcode { Mediate=0x5244_0001, SessionOpen=0x5244_0010,
  SessionRevoke=0x5244_0011, SessionClose=0x5244_0012, AttestRead=0x5244_0020 }
#[derive(Copy,Clone,PartialEq,Eq,Debug,Default)]
pub struct Label(pub u8);   // bit0 = confidentiality (1=SECRET), bit1 = integrity (1=TRUSTED)
impl Label { pub const PUBLIC:Label=Label(0); pub const SECRET:Label=Label(0b01);
  pub const UNTRUSTED:Label=Label(0); pub const TRUSTED:Label=Label(0b10);
  pub fn is_secret(self)->bool{ self.0 & 0b01 != 0 } }
```
- [ ] **Step 4: Run, expect pass** — `cargo test -p abi` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(abi): reason codes, opcodes, labels, magic"`

### Task 3: Bootable M-mode "hello" in QEMU

**Files:** Create `crates/monitor-bin/Cargo.toml`, `crates/monitor-bin/src/main.rs`, `crates/monitor-bin/src/uart.rs`, `crates/monitor-bin/link-qemu.ld`, `crates/monitor-bin/.cargo/config.toml`; add `qemu` subcommand to `xtask`; Test: `tests/qemu/boot.rs` (or an xtask assertion).

**Interfaces:**
- Consumes: nothing. Produces: a bootable ELF; `cargo xtask qemu` runs it and returns QEMU's exit code.

- [ ] **Step 1: Failing test (the run harness)**
```rust
// xtask: `qemu` runs qemu-system-riscv32 and asserts the banner + clean exit
// tests/qemu/boot expectation: stdout contains "redoubt: monitor online" and exit==0
```
Run: `cargo run -p xtask -- qemu` → FAIL (no image yet).
- [ ] **Step 2: Linker script for QEMU `virt` (RAM at 0x8000_0000)**
```
/* link-qemu.ld */
OUTPUT_ARCH(riscv) ENTRY(_start)
MEMORY { RAM (rwx): ORIGIN = 0x80000000, LENGTH = 8M }
SECTIONS { . = 0x80000000; .text : { *(.text._start) *(.text*) } >RAM
  .rodata:{*(.rodata*)}>RAM .data:{*(.data*)}>RAM .bss:{*(.bss*)}>RAM
  _stack_top = ORIGIN(RAM)+LENGTH; }
```
- [ ] **Step 3: Minimal M-mode entry + 16550 UART + sifive_test exit**
```rust
#![no_std] #![no_main]
core::arch::global_asm!(".section .text._start; .globl _start
_start: la sp, _stack_top; call main; 1: wfi; j 1b");
mod uart;                       // NS16550 @ 0x1000_0000: write byte to THR
const FINISHER: *mut u32 = 0x0010_0000 as *mut u32;   // qemu virt sifive_test
#[no_mangle] extern "C" fn main() -> ! {
    uart::puts("redoubt: monitor online\n");
    unsafe { core::ptr::write_volatile(FINISHER, 0x5555); } // PASS -> qemu exits 0
    loop { unsafe { core::arch::asm!("wfi"); } }
}
#[panic_handler] fn ph(_:&core::panic::PanicInfo)->!{ 
    unsafe{ core::ptr::write_volatile(FINISHER,0x3333);} loop{} }   // FAIL exit
```
```
# crates/monitor-bin/.cargo/config.toml
[build] target = "riscv32imac-unknown-none-elf"
[target.riscv32imac-unknown-none-elf] rustflags = ["-Clink-arg=-Tlink-qemu.ld"]
```
- [ ] **Step 4: xtask qemu subcommand**
```rust
// runs: qemu-system-riscv32 -machine virt -bios <elf> -nographic -no-reboot
//       -semihosting -serial mon:stdio ; captures stdout; asserts banner + exit 0
```
- [ ] **Step 5: Run, expect pass** — `cargo xtask qemu` → prints banner, exits 0.
- [ ] **Step 6: Commit** — `git commit -am "feat(boot): M-mode hello on qemu virt via xtask"`

### Task 4: CI wiring

**Files:** Create `.github/workflows/ci.yml`.
- [ ] **Step 1:** Job installs Rust + `riscv32imac` target + `qemu-system-misc`, then runs `cargo test --workspace`, `cargo run -p xtask -- qemu`, `cargo run -p xtask -- loc-gate`, `cargo clippy -- -D warnings`, and `cargo geiger` (fail on unsafe outside `arch`).
- [ ] **Step 2:** Push a branch, confirm the job is green.
- [ ] **Step 3: Commit** — `git commit -am "ci: build, host tests, qemu boot, loc + unsafe gates"`

---

# Phase 1 — The Monitor decision core

All logic tasks (6–14) test on the host with `cargo test -p monitor`; no target/QEMU needed until Task 15. Types defined here are the interfaces later phases consume.

### Task 5: Request/TypedArg codec in `abi`

**Files:** Modify `crates/abi/src/lib.rs`; Test: inline.

**Interfaces:**
- Produces: `struct TypedArg` and `enum ArgVal { Url(UrlParts), Path(&[u8]), Enum(u16), Int(i64), Bytes(&[u8]), LabelSet(Label) }` (tags 0x01..0x06); `struct UrlParts{ scheme:Scheme, host:&[u8], port:u16, path:&[u8] }`; `fn decode_request(buf:&[u8]) -> Result<RequestView, ReasonCode>` returning borrowed slices (zero-copy, no alloc); `struct RequestView{ session_id:u16, req_id:u16, cap_handle:u16, tool_id:u16, args:ArgsIter, in_labels:&[u8] }`.

- [ ] **Step 1: Failing tests (happy path + Review-Focus 1)**
```rust
#[test] fn decodes_minimal_request() {
    let buf = build(&Req{ session:1, req_id:7, cap:3, tool:0x1000, args:&[], labels:&[] });
    let r = decode_request(&buf).unwrap();
    assert_eq!((r.session_id, r.cap_handle, r.tool_id), (1,3,0x1000));
}
#[test] fn rejects_bad_magic()      { assert_eq!(decode_request(&[0,0,0,0]).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn rejects_too_many_args()  { let b=build_with_n_args(9); assert_eq!(decode_request(&b).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn rejects_truncated_tlv()  { let b=truncate(build_url_arg(), 3); assert_eq!(decode_request(&b).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn rejects_len_over_max()   { assert_eq!(decode_request(&[0u8; MAX_REQ+1][..]).unwrap_err(), ReasonCode::DenyMalformed); }
```
- [ ] **Step 2: Run, expect fail** — `cargo test -p abi` → FAIL.
- [ ] **Step 3: Implement `decode_request`** — validate `len<=MAX_REQ`, magic, `n_args<=MAX_ARGS`; iterate TLVs checking each `off+3+len<=buf.len()`; a URL value decodes into `UrlParts` by splitting the pre-parsed fields (host lowercased, no re-parsing of raw text). Return `DenyMalformed` on any bound/shape failure. No `unsafe`, no `alloc`.
- [ ] **Step 4: Run, expect pass.** **Step 5: Commit** — `git commit -am "feat(abi): zero-copy request/TypedArg codec with bounds checks"`

### Task 6: Parser guard in `monitor` (SHARED_REQ bounds)

**Files:** Create `crates/monitor/src/parse.rs`, `crates/monitor/src/lib.rs`; Test: inline.

**Interfaces:**
- Consumes: `abi::decode_request`. Produces: `fn parse_into<'a>(shared:&'a [u8], ptr:usize, len:usize, region:Range<usize>) -> Result<abi::RequestView<'a>, ReasonCode>` — proves `[ptr,ptr+len) ⊆ region` before copying `len` bytes into a private fixed `[u8; MAX_REQ]`, then decodes the copy (defeats TOCTOU, Ch 9 §9.7 stage 1).

- [ ] **Step 1: Failing tests (Review-Focus 1)**
```rust
#[test] fn ptr_outside_region_denies() {
  assert_eq!(parse_into(&shared, region.start-4, 16, region.clone()).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn end_past_region_denies() {
  assert_eq!(parse_into(&shared, region.end-4, 16, region.clone()).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn valid_request_copies_and_decodes() { assert!(parse_into(&shared, ok_ptr, ok_len, region).is_ok()); }
```
- [ ] **Steps 2-4:** fail, implement (checked-arithmetic bounds, copy to `[u8;MAX_REQ]`, `decode_request`), pass.
- [ ] **Step 5: Commit** — `git commit -am "feat(monitor): bounds-checked TOCTOU-safe request copy"`

### Task 7: Capability space + resolver

**Files:** Create `crates/monitor/src/cap.rs`; Test: inline.

**Interfaces:**
- Produces: `#[repr(C)] struct Cap{ ctype:u8, rights:u8, tool_id:u16, pred_ref:u16, flow_ref:u16, secret_ref:u16, aux:u16, epoch:u16 }` (16 bytes); `enum CapType{Empty=0,Net,File,Secret,Tool}`; `struct Session{ epoch:u16, cspace:[Cap;32] }`; `fn resolve(s:&Session, handle:u16) -> Result<&Cap, ReasonCode>`.

- [ ] **Step 1: Failing tests (Review-Focus 3)**
```rust
#[test] fn empty_slot_denies()     { assert_eq!(resolve(&s, 0).unwrap_err(), ReasonCode::DenyNoCap); }
#[test] fn out_of_range_denies()   { assert_eq!(resolve(&s, 99).unwrap_err(), ReasonCode::DenyNoCap); }
#[test] fn stale_epoch_denies()    { let mut s=s; s.cspace[3].epoch=s.epoch.wrapping_sub(1);
                                     assert_eq!(resolve(&s,3).unwrap_err(), ReasonCode::DenyRevoked); }
#[test] fn live_cap_resolves()     { assert_eq!(resolve(&s,3).unwrap().tool_id, 0x1000); }
#[test] fn size_is_16_bytes()      { assert_eq!(core::mem::size_of::<Cap>(), 16); }
```
- [ ] **Steps 2-4:** fail, implement (bounds check into cspace; `Empty`/oob → `DenyNoCap`; `epoch != s.epoch` → `DenyRevoked`), pass.
- [ ] **Step 5: Commit** — `git commit -am "feat(monitor): 16-byte Cap, cspace, epoch-checked resolver"`

### Task 8: Tool binding

**Files:** Modify `crates/monitor/src/lib.rs`; Test: inline.
**Interfaces:** Produces `fn check_tool(cap:&Cap, tool_id:u16) -> Result<(),ReasonCode>`.
- [ ] **Step 1: Failing tests (Review-Focus 4)**
```rust
#[test] fn mismatched_tool_denies() { assert_eq!(check_tool(&cap_http, 0x2000).unwrap_err(), ReasonCode::DenyTool); }
#[test] fn matched_tool_ok()        { assert!(check_tool(&cap_http, 0x1000).is_ok()); }
```
- [ ] **Steps 2-5:** fail, implement (`cap.tool_id == tool_id`), pass, commit.

### Task 9: Predicate engine

**Files:** Create `crates/monitor/src/predicate.rs`; Test: inline.

**Interfaces:**
- Produces: `enum Op{Eq,InSet,Prefix,Suffix,HostInSet,SchemeEq,Range,LenLe}`; `struct Clause{ field:FieldSel, op:Op, operand:u16 }`; `struct FieldSel(u8)` selecting `url.host|url.scheme|method|path|len`; `fn eval(clauses:&[Clause], args:&Args, pool:&ConstPool) -> Result<(), ReasonCode>` returning `DenyArg` (predicate false) or `DenyMalformed` (field/type mismatch).

- [ ] **Step 1: Failing tests (Review-Focus 2, 4, 5 — the SSRF class)**
```rust
#[test] fn host_in_set_passes_exact() { assert!(eval(&[host_in(pool_apis)], &args_url("https","api.example.com",443,"/x"), &pool).is_ok()); }
#[test] fn host_in_set_rejects_other() { assert_eq!(eval(&[host_in(pool_apis)], &args_url("https","evil.tld",443,"/"), &pool).unwrap_err(), ReasonCode::DenyArg); }
#[test] fn host_match_is_case_insensitive() { assert!(eval(&[host_in(pool_apis)], &args_url("https","API.EXAMPLE.COM",443,"/"), &pool).is_ok()); }
#[test] fn trailing_dot_does_not_match() { assert_eq!(eval(&[host_in(pool_apis)], &args_url("https","api.example.com.",443,"/"), &pool).unwrap_err(), ReasonCode::DenyArg); }
#[test] fn scheme_eq_https_rejects_http() { assert_eq!(eval(&[scheme_eq_https()], &args_url("http","api.example.com",80,"/"), &pool).unwrap_err(), ReasonCode::DenyArg); }
#[test] fn wrong_arg_type_is_malformed() { assert_eq!(eval(&[host_in(pool_apis)], &args_bytes(b"x"), &pool).unwrap_err(), ReasonCode::DenyMalformed); }
#[test] fn method_in_set_get_only() { assert_eq!(eval(&[method_in(pool_get)], &args_method("POST"), &pool).unwrap_err(), ReasonCode::DenyArg); }
#[test] fn path_prefix_boundary() { assert!(eval(&[path_prefix("/corpus/")], &args_path("/corpus/a"), &pool).is_ok());
                                    assert_eq!(eval(&[path_prefix("/corpus/")], &args_path("/corpusX")).unwrap_err(), ReasonCode::DenyArg); }
```
Note: `%2e`/credential/port-confusion cases are covered because `eval` reads the **typed, host-decoded** `UrlParts.host` (decoded in Task 5), never raw text; add explicit tests that `args_url` built from a raw `https://user@evil.tld@api.example.com` decodes `host="evil.tld"` (or is rejected as malformed by the decoder) and therefore fails `host_in_set`.
- [ ] **Steps 2-4:** fail, implement the fixed clause loop (≤ MAX_CLAUSES), each op reading its typed field; a field/type mismatch → `DenyMalformed`, a false predicate → `DenyArg`, pass.
- [ ] **Step 5: Commit** — `git commit -am "feat(monitor): typed predicate engine (host-in-set, scheme, method, prefix)"`

### Task 10: Flow engine (IFC)

**Files:** Create `crates/monitor/src/flow.rs`; Test: inline.
**Interfaces:** Produces `struct FlowRule{ inject:Option<u16>, deny_secret_to_public:bool, result_label:Label }`; `fn flow_check(rule:&FlowRule, in_labels:&[Label], cap:&Cap) -> Result<Label,ReasonCode>` (returns the output label or `DenyFlow`).
- [ ] **Step 1: Failing tests (Review-Focus 6)**
```rust
#[test] fn secret_arg_to_public_sink_denies() {
  assert_eq!(flow_check(&rule_public_net, &[Label::SECRET], &cap_net).unwrap_err(), ReasonCode::DenyFlow); }
#[test] fn public_args_ok_and_result_untrusted() {
  assert_eq!(flow_check(&rule_public_net, &[Label::PUBLIC], &cap_net).unwrap(), Label::UNTRUSTED); }
#[test] fn declassify_requires_cap() { /* rule without clearance denies; with clearance allows */ }
```
- [ ] **Steps 2-5:** fail, implement, pass, commit.

### Task 11: Session table + revocation

**Files:** Modify `crates/monitor/src/cap.rs`; Test: inline.
**Interfaces:** Produces `struct Sessions{ tbl:[Option<Session>;8] }`; `fn get(&self,id:u16)->Result<&Session,ReasonCode>`; `fn revoke(&mut self,id:u16)` (bumps epoch).
- [ ] **Step 1: Failing tests (Review-Focus 8)**
```rust
#[test] fn revoke_stales_all_handles() {
  let mut ss=one_session_with_caps(); ss.revoke(1);
  assert_eq!(resolve(ss.get(1).unwrap(), 3).unwrap_err(), ReasonCode::DenyRevoked); }
#[test] fn unknown_session_denies() { assert_eq!(Sessions::default().get(5).unwrap_err(), ReasonCode::DenyNoCap); }
```
- [ ] **Steps 2-5:** fail, implement (epoch bump advances `Session.epoch`; new caps installed at the new epoch), pass, commit.

### Task 12: Egress sink trait + secret injector (mock)

**Files:** Create `crates/monitor/src/egress.rs`; Test: inline.
**Interfaces:** Produces `trait EgressSink{ fn perform(&mut self, cap:&Cap, args:&Args, secret:Option<&[u8]>) -> Result<Response,ReasonCode>; }`; a `MockSink` for host/QEMU that records the outbound bytes; `struct Response{ status:ReasonCode, out_label:Label, body:Vec<u8>|&[u8] }` (fixed buffer, no alloc in `monitor`).
- [ ] **Step 1: Failing tests (Review-Focus 5, 9)**
```rust
#[test] fn secret_is_injected_but_not_returned() {
  let mut s=MockSink::default();
  let r=s.perform(&cap_http, &args_get, Some(b"KEY123")).unwrap();
  assert!(s.last_outbound().windows(6).any(|w| w==b"KEY123"));   // used
  assert!(!r.body.windows(6).any(|w| w==b"KEY123"));             // never returned
}
#[test] fn sink_error_maps_to_err_egress() { assert_eq!(FailingSink.perform(..).unwrap_err(), ReasonCode::ErrEgress); }
#[test] fn sink_timeout_maps_to_err_timeout() { assert_eq!(TimeoutSink.perform(..).unwrap_err(), ReasonCode::ErrTimeout); }
```
- [ ] **Steps 2-5:** fail, implement, pass, commit.

### Task 13: Audit log (hash chain)

**Files:** Create `crates/monitor/src/audit.rs`; Test: inline (add `blake2` no_std dep).
**Interfaces:** Produces `struct Audit{ head:[u8;32], ring:[Entry;N] }`; `fn append(&mut self, e:Entry)`; `fn head(&self)->[u8;32]`.
- [ ] **Step 1: Failing tests (Review-Focus 11)**
```rust
#[test] fn every_verdict_advances_head() { let mut a=Audit::default(); let h0=a.head();
  a.append(entry(ALLOW)); let h1=a.head(); assert_ne!(h0,h1);
  a.append(entry(DenyArg)); assert_ne!(h1,a.head()); }
#[test] fn chain_is_deterministic() { assert_eq!(replay(&entries), replay(&entries)); }
```
- [ ] **Steps 2-5:** fail, implement `h_i = BLAKE2s(h_{i-1} || entry)`, pass, commit.

### Task 14: Wire the pipeline — `monitor::mediate`

**Files:** Modify `crates/monitor/src/lib.rs`; Test: `tests/host/pipeline.rs`.
**Interfaces:** Produces `fn mediate(shared:&[u8], ptr:usize, len:usize, region:Range<usize>, sessions:&Sessions, policy:&Policy, sink:&mut dyn EgressSink, audit:&mut Audit) -> (ReasonCode, ResponseView)` running stages 1..6 in order and appending one audit entry.
- [ ] **Step 1: Failing tests — the full ALLOW/DENY matrix + the three demo scenarios**
```rust
#[test] fn demo_benign_allows_and_injects() {
  let (rc, resp) = mediate(&sh, p, l, region, &sessions, &policy, &mut sink, &mut audit);
  assert_eq!(rc, ReasonCode::Allow);
  assert!(sink.last_outbound_has_auth_header());
  assert!(!resp.bytes().windows(6).any(|w| w==b"API_KEY"));
}
#[test] fn demo_attack_wrong_host_denies_arg() { /* POST evil.tld -> DENY_ARG at stage 4 */ }
#[test] fn demo_flow_secret_in_body_denies_flow() { /* correct host, secret body -> DENY_FLOW at stage 5 */ }
#[test] fn ordering_stage2_before_stage4() { /* forged handle to allowed args still DENY_NO_CAP */ }
```
- [ ] **Steps 2-4:** fail, implement the six-stage sequence exactly per Ch 9 §9.7, pass.
- [ ] **Step 5: Commit** — `git commit -am "feat(monitor): six-stage mediate() + containment scenario tests"`

### Task 15: M-mode trap trampoline — drive `mediate` from an `ecall` in QEMU

**Files:** Create `crates/monitor/src/arch.rs` (the only `unsafe` module), `crates/monitor-bin/src/main.rs` (trap vector + SHARED_REQ), `tests/qemu/mediate.rs`.
**Interfaces:** Consumes `monitor::mediate`. Produces the `mtvec` handler: on `ecall` (mcause 8/9) with `a7==MEDIATE`, read `a0=ptr,a1=len`, call `mediate`, return `a0=status,a1=resp_len`; all other `a7` → `DENY_MALFORMED`.
- [ ] **Step 1: Failing QEMU test (Review-Focus 7)** — a U/S stub issues `ecall MEDIATE` on a crafted SHARED_REQ; harness asserts the returned status matches the host `mediate` result for the same bytes; a second scenario fires a timer interrupt mid-handler and asserts the verdict and return path are intact (interrupts masked in-handler).
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Implement `arch.rs`** — set `mtvec`; on entry switch to the M stack via `mscratch`, save `a0..a7`+`ra`+`mepc`+`mstatus`, keep `MIE` clear, dispatch on `a7`, restore, `mret`. Align the M stack to 16 bytes; place a guard word (real PMP guard is Phase 2). Wire SHARED_REQ as a static `[u8;MAX_REQ]`.
- [ ] **Step 4: Run, expect pass** — `cargo xtask qemu -- mediate` green; the three demo scenarios reproduce the host verdicts in QEMU.
- [ ] **Step 5: Commit** — `git commit -am "feat(monitor): M-mode ecall trampoline; containment demo runs in QEMU"`

**Phase 1 exit:** `cargo test --workspace` green; `cargo xtask qemu -- mediate` reproduces `demo_benign=ALLOW` (secret injected, absent from response), `demo_attack=DENY_ARG`, `demo_flow=DENY_FLOW`; Review-Focus 1–9 and 11 have passing tests; `loc-gate` under budget.

---

# Phase 2 — PMP + measured boot (Verilator)  *(task outline; own bite-sized plan at execution)*

- **Task V1 — LiteX SoC generator.** `sim/redoubt_soc.py`: VexRiscv variant with `CsrPlugin`(M/S/U), `PmpPlugin`(≥8 entries), MulDiv, caches; regions per the FPGA memory map; `EGRESS_MMIO` as a CSR-backed mock. **Produces:** a Verilator model + a memory image loader. **Exit:** SoC boots the Phase-1 monitor image and prints the banner in Verilator.
- **Task V2 — PMP lockdown + the fault assertion (Review-Focus 10).** BROM programs `pmpaddr*/pmpcfg*` (TOR; Smepmp or `L=1`) for the 7 regions and locks them before dropping to S. **Test (Verilator):** an S- and a U-mode access to `SECRETS` and to `EGRESS_MMIO` each raise `mcause` 5/7; an access to its own region succeeds. **Exit:** assertion green in CI (`cargo xtask verilator -- pmp`).
- **Task V3 — Measured boot + stack guard (Review-Focus 12).** BROM computes `BLAKE2s(MON_CODE)` vs a baked `H_expected`, halts on mismatch; a PMP no-access sub-region sits below the M stack. **Test:** a tampered image halts pre-Warden; a forced stack overflow faults at the guard, not into `MON_DATA`.
- **Task V4 — Warden skeleton (S) + real egress MMIO.** Minimal S-mode entry that `mret`s to a U stub and relays its `ecall` to M; `EgressSink` implemented against the CSR-mock. **Exit:** a mediation round-trips U→S→M→(mock egress)→U on the sim SoC; `demo_*` verdicts reproduce at RTL level.

# Phase 3 — Warden, compartments, sessions, wire  *(task outline)*

- **W1 Warden scheduler + rendezvous IPC** (round-robin, timer preempt, bounded copy-by-value; no shared writable pages). **W2 Endpoint compartment** (COBS deframe + CRC32; forward typed requests; framing-only). **W3 Wire codec + host SDK** (`host-sdk`: build Request, COBS/CRC frame; `tests/host` round-trips against the decoder; malformed-frame tests: bad CRC, bad COBS, unknown `ver`, oversize → dropped + counted). **W4 Session lifecycle** (`SESSION_OPEN/REVOKE/CLOSE`, state machine Created→Provisioned→Active→Draining→Destroyed, quotas → `DENY_QUOTA`; Review-Focus 8 hardware-path test). **W5 Policy manifest compiler** (`monitor/src/policy.rs` + a host tool: parse the EBNF manifest → `Cap`+`predicate_table`+`flow_table`+`ConstPool`; a golden test compiles the Ch 8 example to the exact tables Task 14 consumes). **Exit:** host SDK drives a real tool call over the sim UART and gets the correct verdict; revoke stales live handles.

# Phase 4 — FPGA bring-up (ULX3S)  *(task outline)*

- **F1** synth/place/route with yosys + nextpnr-ecp5 (`link-fpga.ld`, FPGA memory map); fit + timing report. **F2** flash via `openFPGALoader`; UART banner on hardware. **F3** ESP32 as M-owned network egress (M-only link; the honest caveat from Ch 12); `EgressSink` performs a real HTTPS GET with injected header. **F4** OLED shows ALLOWED/DENIED + reason. **F5** DMA-by-construction check: SD/net DMA config registers proven M-only (Review-Focus, Ch 4 §4.7). **Exit:** the containment demo runs on the board; exfil denied; verdict on the OLED.

# Phase 5 — Hardening  *(task outline)*

- **H1** IOPMP or the RTL mediation gate on the egress bus; test a rogue master faults. **H2** ECP5 AES-256 encrypted+authenticated bitstream with an OTP-fused key. **H3** a machine-checked model of stages 1–6 (stretch: Kani/Prusti on the `monitor` logic).

---

## Self-review

**1. Spec coverage.** Ch 6 wire → Task 5/W3; Ch 7 caps → Task 7/11; Ch 8 policy → W5; Ch 9 monitor pipeline/trap/secrets/audit → Tasks 6–15; Ch 10 IFC → Task 10; Ch 3/4 PMP+SoC+DMA → V1–V4, F5; Ch 5 boot → V3; Ch 11 Warden/compartments/sessions → W1–W4; Ch 12 egress/secrets/TRNG → Task 12 (mock), F3 (real), and note: **TRNG hardware + 800-90B health tests land in Phase 4 (F-series) with a host deterministic-seed stub for sim** — added here so it isn't dropped; Ch 13 assurance obligations → the Review-Focus tests + V2/V3. No spec section is unmapped.

**2. Placeholder scan.** No "TBD/handle edge cases/similar to Task N". Phases 2–5 are explicitly task-outlines to be expanded into their own bite-sized plans, not hidden work; Phases 0–1 carry real code and commands.

**3. Type consistency.** `ReasonCode`/`Opcode`/`Label`/`MAGIC` (Task 2) used verbatim in 5–15; `Cap` fields (Task 7) match Ch 12 usage and Task 14; `RequestView`/`UrlParts` (Task 5) consumed by Task 6/9; `EgressSink`/`Response` (Task 12) consumed by Task 14/15/V4; `mediate(...)` signature (Task 14) consumed by Task 15.

**4. Review Focus.** Items 1–9 and 11 are pinned to Phase-1 tasks with concrete tests; 10 and 12 to Verilator tasks V2/V3; 8 also re-tested on the hardware path in W4. The section is complete, not skipped.

## Notes for the executor
- Fastest loop: Tasks 5–14 are pure `cargo test -p monitor`/`-p abi` on the dev machine, no QEMU. Only 3, 4, 15 need QEMU.
- macOS setup: `rustup target add riscv32imac-unknown-none-elf`; `brew install qemu verilator`; `oss-cad-suite` for yosys/nextpnr-ecp5; `openFPGALoader` for Phase 4.
- Keep every `unsafe` in an `arch.rs`; the `cargo geiger` gate enforces it.
