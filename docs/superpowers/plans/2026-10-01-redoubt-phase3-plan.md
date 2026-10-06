# Redoubt Phase 3 — Warden, Compartments, Sessions, Wire Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the single-fixture mediation demo into a real agent-facing system: a wire protocol with COBS+CRC32 framing and a host SDK, a policy manifest compiler that replaces the hand-built `Policy` fixtures, a full session lifecycle (open/revoke/close + quotas), and a minimal Warden + Endpoint compartment that carry frames from the serial boundary to the Monitor on the simulated SoC.

**Architecture:** Phases 1–2 built the Monitor (the six-stage `mediate` pipeline, `#![forbid(unsafe_code)]`) and put it on a Verilated VexRiscv+PMP SoC with measured boot. Phase 3 builds the layers around it: (1) the wire codec (shared `no_std` framing + the `host-sdk` encoder) so a host can actually speak to Redoubt; (2) the policy compiler (`monitor/src/policy.rs` + a host manifest tool) that turns a written manifest into the exact `Cap` + predicate-table + flow-table + `ConstPool` the Monitor already consumes; (3) the session state machine + quotas on top of Phase-1's `Sessions`; (4) a U-mode Endpoint compartment that deframes bytes and relays whole frames to M; (5) a minimal Warden that schedules the Endpoint and relays its ecalls. Most of (1)–(3) is pure host-testable logic (fast, like the Phase-1 monitor crate); (4)–(5) are sim-integration on the Verilator SoC.

**Tech Stack:** Rust `no_std` (`monitor`, `abi`, new framing + `host-sdk`), host `std` for the manifest compiler tool + SDK tests, the Phase-2 sim toolchain (LiteX + VexRiscv-`secure` + Verilator in `sim/`, nightly-2026-09-26 + `-Z build-std` for `riscv32ima`), `cargo xtask`.

**Spec:** `docs/architecture/components/06-wire.html` (COBS+CRC32 framing, the Endpoint-as-courier, TypedArg TLV), `07-capabilities.html` (Cap model), `08-policy.html` (the manifest grammar + the compiled tables), `11-stack.html` (Warden/compartments/sessions, the five-state session machine, quotas). Canonical facts: `docs/architecture/AGENT_BRIEF.md`. Phase 2 merged at `origin/main` `75d51d2`.

---

## Grounding & M+U/PMP reconciliation (read before Task 1)

Phase 2 established two hardware facts (recorded in `sim/README.md` and the manual's §3.9 implementation notes) that Ch 11's design predates. Phase 3 is built to the reconciled reality, and each divergence from the manual's S-mode/MMU prose is called out here so the plan and the manual stay honest.

- **R3-A — No S-mode (M+U only).** Ch 11's Warden runs in Supervisor; this core has none. **The Warden runs in U-mode** alongside compartments. Its scheduling *policy* is U-mode code, but the *mechanism* that saves/restores register state and reprograms isolation lives in **M** (the trap handler), because the timer interrupt and PMP are machine-only. "The timer jumps back into the Warden" (Ch 11 §11.3) becomes "the timer traps to M, which runs the scheduler step and resumes the chosen U context."
- **R3-B — No MMU (PMP-only).** Ch 11 §11.5 switches page tables / ASIDs per compartment. There is no paging here. **Compartment isolation is by PMP region**, reprogrammed by M at each context switch (the per-compartment U-grant entry). "Address space" → "the compartment's PMP-granted region(s)".
- **R3-C — Rendezvous IPC crosses PMP walls.** Ch 11 §11.4 copies a fixed-size message sender→receiver. With PMP isolation and no shared writable pages, the copy crosses regions, so **M performs the copy-by-value** (the only component that can read both regions), preserving the no-shared-memory / no-TOCTOU property. For Phase-3 sim scope the only live rendezvous is Endpoint→Monitor via the ecall relay (already the MEDIATE path); a general compartment↔compartment channel is designed but exercised minimally.
- **R3-D — Scope the Warden realistically.** A full preemptive multi-compartment scheduler on PMP-only M+U is a large effort and is NOT required to demonstrate the Phase-3 security story. W1 builds a **minimal cooperative scheduler**: the Endpoint is the one live compartment; M-mediated context handoff on `ecall`/yield; timer-preemption of a runaway compartment is included as a single-compartment liveness guard (M fields the timer, bounds the Endpoint's slice). The full multi-driver preemptive Warden + MMU address spaces are a documented follow-up for a supervisor-capable core.
- **R3-E — Egress MMIO is not PMP-walled (Phase-2 F2).** Unchanged here: compartments gain nothing by poking egress directly (no key, no allowed request); containment stays with mediation. Do not build W-tasks that assume PMP walls U out of EGRESS_MMIO.

**Build order (dependency-sorted; the manual's W-labels kept for traceability):** W3 (wire codec + SDK) → W5 (policy compiler) → W4 (session lifecycle) → W2 (Endpoint compartment) → W1 (minimal Warden). W3 and W5 are pure host logic and unblock the rest.

---

## Global Constraints

- **The wire frame (Ch 6 §6.3, verbatim):** inner layout is `ver:u8` then the payload (the Phase-1 request/response bytes); CRC32 is computed over `ver..end-of-payload`; the whole thing is COBS-encoded and a single `0x00` delimiter byte appended. `0x00` appears nowhere else in a frame. A reader reads to the next `0x00`, COBS-decodes, checks CRC32; **on COBS-fail OR CRC-mismatch the frame is DROPPED and a counter incremented — never partially processed.** CRC is corruption-only, NOT a security control (a hostile host can forge it); integrity rests on the Monitor re-deriving every field. `ver` is a single fixed version for v1 (no negotiation).
- **The inner request/response** are the Phase-1 formats (`abi`): request header = `magic(u32 RDBT) · session_id(u16) · req_id(u16) · cap_handle(u16) · tool_id(u16) · n_args(u8) · reserved(u8) · labels_len(u16)`, then `n_args` TLVs, then `labels_len` bytes. `req_id` is echoed in the response verbatim. A response carries `result` only on ALLOW; a denial carries no body and **no injected secret ever travels back in `result`**.
- **Opcodes (`abi::Opcode`, verbatim):** `MEDIATE 0x5244_0001`, `SESSION_OPEN 0x5244_0010`, `SESSION_REVOKE 0x5244_0011`, `SESSION_CLOSE 0x5244_0012`, `ATTEST_READ 0x5244_0020`. Reason codes incl. `DENY_QUOTA 0x16`.
- **Policy is TOTAL (Ch 8):** the manifest language has no loops, no recursion, no unbounded constructs; it compiles ahead-of-time to fixed tables. The compiler emits exactly the Phase-1 compiled forms: `cap::Cap`, `&[predicate::Clause]` + `predicate::ConstPool`, `flow::FlowRule`. The Monitor's evaluation is unchanged.
- **Session (Ch 11 §11.8):** capability space = `[Cap; 32]`, epoch `u16`, quotas; ≤ 8 live. Five states **Created → Provisioned → Active → Draining → Destroyed**, fixed order; REVOKE bumps epoch = Active→Destroyed O(1); a crossed quota ceiling → `DENY_QUOTA` and Active→Draining; Draining finishes in-flight work, accepts no new, then Destroyed wipes the slot.
- TCB discipline: `monitor` + `abi` stay `#![forbid(unsafe_code)]`. Any new `unsafe` (compartment/Warden context handoff) is confined to `monitor-bin` behind the `sim` feature, never the logic crates. Framing + SDK + compiler are safe Rust.
- No heap on any Monitor request path; fixed buffers; bounded loops; fail closed. No clock/RNG on a decision path.
- Host suite (`cargo test`) and all Phase-2 Verilator scenarios (`boot`/`pmp`/`measure`/`mediate`) must stay green at every task. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

Failure modes the spec implies; each pinned to the task whose tests must exercise it.

1. **Framing ambiguity (W3).** A frame whose COBS decode fails, whose CRC mismatches, that is truncated, that is oversized, or that carries a stray `0x00` must be dropped and counted — never half-parsed. Test every one; a request in a dropped frame "never happened."
2. **Round-trip fidelity (W3).** `host-sdk` encode → COBS frame → deframe → `abi::decode_request` reproduces the exact request for every TypedArg tag; a flipped bit anywhere fails CRC and drops.
3. **Compiler totality + golden tables (W5).** The compiler rejects any manifest with an unbounded/illegal construct, and compiles the Ch 8 worked example to the EXACT `Cap`/clauses/`ConstPool`/`FlowRule` bytes the Monitor consumes (a golden test). A manifest that over-grants must not silently widen a cap.
4. **Session state machine (W4).** Illegal transitions are refused (e.g. MEDIATE on a Created-but-not-Provisioned session, or on a Destroyed one); REVOKE from Active reaches Destroyed and stales every handle in O(1); CLOSE drains then destroys; a reused slot gets a fresh epoch so an old handle never resolves.
5. **Quotas (W4).** Crossing the egress-bytes / request-count ceiling returns `DENY_QUOTA` and moves the session to Draining; in-flight requests finish, new ones are refused; quota debit is part of mediation and cannot be bypassed.
6. **Endpoint holds no authority (W2).** Replacing the Endpoint with hostile code cannot cause an effect policy would deny: it reads no policy, resolves no capability, touches no secret; it only moves bytes and relays. Prove a malformed/oversized frame from the Endpoint is still `DENY_MALFORMED` at the Monitor, and a forged frame still faces full mediation.
7. **Liveness without trust (W1).** A compartment that spins forever is timer-preempted (M bounds its slice) and cannot wedge the device or starve mediation; a Warden bug can stall progress but can NOT cause an unauthorized effect (the security property holds with the Warden fully compromised).

---

# Task W3 — Wire codec (COBS+CRC32) + host SDK

**Files:** Create `crates/wire/` (a `no_std` framing crate: COBS encode/decode + CRC32 + frame/deframe over the Phase-1 request/response bytes), shared by both sides; build out `crates/host-sdk/` (std; build a `Request`, frame it, parse a `Response`); Test: inline in `wire` + `tests/host` round-trips in `host-sdk`.

**Interfaces:**
- Produces `wire`: `fn frame(payload:&[u8], out:&mut [u8]) -> Result<usize, FrameErr>` (prepend `ver`, CRC32 over `ver..payload`, COBS-encode, append `0x00`); `fn deframe<'a>(frame:&[u8], scratch:&'a mut [u8]) -> Result<&'a [u8], FrameErr>` (strip delimiter, COBS-decode, check CRC, return the inner payload or a drop reason); a `DropCounter`. All `no_std`, no alloc, bounded by a fixed `MAX_FRAME`.
- Produces `host-sdk`: `fn build_request(session_id, req_id, cap_handle, tool_id, args:&[TypedArg], labels:&[Label]) -> Vec<u8>` and `fn frame_request(...) -> Vec<u8>`; `fn parse_response(frame:&[u8]) -> Result<ResponseView, _>`.

- [ ] **Step 1: COBS failing tests** — encode/decode round-trips incl. all-zeros, no-zeros, max-length, and the empty payload; a decode of a frame with an interior `0x00` or a bad COBS length fails. (TDD: write, fail, implement, pass.)
- [ ] **Step 2: CRC32 + frame/deframe** — `frame` then `deframe` returns the identical payload; a single flipped bit → CRC mismatch → drop + counter tick; truncated/oversized → drop. (Review-Focus 1.)
- [ ] **Step 3: host-sdk encode** — build each TypedArg tag (URL/PATH/ENUM/INT/BYTES/LABELSET) into the Phase-1 request layout; `frame_request` → `wire::deframe` → `abi::decode_request` reproduces the request exactly. (Review-Focus 2.)
- [ ] **Step 4: host-sdk response** — `parse_response` reads `status` + `req_id` echo; asserts a denial carries no body. Commit.

**Exit:** a host-built request survives frame→wire→deframe→decode byte-for-byte; every malformed-frame class drops-and-counts; `host-sdk` round-trips against the real decoder in `tests/host`.

---

# Task W5 — Policy manifest compiler

**Files:** Create `crates/monitor/src/policy.rs` (the compiled `Policy` aggregate type + the in-crate representation; `no_std`) and `crates/policyc/` (a host `std` tool: parse the manifest grammar → emit the tables); Test: inline + a golden test compiling the Ch 8 example.

**Interfaces:**
- Produces `policy::Policy<'a>` (the Phase-1 `lib.rs` fixture `Policy` promoted here: `preds: &[&[Clause]]`, `flows: &[FlowRule]`, `secrets: &[&[u8]]`, `pool: ConstPool`) and the parser/compiler in `policyc` that turns a manifest file into a `Policy` (or a generated Rust/const blob the Monitor loads). Consumes Phase-1 `predicate::{Clause,Op,FieldSel,PoolEntry,ConstPool}`, `cap::Cap`, `flow::FlowRule`.

- [ ] **Step 1: grammar + totality failing tests** — a minimal manifest (one tool, host-allowlist + method + scheme + a secret inject) parses; a manifest with any unbounded/illegal construct is rejected. (Review-Focus 3.)
- [ ] **Step 2: compile to tables** — emit `Cap` (ctype/rights/tool_id/pred_ref/flow_ref/secret_ref/epoch), the `Clause` list + `ConstPool` entries, and the `FlowRule`. The eight ops (EQ/IN_SET/PREFIX/SUFFIX/HOST_IN_SET/SCHEME_EQ/RANGE/LEN_LE) each have a manifest surface syntax.
- [ ] **Step 3: golden test** — compile the Ch 8 worked example; assert the emitted tables equal the exact bytes/values the Phase-1 `mediate` host demo used as its hand-built fixture (so the compiler is a drop-in replacement). (Review-Focus 3.)
- [ ] **Step 4:** wire `policy::Policy` into the Phase-1 `mediate` fixtures (`fixtures.rs`) so the demo can optionally source its policy from a compiled manifest; keep the hand fixture as a test fallback. Commit.

**Exit:** a written manifest compiles to the exact tables the Monitor already evaluates; the Ch 8 example is a golden test; illegal manifests are rejected at compile time.

---

# Task W4 — Session lifecycle + quotas

**Files:** Modify `crates/monitor/src/cap.rs` (extend `Session`/`Sessions` with state + quotas) and `crates/monitor/src/lib.rs` (the SESSION_OPEN/REVOKE/CLOSE handlers + quota debit in `mediate`); Test: inline.

**Interfaces:**
- Produces a `SessionState { Created, Provisioned, Active, Draining, Destroyed }` on `Session`; `Quotas { egress_bytes_left, requests_left, ... }`; `fn session_open(&mut Sessions, policy) -> Result<id, Reason>`, `fn session_revoke(&mut Sessions, id)`, `fn session_close(&mut Sessions, id)`; `mediate` debits quotas and refuses on the wrong state. Consumes W5 `Policy` (to provision caps) + Phase-1 `Sessions::{install,get,get_mut,revoke}`.

- [ ] **Step 1: state-machine failing tests (Review-Focus 4)** — MEDIATE on a non-Active session denies; the five transitions occur in order; REVOKE (Active→Destroyed) stales all handles O(1); CLOSE (Active→Draining→Destroyed); a reused slot gets a fresh epoch.
- [ ] **Step 2: implement the state machine** on `Session` + the open/revoke/close functions; `session_open` provisions the cspace from a compiled `Policy` and stamps the epoch.
- [ ] **Step 3: quota failing tests (Review-Focus 5)** — crossing the egress-bytes and request-count ceilings returns `DENY_QUOTA` and moves Active→Draining; in-flight finishes, new work refused.
- [ ] **Step 4: implement quota debit** in the `mediate` path (debit per effect; check before perform). Commit.

**Exit:** the full five-state session lifecycle + quotas are host-tested; revocation is O(1) and total; `DENY_QUOTA` fires at the ceiling; illegal transitions fail closed.

---

# Task W2 — Endpoint compartment (U-mode, sim)

**Files:** Create `crates/monitor-bin/src/endpoint.rs` (a U-mode compartment: pull bytes from a mock serial source into SHARED_REQ, `wire::deframe`, relay the inner frame to M via `ecall`); modify `simtrap.rs`/`sim/redoubt_soc.py` (a mock serial-in source; the relay); Test: xtask `endpoint` scenario.

**Interfaces:** Consumes `wire::deframe` (W3), the Phase-1 MEDIATE ecall path (V4). Produces a U-mode courier that turns a framed byte stream into a MEDIATE call and a dropped-frame counter visible to M.

- [ ] **Step 1: failing xtask `endpoint` scenario** — feed a valid framed benign request through the mock serial → the Endpoint deframes → relays → M mediates → ALLOW; feed a CRC-corrupt frame → dropped, counter ticks, no mediation. (Review-Focus 1,6.)
- [ ] **Step 2: implement the Endpoint** (U-mode, `no_std`): bounded read, `wire::deframe`, on success `ecall MEDIATE`, on drop bump the counter; it reads no policy, resolves no cap, holds no secret.
- [ ] **Step 3: authority test (Review-Focus 6)** — a malformed/oversized frame from the Endpoint still returns `DENY_MALFORMED` at the Monitor; prove replacing the Endpoint's logic cannot produce an effect policy would deny (it only relays bytes). Commit.

**Exit:** on the sim SoC, a framed request flows serial→Endpoint(U)→M→verdict; corrupt frames drop-and-count; the Endpoint has no authority.

---

# Task W1 — Minimal Warden + cooperative scheduler (sim)

**Files:** Create `crates/monitor-bin/src/warden.rs` (U-mode minimal scheduler) + the M-side context-handoff in `simtrap.rs` (save/restore U context, PMP region reprogram, timer slice); Test: xtask `warden` scenario.

**Interfaces:** Consumes W2 Endpoint, the M-mode trap handler (V3/V4), `pmp::lock_regions`/per-compartment grant. Produces a minimal scheduler that runs the Endpoint with an M-fielded timer slice and relays its ecalls.

- [ ] **Step 1: failing xtask `warden` scenario** — the Warden schedules the Endpoint; a request round-trips; a compartment that spins past its slice is timer-preempted (M bounds it) and the device stays responsive. (Review-Focus 7, reconciliation R3-A/B/D.)
- [ ] **Step 2: implement the M-side handoff** — on the machine timer (traps to M), save the running U context, reprogram the compartment PMP grant, resume the scheduled U context; the scheduler *policy* (round-robin over the live set, here just the Endpoint) is minimal U-mode code.
- [ ] **Step 3: liveness-without-trust test (Review-Focus 7)** — a wedged Warden can stall progress but CANNOT cause an unauthorized effect (mediation still gates every call; the Phase-2 PMP walls still hold). Document the deferred full-preemptive-multi-driver Warden (needs a supervisor-capable core / MMU) per R3-D. Commit.

**Exit:** a minimal Warden schedules the Endpoint under an M-fielded timer slice; a runaway compartment is preempted; a compromised Warden still cannot breach the Monitor. The full MMU/S-mode Warden is a documented follow-up.

---

## Self-review

**Spec coverage.** Ch 6 wire → W3 (framing) + W2 (Endpoint courier); Ch 8 policy → W5 (compiler + golden); Ch 7 caps → W5 (emits Cap) + W4 (session cspace); Ch 11 Warden/compartments/sessions → W1 (Warden/scheduler, reconciled), W2 (Endpoint), W4 (sessions/quotas/revocation). Every Ch-11 invariant (§11.10) maps to a Review-Focus test. The M+U/PMP divergences from Ch 11's S-mode/MMU prose are enumerated in R3-A..E and each handled in the owning task.

**Placeholder scan.** No "TBD/handle edge cases". The hard reconciliations (scheduler mechanism in M, PMP-not-MMU isolation, IPC copy via M) are named decisions (R3-A..D), and the full preemptive/multi-driver Warden is an explicit deferral with a stated reason, not hidden work.

**Type consistency.** W5 emits exactly the Phase-1 `predicate::{Clause,ConstPool}` / `cap::Cap` / `flow::FlowRule` the Monitor consumes (golden-tested). W4 extends Phase-1 `Session`/`Sessions`. W3's `wire` is consumed by `host-sdk` and W2's Endpoint. `abi` opcodes/req layout reused verbatim.

**Review Focus.** 7 items, each pinned to a task with a concrete test; items 6–7 (Endpoint-has-no-authority, liveness-without-trust) are the load-bearing "compromised lower tier changes nothing" properties and get explicit adversarial tests.

## Notes for the executor
- W3 and W5 are pure host logic (`cargo test`, no sim) — fastest loop; build them first to unblock W2/W4.
- Keep every Phase-2 scenario green; the sim tasks (W2/W1) reuse the Phase-2 Verilator plumbing + the pinned `nightly-2026-09-26`.
- W1 is the hardest and most reconciled task — keep it MINIMAL (one live compartment, cooperative + a timer bound). Resist building a full RTOS; the full Warden waits for a supervisor-capable core.
- When W5's compiler lands, the Phase-1 hand-built `Policy` fixture becomes a test fallback, not the source of truth — a small but real step toward "policy is a written, audited manifest."
