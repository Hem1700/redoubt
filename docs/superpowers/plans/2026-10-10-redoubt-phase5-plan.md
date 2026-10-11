# Redoubt Phase 5 — Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two honest gaps the design has carried since Phase 2, in the two ways that need no board: a **bus-level egress gate** so a user-mode (or rogue) master genuinely cannot reach egress (not just "by construction"), and a **machine-checked model** of the six-stage decision chain that turns the Chapter 13 §13.2 proof *sketch* into checked properties. The third hardening item (an authenticated/encrypted bitstream) is board-gated and is deferred to the board.

**Architecture:** Phases 1-3 built + simulated the monitor and its stack; Phase 4 F1 proved it fits the ECP5. Two Phase-2/3 honesty caveats remain: (1) on this core CPU MMIO *bypasses PMP*, so U is kept out of the egress registers only "by construction," not by an enforced boundary; (2) the mediation chain is argued by a prose sketch, not a proof. Phase 5 addresses both without hardware. **H1** adds a custom RTL mediation gate on the egress bus in the LiteX SoC (RISC-V IOPMP is not available off-the-shelf in LiteX/VexRiscv, so we build the gate), tested in Verilator: a non-monitor transaction to egress is blocked. **H3** writes Kani (bounded model checking) proof harnesses over the frozen `monitor` crate, proving the load-bearing properties of `mediate` (a non-ALLOW verdict performs no effect and returns no secret; stage ordering; no panic on arbitrary input). **H2** (ECP5 AES-256 encrypted + OTP-fused-key bitstream) needs the physical chip's OTP and is deferred.

**Tech Stack:** LiteX/Migen (the custom egress-gate peripheral) + Verilator (the Phase-2/3 sim toolchain in `sim/`), Kani (`cargo kani`, a bounded model checker for Rust) on the host for the `monitor` crate, `cargo xtask`. No board.

**Spec:** `docs/architecture/components/13-assurance.html` (§13.2 the mediation-chain sketch to formalize, §13.5-13.6 the honest gaps + the roadmap: the bus-level gate, the formal model, the authenticated bitstream), `04-soc.html` §4.7 (DMA and the limit of PMP), `03-isolation.html` §3.9 (the MMIO-bypasses-PMP implementation note). Phases 1-4(F1) merged/local on `worktree-redoubt-v1`.

---

## Grounding checklist (the two feasibility spikes, resolve first)

Like Phase 2's G-items, the two buildable tasks each hinge on one feasibility question. Close them in each task's Step 1 before the dependent work.

- **G5-A — the egress gate needs an origin signal (H1).** A bus-level gate can only admit "monitor-authorized" egress transactions if it can tell them from a compartment's. Determine how: (a) does the VexRiscv-`secure` core expose the current *privilege mode* (M vs U) on the bus/a side-channel the gate can read, so the gate opens the EGRESS_MMIO window only while the CPU is in M-mode? or (b) a monitor-written capability token/arm register (in the M-only region) that the gate checks per transaction? Option (a) is cleaner if the privilege signal is reachable; (b) is a fallback that works regardless. The spike decides which, by inspecting what the LiteX/VexRiscv bus exposes. This is the make-or-break for H1.
- **G5-B — Kani on the `no_std` monitor (H3).** Confirm `cargo kani` installs and runs on the `monitor` crate (it is `no_std` + `#![forbid(unsafe_code)]`, which suits Kani/CBMC). Determine which inputs can be made bounded-nondeterministic (`kani::any()`): a `RequestView` over a bounded byte buffer, a small `Policy`/`Sessions` fixture, a bounded cspace. The first proof target is the §13.2 chain: **a non-ALLOW verdict drives no egress and returns no secret.** If full `mediate` is too large for CBMC to discharge in reasonable time, prove the per-stage properties and the composition separately (documented).

---

## Global Constraints

- **The honesty bar is the point of this phase. Do NOT claim "formally verified."** H3 produces *machine-checked properties via bounded model checking* (Kani/CBMC), which is strictly weaker than a full functional-correctness proof (seL4-grade). Every artifact (code comments, the manual, any README line) must say exactly that: which properties are checked, under what bounds, and that the core's RTL + the compiler remain trusted-not-proven. The manual (Ch 13) already refuses the phrase "formally verified"; keep it refused.
- **The `monitor` + `abi` + `wire` + `policyc` logic stays FROZEN and `#![forbid(unsafe_code)]`.** H3 adds Kani proof harnesses (behind a `kani`/`#[cfg(kani)]` gate or a `proofs/` module) that do not change the logic. H1 adds RTL + a sim scenario, not monitor logic.
- **H1 closes the Phase-2 F2 gap honestly.** The Phase-2 finding was that MMIO bypasses PMP so U can reach EGRESS_MMIO. H1's gate must make a U-mode (or any non-monitor) egress transaction *fault or be dropped* in the Verilator sim. Prove it with the same adversarial shape as the Phase-2 `pmp` scenario. It is a custom RTL gate (document it as such, not "IOPMP"); real RISC-V IOPMP remains a further-future note.
- All Phase 1-4 suites stay green: host `cargo test`, `cargo clippy -- -D warnings` (the CI gate), and `cargo xtask verilator -- {boot,pmp,measure,mediate,endpoint,warden}`. H1 adds an `egress-gate` scenario; it must not regress the others.
- No board; no push without explicit consent. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

1. **The gate actually blocks non-monitor egress (H1).** A U-mode compartment writing EGRESS_MMIO must be blocked/faulted by the gate (not merely "by convention"). Test: the exact Phase-2 F2 scenario (U pokes egress) now fails closed at the gate; and a legitimate monitor (M) egress still succeeds.
2. **The gate's origin signal is sound (H1).** Whatever distinguishes a monitor transaction from a compartment's (privilege signal or armed token) cannot be forged by U. Test: a compartment cannot set the condition that opens the gate.
3. **The checked property is the real one (H3).** The Kani harness must prove the load-bearing claim (non-ALLOW ⇒ no egress effect, no secret returned), with `kani::any()` inputs, not a fixed example. A harness that only checks one concrete input proves nothing.
4. **Honest scope of the proof (H3).** The harness's bounds and assumptions are documented; the project does not over-claim. Test (review): the wording in code + any doc says "machine-checked under these bounds," never "formally verified."
5. **No regression (both).** The frozen logic is unchanged; all prior scenarios + host tests + clippy stay green.

---

# Task H1 — Custom RTL egress mediation gate (Verilator)

**Files:** Add the gate to `sim/redoubt_soc.py` (a Migen/LiteX module on the EGRESS_MMIO bus path); a U-mode prober in the sim image (reuse the Phase-2 `pmp`/W2 Endpoint U-stub shape); `xtask` `egress-gate` scenario. Test: the gate scenario.

**Interfaces:** Produces an egress-bus gate that admits only monitor-originated (M-mode / armed) transactions to `EGRESS_MMIO 0xF000_0000`; a compartment transaction is blocked (bus error / dropped + a counter). Consumes the Phase-2/3 SoC + the privilege/origin signal from G5-A.

- [ ] **Step 1 (spike, closes G5-A):** determine the origin signal — inspect whether the VexRiscv-`secure` core / the LiteX bus exposes the CPU privilege mode to a peripheral; pick option (a) M-mode-gated window or (b) monitor-armed token. Prototype the smallest gate that compiles into the SoC and elaborates in Verilator.
- [ ] **Step 2 (failing test):** `xtask verilator -- egress-gate`: a U-mode compartment attempts to write/read EGRESS_MMIO → assert it is blocked (fault or a dropped-and-counted transaction, no egress effect); a monitor (M) egress to the same window succeeds. Run: expect FAIL (no gate yet).
- [ ] **Step 3:** implement the gate (Migen) on the egress path; wire the origin signal; the monitor's existing egress sink still works through it.
- [ ] **Step 4 (Review-Focus 1,2):** the U access is blocked at the gate; a compartment cannot forge the open condition; the Phase-2 F2 gap is closed for the CPU-MMIO path. Keep the other sim scenarios green. Commit.

**Exit (H1):** in Verilator, a non-monitor egress transaction is blocked at the bus gate (closing the MMIO-bypasses-PMP gap), while legitimate monitor egress still works; documented as a custom RTL gate (real IOPMP is a further-future note).

---

# Task H3 — Machine-checked model of the mediation chain (Kani)

**Files:** A `crates/monitor/proofs/` module or `#[cfg(kani)]` harnesses in the `monitor` crate; an `xtask kani` (or documented `cargo kani`) runner; a short `docs/` note on what is checked and under what bounds. Test: the Kani proofs discharge.

**Interfaces:** Produces Kani proof harnesses over `mediate` (and/or the six stages) that CBMC discharges, proving the load-bearing invariants. Consumes the frozen `monitor` logic unchanged.

- [ ] **Step 1 (spike, closes G5-B):** install Kani; get a trivial harness to discharge on the `monitor` crate (confirm `no_std` + the toolchain work). Decide the input-bounding strategy (`kani::any()` over a bounded request buffer + a small Policy/Sessions fixture).
- [ ] **Step 2 (the load-bearing proof, Review-Focus 3):** a harness that, for a bounded-nondeterministic request + fixture, proves **a non-ALLOW verdict from `mediate` performs no egress effect and returns no secret** (the §13.2 security property). If full `mediate` is too heavy for CBMC, prove it per-stage + compose, documented.
- [ ] **Step 3:** additional harnesses for the cheap, high-value invariants: `mediate` never panics on arbitrary input within bounds; stage ordering (a deny at stage N never reaches stage N+1's effect); `resolve` epoch-revocation (a stale handle never resolves).
- [ ] **Step 4 (Review-Focus 4):** write the honest scope note (checked properties, the bounds, the `kani::any()` assumptions, and that the VexRiscv RTL + rustc remain trusted-not-proven); wire `xtask kani` or document the `cargo kani` invocation; keep it out of the default `cargo test`/CI-clippy path (Kani is a separate, slower run). Commit.

**Exit (H3):** Kani discharges a machine-checked proof that a non-ALLOW `mediate` causes no egress effect and leaks no secret (plus no-panic, stage-ordering, revocation), with the bounds documented honestly and the "not formally verified" caveat intact.

---

# Task H2 (DEFERRED, board-gated) — authenticated/encrypted bitstream

Not implemented in this phase: it needs the physical ECP5's OTP fuses to verify. **When the board is in hand** (after Phase 4 F2): generate an AES-256 encrypted + authenticated bitstream (`ecppack`/the ECP5 flow), fuse the key into OTP, and confirm the device boots only the authentic bitstream, closing the root-of-trust gap beneath measured boot (Ch 13 §13.6). Recorded here so it is not dropped.

---

## Self-review

**Spec coverage.** Ch 13 §13.6 roadmap → H1 (bus-level gate), H3 (formal model), H2 (authenticated bitstream, deferred); §13.2 mediation-chain sketch → H3's proof target; Ch 4 §4.7 / Ch 3 §3.9 (MMIO/DMA bypass of PMP) → H1 is the enforced boundary that closes it. The honesty constraints (no "formally verified"; the gate is a custom RTL gate, not off-the-shelf IOPMP) come straight from Ch 13's own careful wording.

**Placeholder scan.** No "TBD": the two feasibility unknowns are explicit spikes (G5-A origin signal, G5-B Kani-on-no_std) closed in each task's Step 1; H2 is an explicit board-gated deferral with its procedure recorded, not hidden work.

**Type consistency.** H3 adds harnesses behind a `kani` cfg and does not touch the frozen `monitor` logic; H1 adds RTL + a scenario, reusing the Phase-2 `pmp`/W2 U-prober shape and the single-source memory map. No interface changes to the monitor.

**Review Focus.** 5 items: the gate blocks non-monitor egress + the origin signal is unforgeable (H1); the Kani harness proves the real property with nondeterministic inputs + the scope is stated honestly (H3); no regression (both). Each has a concrete test.

## Notes for the executor
- H1 and H3 are independent and both board-free; do them in either order. H3 (host, on the frozen logic) is the lower-risk, high-credibility one ("a machine-checked reference monitor"); H1 (RTL) has the bigger unknown (G5-A) but closes the demo's biggest honest gap.
- Keep the honesty bar front of mind: this phase's *value* is partly that it is honest about what is proven vs tested. Over-claiming here would undercut the whole flagship.
- H2 waits for the board; it rides along with Phase 4's hardware bring-up.
