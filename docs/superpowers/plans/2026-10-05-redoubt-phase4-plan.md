# Redoubt Phase 4: FPGA Bring-Up (ULX3S) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put Redoubt on real silicon: synthesize the SoC for the ULX3S (ECP5-85F), boot the measured monitor on the board, give it real network egress over an M-owned ESP32 link, show the verdict on the OLED/LEDs, and prove the SD/network DMA config is M-only, so the live containment demo (prompt-inject the host agent, watch Redoubt deny the exfil) runs on hardware.

**Architecture:** Phases 1-3 built and simulated the whole stack (Monitor + PMP + measured boot + wire/policy/sessions/compartments) on a Verilated LiteX + VexRiscv-`secure` SoC. Phase 4 re-targets that SoC generator from the Verilator platform to the real **ULX3S** platform (LiteDRAM for the onboard SDRAM, SPI flash, SD, the ESP32 UART link, the SSD1331 OLED, LEDs), synthesizes it with yosys + nextpnr-ecp5 + prjtrellis, flashes it with openFPGALoader, and wires the egress sink (a stub in sim) to the real ESP32 network path and the real storage. The monitor, policy compiler, and session logic are unchanged; Phase 4 is about the SoC platform, the physical egress, and the demo.

**Tech Stack:** LiteX + litex-boards (`ulx3s` platform), VexRiscv-`secure`, yosys + nextpnr-ecp5 + prjtrellis (all in the already-installed `sim/oss-cad-suite`), openFPGALoader (to be installed) for flashing, the pinned Rust `nightly-2026-09-26` + `riscv32ima` + `-Z build-std`, `cargo xtask`. Board: **ULX3S ECP5 LFE5U-85F**, 32 MB SDRAM, ESP32 (wifi), microSD, QSPI flash, 11 LEDs + optional SSD1331 OLED.

**Spec:** `docs/architecture/components/04-soc.html` (SoC + memory map), `12-egress.html` (ESP32/SD/TRNG/OLED, the M-owned egress), `05-boot.html` (measured boot, now from QSPI/SD on real HW), `13-assurance.html` (§DMA, the Phase-5 roadmap), `docs/design/2026-09-22-hardware-plan.md` (board choice + the honest ESP32 caveat). Phase 3 merged at `origin/main` `c8a0dba`.

---

## Board-gating: what can start now vs what waits for the ULX3S

**You do not have the board yet.** This plan is written so the board-independent work can start immediately and the hardware work queues cleanly for when it arrives.

- **F1 (SoC re-target + synthesis + timing) is board-INDEPENDENT.** It produces a bitstream and a fit/timing report using yosys + nextpnr-ecp5 + prjtrellis, which are already in `sim/oss-cad-suite`. We can confirm our SoC *fits* the ECP5-85F and meets timing before the board ever arrives. **Do F1 now.**
- **F2-F5 are board-GATED.** Flashing, booting on hardware, ESP32 egress, the OLED, and the DMA proof all need the physical board (and `openFPGALoader`, and an ESP32 flashed as a wifi modem). Draft and stage them; execute when the board is in hand. Each F2-F5 task names its hardware dependency up front.
- The Verilator simulation (Phases 1-3) stays the regression oracle throughout: every verdict the board produces must match the sim/host `mediate` result for the same request.

---

## Global Constraints

- **The monitor/policy/session logic is FROZEN for Phase 4.** `crates/monitor` + `abi` + `wire` + `policyc` stay `#![forbid(unsafe_code)]` and unchanged except where a real peripheral replaces a sim stub behind a trait. Phase 4 changes the SoC platform and the egress/boot *backends*, not the decision logic. The host + Verilator suites must stay green.
- **Memory map is canonical** (Ch 4; same as sim): BROM, MON_CODE/MON_DATA/SECRETS (M-only), WARDEN, COMPARTMENTS, SHARED_REQ, SDRAM `0x8000_0000`, EGRESS_MMIO `0xF000_0000`. On hardware the monitor image + `H_expected` live in QSPI flash / SD; SDRAM (MT48LC32M16, 32 MB) backs compartments.
- **Egress is M-owned (Ch 12).** The ESP32 (network) and the SD (storage) are driven only by the monitor, over links whose control registers sit in the M-only EGRESS_MMIO region. The agent/compartments have no direct path. **Honest caveat (carry it, do not hide it):** the ESP32 runs closed-ish firmware, so it is in the egress trust path for v1; a wired-Ethernet ECP5 board is the documented upgrade. The real bus-level wall (IOPMP) is Phase 5.
- **TRNG:** real session nonces/epoch seeds need hardware randomness (Ch 12: ring-oscillator + NIST SP 800-90B health tests). The sim uses a deterministic-seed stub; the board uses the TRNG. Keep the deterministic stub for sim regression.
- **Determinism unchanged:** no clock/RNG on the mediation *decision* path (the TRNG feeds session setup, not a verdict).
- All new unsafe stays in `monitor-bin` (peripheral drivers) behind the board target. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- CI gate for every task: `cargo test` AND `cargo clippy -- -D warnings` green (the clippy gate is now part of the loop, per the Phase-3 lesson), plus the relevant Verilator scenarios still green.

## Review Focus

Hardware failure modes the spec implies; each pinned to a task.

1. **Fit + timing (F1).** The SoC must fit the ECP5-85F and meet the target clock; a design that routes but fails timing will behave nondeterministically on the board. Test: nextpnr reports a passing timing summary at the chosen `sys_clk`.
2. **Measured boot on real NV (F2).** The BROM must measure the monitor image as loaded from QSPI/SD and halt on tamper, exactly as in sim. Test: a byte-flipped image in flash halts before the banner on the board.
3. **Egress is M-only, end to end (F3).** A compartment (U) must have no path to the ESP32 or SD control registers; only the monitor drives them. Test: a U-mode poke at EGRESS_MMIO faults (PMP where it can; and the control path is M-only by construction), and a real outbound request carries the injected secret while the response to the agent does not.
4. **Verdict is observable and honest (F4).** ALLOWED/DENIED + the reason must display correctly for each demo case; a denial must never light "allowed". Test: the three demo requests drive the expected OLED/LED state.
5. **DMA config is M-only (F5, Review-Focus from Ch 4 §4.7).** PMP cannot filter a DMA master's transfers, but the SD/network DMA *configuration* registers must be reachable only by the monitor, so a U-mode driver cannot program a transfer that bypasses mediation. Test: the DMA config registers sit in the M-only region and a U access faults; documented honestly as a partial mitigation pending IOPMP (Phase 5).

---

# Task F1: ULX3S SoC target + synthesis + timing  *(board-independent; do now)*

**Files:** Modify/extend `sim/redoubt_soc.py` (or add `sim/redoubt_ulx3s.py`) to target the litex-boards `ulx3s` platform; add `crates/monitor-bin/link-fpga.ld` (the FPGA memory map, monitor image placement for QSPI/SDRAM); extend `xtask` with a `synth` command. Test: the nextpnr timing report + a fit check.

**Interfaces:** Produces an ULX3S-targeted `RedoubtSoC` (VexRiscv-`secure`, LiteDRAM for MT48LC32M16, UART, SPI flash, SD, ESP32 UART, LEDs, optional SSD1331 OLED; EGRESS_MMIO as the M-only peripheral window), a bitstream, and a fit/timing report. Consumes the Phase-1-3 monitor image (retargeted to the FPGA map).

- [ ] **Step 1 (grounding spike):** stand up the `ulx3s` LiteX platform with the VexRiscv-`secure` core + LiteDRAM + UART, and run `yosys` + `nextpnr-ecp5` (from `sim/oss-cad-suite`; install litex-boards in the venv) to the point of a routed design. Confirm the `secure` core + LiteDRAM fit the 85F. NOTE: synthesis is minutes-to-tens-of-minutes; be patient.
- [ ] **Step 2:** add the 8-region memory map on the real platform (SDRAM-backed compartments, QSPI/SD-backed monitor image + `H_expected`, EGRESS_MMIO window over the ESP32/SD/OLED control regs). Single source shared with the Rust map (reuse the Phase-2 `memory_map.json` mechanism).
- [ ] **Step 3:** `link-fpga.ld` + build the monitor/BROM images for the FPGA map (same nightly `riscv32ima` + build-std).
- [ ] **Step 4:** `cargo xtask synth` runs the flow end to end and asserts nextpnr's timing summary PASSES at the chosen `sys_clk` (Review-Focus 1). Produce the bitstream artifact. Commit.

**Exit (F1):** a bitstream for the ULX3S-targeted Redoubt SoC exists and meets timing; the fit report is recorded. No board needed. This de-risks the whole phase.

---

# Task F2: Flash + measured boot on hardware  *(board-gated: needs ULX3S + openFPGALoader)*

**Files:** `xtask` flash/run commands (openFPGALoader); the QSPI/SD monitor-image + `H_expected` loader; the hardware UART path. Test: on-board boot + a `--tamper` variant.

- [ ] **Step 1:** install + wire `openFPGALoader`; flash the F1 bitstream to the ULX3S; confirm the monitor banner over the hardware UART (the sim banner, now on real silicon). [HW]
- [ ] **Step 2:** load the monitor image + `H_expected` from QSPI flash (or SD); the BROM measures it on the real NV path and jumps or halts. [HW]
- [ ] **Step 3 (Review-Focus 2):** flash a byte-flipped monitor image; assert the BROM tamper-halt fires on the board and the banner never appears. Wire the **TRNG** (ring-oscillator) for session nonces, keeping the deterministic-seed stub for sim. [HW]
- [ ] **Step 4:** commit; record the on-board boot + tamper-halt evidence (serial logs / photos).

**Exit (F2):** the measured monitor boots on the physical board, and a tampered image halts in the BROM before anything runs.

---

# Task F3: ESP32 network egress (M-owned) + real request  *(board-gated: ULX3S w/ ESP32)*

**Files:** `crates/monitor-bin` egress backend: a real `EgressSink` implementation driving the ESP32 over the M-owned link (replacing the EGRESS_MMIO mock behind the existing trait); the ESP32 configured as a wifi modem. Test: a real outbound HTTPS GET with the injected header.

- [ ] **Step 1:** bring up the ESP32 as an FPGA-driven wifi modem (AT-command or an SPI/UART modem firmware); the link's control registers live in the M-only EGRESS_MMIO window. [HW]
- [ ] **Step 2:** implement the real `EgressSink` against that link; a `MEDIATE`-allowed `http.request` performs a genuine HTTPS GET to the allowed host, with the monitor injecting the API key the agent never saw. [HW]
- [ ] **Step 3 (Review-Focus 3):** prove egress is M-only: a U-mode compartment poking the ESP32/SD control registers faults (PMP where applicable) and the control path is M-only by construction; the injected secret appears in the outbound request but NEVER in the response handed back to the agent. Carry the honest ESP32-firmware-in-the-path caveat in the report + manual. [HW]
- [ ] **Step 4:** commit; record the real allowed-vs-denied egress evidence (a captured request, a denied exfil).

**Exit (F3):** a live, allowed tool call reaches the network with the secret injected; a denied one does not; the agent never sees the secret.

---

# Task F4: Verdict display (OLED / LEDs)  *(board-gated)*

**Files:** `crates/monitor-bin` display backend (SSD1331 SPI OLED driver, with an LED fallback that is always available). Test: the three demo cases drive the expected display.

- [ ] **Step 1:** SSD1331 OLED driver (M-driven, over the M-only SPI in EGRESS_MMIO); if the OLED footprint is unpopulated, fall back to the 11 LEDs (guaranteed on every ULX3S). [HW]
- [ ] **Step 2 (Review-Focus 4):** on each verdict, show ALLOWED / DENIED + the reason code; assert a denial never shows "allowed". Drive the three demo requests and check the display state. [HW]
- [ ] **Step 3:** commit; record the demo (video/photos of the verdict display).

**Exit (F4):** the board visibly shows ALLOWED/DENIED + reason for each demo request, honestly.

---

# Task F5: DMA-config-is-M-only proof + the hardware containment demo  *(board-gated)*

**Files:** the SD/network DMA config placement (M-only region) + a U-mode fault test; the end-to-end demo script. Test: a U access to the DMA config faults; the full containment demo on the board.

- [ ] **Step 1 (Review-Focus 5):** place every SD/network DMA *configuration* register in the M-only region; a U-mode driver attempting to program a DMA transfer faults. Document honestly: PMP does not filter the DMA master's transfers themselves, so this is a partial mitigation (U cannot *initiate* an unmediated transfer); the full bus-level wall is RISC-V IOPMP in Phase 5 (Ch 4 §4.7, Ch 13). [HW]
- [ ] **Step 2 (the Phase-4 payoff):** run the full containment demo on the board: a (prompt-injected) host agent issues the benign request (ALLOW, real egress, secret injected, OLED shows ALLOWED), the wrong-host request (DENY_ARG, OLED shows DENIED, no egress), and the secret-to-public request (DENY_FLOW). Every verdict matches the sim/host `mediate` oracle for the same bytes. [HW]
- [ ] **Step 3:** commit; record the demo end to end.

**Exit (F5) = Phase-4 exit:** the live containment demo runs on the ULX3S: an allowed call reaches the network with an injected secret, a hijacked/ungranted call is denied with the verdict on the display, DMA config is M-only, and every board verdict matches the simulation. The ESP32-firmware and DMA-transfer gaps are documented, handed to Phase 5 (IOPMP).

---

## Self-review

**Spec coverage.** Ch 4 (SoC/board/memory map, §4.7 DMA) → F1 + F5; Ch 12 (ESP32 egress, SD, TRNG, OLED) → F2 (TRNG) + F3 (ESP32/SD) + F4 (OLED); Ch 5 (measured boot from real NV) → F2; Ch 13 (DMA gap, IOPMP roadmap) → F5 + the Phase-5 handoff. The monitor/policy/session logic is unchanged (frozen), so no Ch 6-11 re-coverage is needed; the Verilator suite guards against regressions.

**Placeholder scan.** No "TBD". The board-gating is explicit (F1 now; F2-F5 marked [HW]); the honest caveats (ESP32 firmware in the path, DMA-transfers vs DMA-config, OLED-optional-so-LED-fallback) are named decisions, not hidden work.

**Type/interface consistency.** The egress + display + TRNG are swapped behind existing traits/stubs (the Phase-2/3 `EgressSink` and the sim stubs), so the frozen logic consumes real backends unchanged. The FPGA memory map reuses the Phase-2 single-source mechanism. Every board verdict is checked against the sim/host `mediate` oracle.

**Review Focus.** 5 items: fit+timing (F1), measured boot on NV (F2), M-only egress (F3), honest verdict display (F4), DMA-config-M-only (F5). Each has a concrete hardware test; item 5 is honestly a partial mitigation with the full fix scoped to Phase 5.

## Notes for the executor
- **Start F1 now**, it is board-independent, de-risks the ECP5 fit/timing, and the toolchain (yosys/nextpnr-ecp5/prjtrellis) is already in `sim/oss-cad-suite`. Install `litex-boards` in the sim venv for the `ulx3s` platform.
- Buy the ULX3S **85F with the ESP32 populated** (for F3) and optionally the **SSD1331 OLED** (F4 is nicer with it; the LED fallback always works).
- Keep the Verilator simulation as the regression oracle: if a board verdict ever disagrees with sim for the same request, the board build is wrong, not the logic.
- The ESP32-firmware-in-the-egress-path and DMA-transfer gaps are the honest limits of this board; they go to Phase 5 (IOPMP / a wired-Ethernet board / an RTL egress gate), and the manual already carries the shape of these caveats.
