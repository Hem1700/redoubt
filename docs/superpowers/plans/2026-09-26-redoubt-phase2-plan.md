# Redoubt Phase 2 — PMP + Measured Boot (Verilator) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Phase-1 software monitor into a *hardware-enforced* one: boot the monitor image on a simulated RISC-V SoC (VexRiscv + PMP, in Verilator), have a boot ROM measure it before it runs, and have the monitor lock PMP so a supervisor/user-mode takeover provably cannot reach the secrets, the egress hardware, or the monitor's own memory.

**Architecture:** A LiteX-generated SoC (`sim/redoubt_soc.py`) instantiates a VexRiscv core with M/S/U privilege and a `PmpPlugin`, laid out on the canonical Redoubt memory map. A tiny boot ROM (`crates/brom`) at address 0 measures the monitor image with BLAKE2s against a baked hash and halts on mismatch. The monitor's M-mode startup programs and locks the 8 PMP entries *before* dropping to a minimal S-mode Warden that `mret`s to a U-mode stub. The Phase-1 `mediate` pipeline is unchanged; Phase 2 wraps it in real hardware isolation and proves the walls hold with fault-injection tests run under Verilator via `cargo xtask verilator`.

**Tech Stack:** LiteX (Python SoC generator), VexRiscv (SpinalHDL RISC-V core with `PmpPlugin`), Verilator (cycle-accurate C++ sim, driven by `litex_sim`), Rust `no_std` (`riscv32imac-unknown-none-elf`) for BROM/monitor/warden images, `blake2` (measured boot), `cargo xtask` automation. Host: macOS (`brew install verilator`; LiteX via `litex_setup.py`/pip; `oss-cad-suite` optional here, required Phase 4).

**Spec:** `docs/architecture/components/03-isolation.html` (PMP, the region table, the lock/Smepmp story, the DMA caveat), `docs/architecture/components/04-soc.html` (SoC + memory map), `docs/architecture/components/05-boot.html` (measured boot, "measure → lock → descend"), `docs/design/2026-09-22-redoubt-architecture-v1.md`, `docs/architecture/AGENT_BRIEF.md` (canonical facts). Phase-1 code merged at `main` (commit `1722022`).

---

## Grounding checklist (status as of 2026-09-26 research pass)

Items marked ✅ were resolved by researching the live LiteX/VexRiscv sources; ⚠️ items still need an empirical check (they close cheaply inside V1's spike step, or need the toolchain installed first).

- **G1 — VexRiscv PMP variant. ✅ RESOLVED.** LiteX ships a **`secure`** VexRiscv variant as a *prebuilt* `secure.v` netlist in `pythondata-cpu-vexriscv` (retrieved by `litex/soc/cores/cpu/vexriscv/core.py`; NOT generated on the fly), built with `--pmpRegions 16 --pmpGranularity 256` and **TOR** support. So: `--cpu-type=vexriscv --cpu-variant=secure`. **No SpinalHDL/`sbt` rebuild.** Existence proof: Zephyr's `litex_vexriscv` runs PMP + user mode.
- **G2 — PmpPlugin capabilities. ✅ mostly.** 16 regions (need 8) ✓; granularity 256 B ✓ (all our regions ≥ 4 KiB and 256-aligned); **TOR** ✓. **Smepmp/`mseccfg`: NOT present** in LiteX's VexRiscv → take Ch 3 §3.4's honest fallback: SECRETS + EGRESS are **left undescribed to S/U** (deny-by-default for S/U; M reaches them by PMP exemption). ⚠️ NAPOT reliability in this netlist is unconfirmed and historically buggy → **use TOR throughout** (see the revised encoding rule below), which `secure` explicitly supports.
- **G2b — ISA match. ⚠️ NEW, check in V1.** The `secure` variant's GCC flags are `-march=rv32i2p0_ma` (rv32i + **M** + **A**, *no compressed C*). Phase-1 images are `riscv32imac`. Confirm whether the `secure` core decodes the C extension; if it does not, **retarget the BROM/monitor/warden images from `riscv32imac` to `riscv32ima`** (drop the `c`). Cheap to test: build a tiny image both ways and see which runs.
- **G3 — litex_sim image loading. ⚠️ check in V1.** Load three images into their regions: BROM at 0x0 (init the integrated-ROM/a ROM `SoCRegion`), monitor at 0x1000_0000, warden at 0x2000_0000. Likely per-region `init=`/`--rom-init`/`--ram-init`. Confirm the mechanism and that reset = 0x0 lands in the BROM.
- **G4 — Fault observation. ✅ approach fixed.** Architectural, mirroring Phase-1's `cargo xtask qemu`: the PMP trap lands in the monitor's fault handler, which prints a known UART line (`PMP-FAULT mcause=… addr=…`) and writes a finisher/sentinel; the harness asserts on that line + exit. Confirm LiteX-sim's finisher (`sim_finish`/`--finish`) exists, else UART sentinel + timeout.
- **G5 — Reset vector. ✅ RESOLVED.** `VexRiscv.set_reset_address()` exists and drives `i_externalResetVector`; `redoubt_soc.py` calls it with `0x0` so reset enters the BROM.
- **G6 — Toolchain install. ⚠️ LiteX ✅ / Verilator BLOCKED on this host.** LiteX side is **empirically working** in a Python **3.11.2** venv (brew `python@3.11` already present): pinned `litex 2024.12`, `migen 0.9.2`, `pythondata-cpu-vexriscv 1.0.1.post407`, and the `lite*` companions (`litedram/liteeth/litesdcard/litespi/litescope/liteiclink` all `2024.12`/`2025.4`) — `litex_sim --help` runs and exposes `--cpu-type/--cpu-variant/--rom-init/--ram-init/--integrated-rom-init/--sdram-init/--non-interactive/--trace`. Introspection confirms `secure → VexRiscv_Secure` with `VexRiscv_Secure.v` on disk. **Verilator is the blocker:** Homebrew treats this macOS (Darwin 27) as **Tier-3 unsupported** — `brew install verilator` prints the tier notice and installs nothing, and there is no bottle. **Recommended fix: install `oss-cad-suite`** (YosysHQ prebuilt tarball) which bundles **Verilator + yosys + nextpnr-ecp5** in one self-contained archive — it sidesteps Homebrew entirely AND provisions Phase-4's FPGA toolchain. Alternatives: build Verilator from source (fragile on Tier-3), or run the Verilator scenarios in a Linux container / CI only (develop locally against Verilog generation + host unit tests). Record the chosen path + exact versions in `sim/README.md`.

**Net: grounding COMPLETE (empirically verified 2026-09-26).** The full SoC with `--cpu-variant=secure` elaborates, generates includes, and produces the Verilator build files with no error (`litex_sim --cpu-type=vexriscv --cpu-variant=secure --no-compile --non-interactive` prints the CSR map + clean `INFO:SoC` finish); Verilator 5.053 runs independently. Only the actual verilator *compile + boot of a real image* is left — that is V1 Step 1's mechanical job, now fully de-risked.

### Verified toolchain recipe (put verbatim in `sim/README.md`)
- **Python 3.10** (`brew python@3.10`, tested 3.10.10). **NOT 3.11** — migen 0.9.2's clock-domain name auto-extraction fails on 3.11's changed frame internals (`ValueError: Cannot extract clock domain name`); **NOT 3.14** (system; LiteX unsupported). Make a venv with 3.10.
- **pip (into that venv):** `litex==2024.12`, `migen==0.9.2`, `pythondata-cpu-vexriscv` (1.0.1.post407), `litedram liteeth litesdcard litespi litescope liteiclink` (2024.12/2025.4), and the data modules `pythondata-software-picolibc`, `pythondata-software-compiler_rt`, `pythondata-misc-tapcfg` (all on PyPI — LiteX pulls them lazily during sim build). Network install; no `git+` needed.
- **Verilator:** Homebrew is Tier-3 on this macOS and installs nothing. Use **oss-cad-suite** (`YosysHQ/oss-cad-suite-build`, `darwin-arm64`, dated build; also bundles yosys + nextpnr-ecp5 for Phase 4). It extracts clean (no Gatekeeper quarantine). Provide its env to `litex_sim` by exporting `VERILATOR_ROOT=<suite>/share/verilator` and prepending `<suite>/bin` to PATH (the suite's `environment` script does this; `cargo xtask verilator` should set these two vars itself so the build is non-interactive).
- **Rust images:** keep the `riscv32imac-unknown-none-elf` target but emit rv32ima with `-C target-feature=-c` (the `secure` core is `rv32ima`, no compressed). Confirm in V1 Step 3 by booting a tiny image.
- **RISC-V GCC not required:** we never build the LiteX BIOS (`--no-compile-software`); we load our own Rust images via `--rom-init`/`--ram-init`/`--integrated-rom-init`. `cargo xtask verilator` drives `litex_sim` with these.

---

## Global Constraints

- **Memory map is canonical — copy these values verbatim** (Ch 3 §3.5 region table; Ch 4). Every address below is a hard fact:
  | # | Region | Range | M | S | U |
  |---|--------|-------|---|---|---|
  | 0 | BROM (measured boot) | `0x0000_0000`–`0x0000_2000` (8 KiB) | R-X | — | — |
  | 1 | MON_CODE | `0x1000_0000`–`0x1000_8000` (32 KiB) | R-X | — | — |
  | 2 | MON_DATA (caps, policy, log) | `0x1000_8000`–`0x1002_0000` (96 KiB) | RW- | — | — |
  | 3 | SECRETS | `0x1002_0000`–`0x1002_4000` (16 KiB) | RW- | — | — |
  | 4 | EGRESS_MMIO (ESP32/SD/TRNG) | `0xF000_0000`–`0xF001_0000` (64 KiB) | RW- | — | — |
  | 5 | WARDEN | `0x2000_0000`–`0x2010_0000` (1 MiB) | RWX | RWX | — |
  | 6 | SHARED_REQ buffer | `0x4000_0000`–`0x4000_1000` (4 KiB) | RW- | — | RW- |
  | 7 | COMPT_0 (per compartment) | `0x3000_0000`+ (backed by SDRAM `0x8000_0000`) | — | — | RW- (own) |
- **PMP encoding rule (grounded to the `secure` variant: 16 TOR entries, no Smepmp).** `pmpcfg` byte layout: bit7 `L`, bits4:3 `A` (0 off / 1 TOR / 2 NA4 / 3 NAPOT), bit2 `X`, bit1 `W`, bit0 `R`. Deny-by-default: an address in no entry is refused to S/U (and, for an *undescribed* region, still reachable by M via exemption). Use **TOR throughout** (avoid NAPOT — G2 flags its reliability in this netlist). TOR entry *i* covers `[pmpaddr[i-1], pmpaddr[i])`, matched first-hit, so scattered regions need an explicit lower-bound entry (`A=OFF`) before each TOR entry — with 16 entries and ~7 regions this fits comfortably. **Concrete plan:**
  - Describe the **S/U-visible** regions with locked (`L=1`) TOR entries: WARDEN (RWX for S), SHARED_REQ (RW for U), COMPT_0 (RW for its owner U), and the S/U-*denied* trusted regions BROM/MON_CODE/MON_DATA (locked, no S/U permission).
  - **SECRETS + EGRESS_MMIO: leave undescribed** (the no-Smepmp fallback) → denied to S/U by default, reachable only through the monitor's M-mode code path. Honest cost (per Ch 3 §3.4): no defense-in-depth against a *monitor* bug touching secrets. Record this in `sim/README.md`.
  - Lock (`L=1`) every trusted entry **before** any S/U instruction runs. `L=1` also constrains M — fine for the read-only/no-access ones; do NOT put an `L=1` rule on a region the monitor must RW (leave those either M-only-by-omission or unlocked-until-needed).
  - Generate the whole table from ONE source of truth in `redoubt_soc.py`, shared with the Rust `pmp.rs` (emit a `memory_map.json`/const header both sides read).
- TCB budget (extend the loc-gate this phase): Monitor ≤ 2500 LoC; **BROM ≤ 300**; the loc-gate must actually measure the BROM crate and `monitor-bin/arch.rs`+`pmp.rs` (fixes the Phase-1 stale-`brom`-path follow-up). `abi` counted toward the TCB tally as an informational line.
- All `unsafe` stays in the bare-metal crates (`brom`, `monitor-bin`, `warden`); the `monitor`/`abi` logic crates keep `#![forbid(unsafe_code)]` untouched.
- Determinism: no wall-clock/RNG on any decision or boot-measurement path. The BROM hash is over fixed bytes; `H_expected` is a build-time constant.
- Every task ends green under `cargo test` (host, unchanged Phase-1 suite still passes) AND its Verilator assertion (`cargo xtask verilator -- <scenario>`).
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

The failure modes the spec implies that a naive implementation gets wrong; each is pinned to the task whose test must exercise it.

1. **PMP lock timing (V2).** If the monitor drops to S-mode before locking PMP (or locks it a few instructions late), a fast Warden takeover has a window. Test: assert the S/U-visible walls are the ONLY thing reachable the instant Warden runs; a stage-ordering test that the lock CSR writes complete before the `mret`.
2. **Undescribed region ≠ open (V2).** A region accidentally left out of the PMP table must be *denied* to S/U, not silently accessible. Test: an S-mode access to an address in no entry faults.
3. **TOR/NAPOT mis-encoding (V2).** An off-by-one in a NAPOT size field or a TOR lower-bound silently shadows/opens a neighbour. Test: probe the exact boundary bytes of SECRETS (last byte denied, first byte of the next region behaves per its own rule).
4. **The lock genuinely locks (V2).** After `L=1`, even the monitor cannot rewrite the entry. Test: attempt a `pmpcfg` rewrite post-lock in M-mode and confirm it is a no-op (value unchanged).
5. **Tamper halts pre-Warden (V3).** A single flipped bit in the monitor image must halt in the BROM, before any S/U code — not "log and continue." Test: corrupt the image, assert the sim halts with the BROM's tamper signal and Warden never runs.
6. **Stack guard catches overflow (V3).** A forced M-stack overflow faults at a PMP no-access guard page, not silently into MON_DATA. Test: recurse/underflow the M stack, assert a fault at the guard address, not corruption of adjacent data.
7. **Self-fault fails closed (V3).** If the monitor itself trips a **locked** rule (a bug), it halts rather than limping on (Ch 3 edge cases + the Phase-1 fail-closed trap). Because there is no Smepmp (G2), SECRETS is undescribed and M *can* read it by design, so the self-fault guarantee is demonstrated on a **locked no-access region** instead: the M-stack guard page (V3). Test: an M-mode access to the locked guard page faults into the handler and halts.
8. **DMA is out of PMP's reach — state it, don't test a false guarantee (V4, doc).** PMP filters the CPU's own loads/stores only; a DMA master is not filtered. V4's egress mock must not imply otherwise; the honest caveat is carried in `sim/README.md` and Ch 3/13 (real IOPMP is Phase 5).

---

# Task V1 — LiteX SoC + Verilator harness + retargeted images

**Files:**
- Create: `sim/redoubt_soc.py` (LiteX SoC generator), `sim/README.md` (toolchain versions + how to run), `sim/requirements.txt` (pinned LiteX/migen/pythondata revs).
- Create: `crates/monitor-bin/link-sim.ld` (linker script for the SoC memory map; monitor image at `0x1000_0000`).
- Modify: `xtask/src/main.rs` (add a `verilator` subcommand that builds the images, runs `litex_sim`, and asserts on UART/exit — mirroring the existing `qemu` runner).
- Modify: `crates/monitor-bin/.cargo/config.toml` and `main.rs`/`arch.rs` as needed to build at the new base address.

**Interfaces:**
- Produces: `sim/redoubt_soc.py` exposing a `RedoubtSoC(SoCCore)` with the 8 regions above added as `SoCRegion`s, VexRiscv with `PmpPlugin` (G1/G2), `cpu_reset_address = 0x0` (G5), an `EGRESS_MMIO` CSR-backed mock region at `0xF000_0000`, and a UART. Verilatable via `litex_sim` (G3).
- Produces: `cargo xtask verilator -- <scenario>` that (1) cross-builds the needed image(s), (2) invokes `litex_sim` with the SoC + image init, (3) captures UART stdout with a timeout, (4) asserts scenario-specific sentinel lines + clean exit. Scenarios grow across V1–V4: `boot` (V1), `pmp` (V2), `measure` (V3), `mediate` (V4).

- [ ] **Step 1 (spike, closes G1/G2/G5):** stand up the minimal SoC — VexRiscv **with PmpPlugin, M/S/U, no MMU** — in `redoubt_soc.py`, reset vector 0x0, one RAM region + UART, and get `litex_sim` to elaborate and Verilate it. If no prebuilt PMP variant exists, regenerate the VexRiscv Verilog once via SpinalHDL and vendor it under `sim/vendor/` with its provenance in `sim/README.md`. **Exit of step:** `litex_sim` builds the Verilator model and prints the LiteX BIOS banner (or our banner) — proving the core + PMP CSRs exist in the model.
- [ ] **Step 2:** add the full 8-region memory map to `redoubt_soc.py` (BROM ROM region at 0x0, MON_CODE/MON_DATA/SECRETS at 0x1000_0000, WARDEN at 0x2000_0000, COMPT at 0x3000_0000 backed by SDRAM, SHARED_REQ at 0x4000_0000, EGRESS_MMIO CSR mock at 0xF000_0000). Keep the region defs as a single Python dict that also emits a header/const the Rust side reads (or a committed generated `sim/memory_map.json` consumed by a `build.rs`/xtask), so the map has ONE source of truth (Ch 3: "generated from a single source").
- [ ] **Step 3:** write `link-sim.ld` placing the Phase-1 monitor image at `0x1000_0000` (MON_CODE) with its data in MON_DATA, and retarget `monitor-bin` to build against it (a `--scenario`/feature or a second bin target). The Phase-1 QEMU image (0x8000_0000) must still build and pass `cargo xtask qemu` — do not regress it.
- [ ] **Step 4:** implement `cargo xtask verilator -- boot`: cross-build the retargeted monitor image, run `litex_sim` with it loaded at MON_CODE and reset temporarily pointed at MON_CODE (BROM comes in V3), assert the monitor's `"redoubt: monitor online"` banner appears on the sim UART and the run exits cleanly (G4). Document the exact `litex_sim` invocation in `sim/README.md`.
- [ ] **Step 5:** commit. `feat(sim): LiteX VexRiscv+PMP SoC boots the monitor image in Verilator`.

**Exit (V1):** `cargo xtask verilator -- boot` is green in a fresh checkout that followed `sim/README.md`; `cargo xtask qemu` still green; host `cargo test` unchanged.

---

# Task V2 — PMP lockdown + the fault assertion (Review-Focus 1–4, 7)

**Files:**
- Create: `crates/monitor-bin/src/pmp.rs` (the M-mode PMP programming: unsafe CSR writes for `pmpaddr0..7`/`pmpcfg0..1`(+`mseccfg` if Smepmp), driven by the shared memory-map constants).
- Modify: `crates/monitor-bin/src/main.rs`/`arch.rs` — call `pmp::lock_regions()` as the monitor's FIRST M-mode act, before any S/U code; add the fault handler path that reports `(mcause, mtval)` on a PMP fault and halts (extend the Phase-1 fail-closed trap).
- Modify: `sim/redoubt_soc.py` — add a tiny S-mode/U-mode "prober" stub image (or reuse the Phase-1 warden stub) that attempts the forbidden accesses for the test.
- Modify: `xtask` — add the `pmp` scenario.

**Interfaces:**
- Consumes: the memory-map constants from V1 (single source of truth).
- Produces: `pub fn lock_regions()` in `pmp.rs` that programs entries 0–7 per the encoding rule (NAPOT for standalone regions, TOR for MON_DATA), sets `L`/Smepmp bits, and returns only after every locked entry is committed. Produces a fault-report line on the UART of the exact form the `pmp` scenario asserts.

- [ ] **Step 1 (failing test):** author the `pmp` scenario in xtask + a prober stub that, from **S-mode**, issues `lw` from an address inside SECRETS (`0x1002_0100`) and from EGRESS_MMIO; and from **U-mode**, `lw` from WARDEN and from MON_DATA. Assert the sim prints the fault line (`PMP-FAULT mcause=5 addr=0x10020100` for a load-access fault, `mcause=7` for stores per Ch 3's worked example) for each, and that a control access to each mode's OWN region succeeds. Run: expect FAIL (pmp.rs not written).
- [ ] **Step 2:** implement `pmp::lock_regions()` — the NAPOT/TOR encoding from the Global Constraints, generated from the shared map. Program entries, set lock+Smepmp, `fence`/`fence.i` as needed.
- [ ] **Step 3:** wire `lock_regions()` as the monitor's first act; only after it returns does the monitor `mret` toward the (stub) Warden. Assert the ordering in code (no S/U entry path exists before the call).
- [ ] **Step 4 (Review-Focus 2,3,4):** extend the scenario: (a) an access to an **undescribed** address (e.g. a gap between regions) faults for S/U; (b) probe the **exact boundary** — last byte of SECRETS denied, first byte of the following described region behaves per its own rule; (c) after lock, an **M-mode rewrite** of `pmpcfg` for a locked entry is a no-op (read back unchanged). Assert all.
- [ ] **Step 5 (Review-Focus 7):** self-fault — an **M-mode** read of a Smepmp-denied SECRETS byte (simulating a monitor bug) faults into the handler and **halts** (finisher fail), not limps on. (If Smepmp is unavailable per G2, document the fallback and assert the locked-rule behaviour that IS achievable.)
- [ ] **Step 6:** run `cargo xtask verilator -- pmp` green; commit. `feat(sim): PMP lockdown + fault assertions (S/U walls, lock immutability, self-fault halt)`.

**Exit (V2):** the `pmp` scenario proves every S/U access to a trusted region faults, own-region access succeeds, locks are immutable, and a self-fault halts. This is the core "unbypassable" evidence.

---

# Task V3 — Measured boot + stack guard (Review-Focus 5, 6, 7)

**Files:**
- Create: `crates/brom` (a new `no_std`/`no_main` crate, its own image linked at `0x0`, ≤ 300 LoC): reads MON_CODE, computes BLAKE2s-256, compares to a baked `H_EXPECTED`, jumps to the monitor on match, halts on mismatch.
- Create: `crates/brom/link-brom.ld` (link at 0x0), `crates/brom/build.rs` or an xtask step that computes `H_EXPECTED` from the built monitor image and bakes it in (the "measure at build time" step).
- Modify: `sim/redoubt_soc.py` — set `cpu_reset_address = 0x0`, init the BROM ROM region with the brom image, init MON_CODE with the monitor image, bake `H_expected` into a small ROM/const (G3).
- Modify: `crates/monitor-bin` — add the M-stack **guard**: a PMP no-access sub-region just below the M stack (an extra locked entry), and place the stack so overflow hits it.
- Modify: `xtask` — `measure` scenario + a `--tamper` knob that flips a byte of the monitor image before loading.
- Modify: `xtask` loc-gate — count `crates/brom` (≤300) and `monitor-bin/arch.rs`+`pmp.rs`; retire the stale `boot.rs` path (Phase-1 follow-up #2).

**Interfaces:**
- Consumes: the built monitor image (to hash) and the memory map.
- Produces: a boot chain BROM(0x0) → measure → MON_CODE(0x1000_0000); `H_EXPECTED` baked constant; a stack-guard PMP entry.

- [ ] **Step 1 (failing, Review-Focus 5):** `measure` scenario boots reset→BROM, expects the monitor banner (good image) OR, with `--tamper`, expects the BROM tamper-halt line and that the monitor banner NEVER appears and Warden never runs. Run: expect FAIL (no brom).
- [ ] **Step 2:** implement `crates/brom`: BLAKE2s-256 over `[MON_CODE_BASE, MON_CODE_BASE+len)`, constant-time-enough compare to `H_EXPECTED`, jump to `0x1000_0000` on match, else halt (write finisher-fail + `wfi`). Keep ≤ 300 LoC.
- [ ] **Step 3:** bake `H_EXPECTED`: an xtask/build step hashes the final monitor image and writes the constant the brom links against; wire the SoC to init BROM + MON_CODE + the hash const.
- [ ] **Step 4 (Review-Focus 6):** add the M-stack guard PMP entry (no-access page below the stack, locked in `pmp.rs`); a `--stack-overflow` test path deliberately overflows the M stack and asserts the fault lands at the guard address, not in MON_DATA.
- [ ] **Step 5:** run `cargo xtask verilator -- measure` (both good and `--tamper`) green; loc-gate green with the new coverage; commit. `feat(sim): measured boot (BLAKE2s) + M-stack guard; loc-gate covers BROM`.

**Exit (V3):** a tampered monitor halts in the BROM before Warden; a genuine image boots through; a stack overflow faults at the guard; loc-gate now counts the real TCB.

---

# Task V4 — Warden skeleton (S) + real egress MMIO mock; the RTL-level demo

**Files:**
- Create: `crates/warden` (a minimal `no_std` S-mode image linked at `0x2000_0000`): entry that sets up an S→U drop, `mret`s to a U-mode stub, and relays the stub's `ecall` up to M (the trap goes to the monitor's M-mode handler which runs `mediate`).
- Create/modify: an `EgressSink` implementation in `monitor-bin` that performs against the `EGRESS_MMIO` CSR mock (records the outbound bytes into the CSR-backed region; returns a fixed body) — replacing the Phase-1 in-image mock sink with one that actually touches the SoC's egress registers.
- Modify: `sim/redoubt_soc.py` — flesh out the `EGRESS_MMIO` CSR mock (a writable record buffer + a "sent" trigger the harness can read).
- Modify: `crates/monitor-bin` — the real privilege drop (M sets `mstatus.MPP=S`, `mepc=warden_entry`, `mret`), replacing the Phase-1 M-mode-ecall fallback for the sim path (Phase-1 R12 note: this is where S-mode becomes real, now that PMP is programmed).
- Modify: `xtask` — `mediate` scenario at RTL level.

**Interfaces:**
- Consumes: `monitor::mediate` (unchanged from Phase 1), `pmp::lock_regions`, the memory map, the EGRESS_MMIO CSR mock.
- Produces: a full round-trip U→S(Warden)→M(Monitor+mediate)→(egress MMIO)→U on the simulated SoC; the three Phase-1 demo verdicts reproduced at RTL level.

- [ ] **Step 1 (failing):** `mediate` scenario: the U stub places a crafted request in SHARED_REQ and `ecall`s; assert the returned status matches the host `mediate` verdict for the SAME bytes. Three sub-scenarios (reuse the Phase-1 fixtures verbatim): benign=ALLOW (secret written to EGRESS_MMIO record, absent from the response the U stub reads back), wrong-host=DENY_ARG, secret-to-public=DENY_FLOW. Run: expect FAIL.
- [ ] **Step 2:** implement `crates/warden` minimal S entry + the M→S→U drop in the monitor startup (after `lock_regions()`), and the S→M ecall relay so the U stub's MEDIATE trap reaches the monitor.
- [ ] **Step 3:** implement the `EGRESS_MMIO`-backed `EgressSink`; the injected secret is written to the egress record region (M-only), and the response the U stub can read never contains it (re-prove secret non-leak at the hardware boundary).
- [ ] **Step 4:** run `cargo xtask verilator -- mediate` green (all three verdicts reproduce the host results); confirm `pmp`/`measure`/`boot` still green; host `cargo test` still green; commit. `feat(sim): U→S→M mediation round-trip on the RTL SoC; egress via M-only MMIO`.

**Exit (V4) = Phase-2 exit:** on the simulated SoC, a request round-trips U→S→M→egress→U; the containment demo reproduces `benign=ALLOW` (secret injected via M-only egress MMIO, absent from the U-visible response), `attack=DENY_ARG`, `flow=DENY_FLOW`; the PMP walls (V2) and measured boot (V3) hold; Review-Focus 1–7 have passing Verilator assertions; loc-gate covers the full TCB and is under budget.

---

## Self-review

**Spec coverage.** Ch 3 (PMP table, lock/Smepmp, DMA caveat) → V1 map + V2 lockdown + RF8 doc; Ch 4 (SoC, memory map) → V1; Ch 5 (measure→lock→descend, stack guard) → V3 + V2 ordering; Ch 12 egress MMIO → V4 mock (real ESP32 is Phase 4 F3); Ch 9 mediate/trap → reused from Phase 1, driven at RTL in V4. Ch 13 assurance obligations → the Review-Focus assertions + the loc-gate TCB coverage fix. Phase-1 deferred follow-ups folded in: loc-gate TCB coverage (V3), S-mode privilege drop made real (V4). The `LabelSet` channel and `parse_into` DRY item remain Phase-3 (manifest compiler / parse refactor) — noted, not dropped.

**Placeholder scan.** The toolchain-specific unknowns are named as explicit Grounding items G1–G6 with fallbacks and a spike-first V1, not hidden as "TBD". No step says "handle edge cases" without naming the case.

**Type/interface consistency.** The memory map is a single source of truth shared between `redoubt_soc.py` and the Rust `pmp.rs` (Global Constraints + V1 Step 2). `mediate`'s signature is unchanged from Phase 1 and consumed unchanged in V4. `EgressSink`/`Response` reused from Phase 1.

**Review Focus.** 8 items, each pinned to a task with a concrete Verilator assertion; item 8 (DMA) is honestly a documentation-only obligation (PMP cannot guarantee it) rather than a false test.

## Notes for the executor
- **Ground G1 first** (VexRiscv-with-PMP into LiteX) — it gates the entire phase; do the V1 Step-1 spike before writing anything downstream.
- Fastest loop: `pmp.rs` encoding logic can be unit-tested for the bit math on the host (`cargo test`) before ever running Verilator — write host tests for the NAPOT/TOR field computation.
- Keep the Phase-1 QEMU path (`cargo xtask qemu`) alive throughout; it's the cheap smoke test while the SoC is in flux.
- Each Verilator scenario should fail CLOSED and fast (finisher + timeout), never hang the CI.
- macOS setup to record in `sim/README.md`: `brew install verilator`; LiteX + migen + `pythondata-cpu-vexriscv` pinned revs; Python venv.
