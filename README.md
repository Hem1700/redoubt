# Redoubt

> A *redoubt* is a small, self-contained, defensible stronghold: the last, smallest position
> you can actually hold and trust.

**Redoubt is a hardware-rooted reference-monitor OS for AI agents.** It is a tiny,
inspectable, unbypassable trust anchor on an open RISC-V soft-core that mediates every tool
call and external effect an autonomous agent makes, enforcing capabilities, typed-argument
predicates, and information-flow labels *deterministically*, so a fully hijacked agent
(prompt injection, goal hijack, tool poisoning) still cannot exceed its granted authority.

The whole point is a trust base small enough for one person to read. The monitor is about
1,000 lines of `no_std` Rust, `#![forbid(unsafe_code)]`, with the single unsafe module being
the boot/trap assembly on the bare-metal side.

## Status: phases 1 to 3 built, in simulation, open source

This is no longer a design doc. The monitor runs. Three phases are built, each reviewed and
merged, and the whole thing is public and CI-green:

- **Phase 1 (software monitor):** the six-stage decision pipeline (`mediate`) with
  capabilities, typed-argument predicates, an information-flow lattice, inject-only secrets,
  and a BLAKE2s audit hash chain. 73 host tests. Boots in QEMU.
- **Phase 2 (hardware-enforced):** the monitor runs on a Verilated RISC-V SoC
  (LiteX + VexRiscv-`secure` with real PMP). A BLAKE2s boot ROM measures the full monitor
  image and halts on tamper; PMP walls are proven unbypassable by fault injection; the
  containment demo reproduces `ALLOW` / `DENY_ARG` / `DENY_FLOW` at RTL with a secret injected
  into egress but absent from everything the agent can read.
- **Phase 3 (the agent-facing stack):** a wire protocol (COBS + CRC32) and a host SDK, a
  policy *manifest compiler* (policy is now audited text, not a hand-built table), a full
  session lifecycle with quotas and O(1) revocation, a U-mode Endpoint compartment proven to
  hold no authority, and a minimal cooperative Warden demonstrating liveness without trust.

Next is Phase 4 (bring-up on a real ULX3S FPGA board) and Phase 5 (bus-level hardening). See
the roadmap below.

## The problem, and the white space

Autonomous AI agents break the assumption every existing secure OS makes: that the "user" has
stable, honest intent. An agent's intent is hijackable (prompt injection), it runs arbitrary
untrusted tools, and it is at once the user and the threat. seL4, Qubes, and the rest were not
designed for that user. Current agent-security efforts (Progent, IFC-for-agents, governed-MCP,
and the vendor frameworks) build the enforcement in software on Linux, which is a huge,
unverifiable trusted base.

Redoubt makes the reference monitor the hardware-rooted, tiny, inspectable trust anchor
*below* the agent runtime, so it holds even if the agent and the OS above it are fully
compromised. The key discipline: enforce at the **structured tool-call boundary** (tool id +
typed arguments + data labels) with non-AI logic, never by judging the agent's fuzzy
reasoning. This follows Anderson's 1972 reference-monitor criteria (tamper-proof,
always-invoked, small enough to verify) and the Keystone / Sanctorum line of M-mode security
monitors, applied to the OWASP agentic threat model.

## Topology

The LLM/agent runs on an untrusted **host**. Redoubt, on the FPGA, owns egress (network and
storage) and the secrets, and mediates every request. It is, in effect, an HSM plus a firewall
for an agent's tool calls: the agent holds opaque capability handles, never keys, and every
effect is performed by the monitor after a deterministic check.

## Run it

Everything below runs in simulation today (no board required).

**Host logic and tests** (plain stable Rust):

```sh
cargo test                     # abi, monitor, wire, host-sdk, policyc, xtask
cargo clippy -- -D warnings    # the CI lint gate
```

**Boot + the containment demo in QEMU** (needs `qemu-system-riscv32`):

```sh
cargo xtask qemu               # boots the monitor image, checks the banner
cargo xtask qemu -- mediate    # the ALLOW / DENY_ARG / DENY_FLOW demo
```

**The full hardware (Verilator) simulation** of the LiteX + VexRiscv-`secure` SoC. This needs
the sim toolchain (a Python 3.10 LiteX venv, Verilator from oss-cad-suite, and a pinned Rust
nightly for `riscv32ima`); the exact, reproducible setup is in
[`sim/README.md`](sim/README.md):

```sh
cargo xtask verilator -- boot       # monitor boots on the Verilated SoC
cargo xtask verilator -- pmp        # PMP walls: every S/U reach into the TCB faults
cargo xtask verilator -- measure    # measured boot: a tampered image halts in the BROM
cargo xtask verilator -- mediate    # the containment demo at RTL (secret injected, not leaked)
cargo xtask verilator -- endpoint   # the U-mode Endpoint courier relays frames; corrupt ones drop
cargo xtask verilator -- warden     # the minimal Warden schedules the Endpoint; liveness without trust
```

## Architecture at a glance

Three privilege tiers in the design, two realized on today's core (see the honest notes below):

| Tier | Component | Role |
|------|-----------|------|
| M-mode | **Monitor** (+ boot ROM + PMP) | the TCB: measures boot, locks the walls, decides every call |
| (S-mode) | **Warden** | scheduling and IPC only, trusted for liveness, never for the verdict |
| U-mode | **Compartments** | the Endpoint (wire framing), drivers, and the agent's requests: fully untrusted |

Every `MEDIATE` runs six checks in order: well-formed, capability resolve (with epoch
revocation), tool binding, typed-argument predicate, information-flow, and only then perform
the effect and inject the secret. A denial never performs anything and never returns a secret.

The deeper design is a 13-chapter manual:
[`docs/architecture/components/index.html`](docs/architecture/components/index.html) (threat
model, privilege and PMP, SoC and memory map, boot, wire, capabilities, policy, the monitor,
information-flow, the stack, egress, assurance).

## Honest hardware notes

Grounding the design against a real open core taught us things the design predated, and the
repo says so plainly rather than overclaiming (this is a security project; the honesty is the
point). These are in the code, the manual's implementation-status notes, and `sim/README.md`:

- **The VexRiscv `secure` core is M+U only (no Supervisor mode).** v1 runs the two-tier
  Keystone/Sanctorum shape (Monitor in M, everything else in U); the three-tier design holds
  as the target for a supervisor-capable core. Getting S-mode on VexRiscv would force the MMU,
  which contradicts the "PMP, not virtual memory" choice.
- **CPU uncached-MMIO access bypasses PMP on this core,** so PMP does not fence user mode out
  of the egress registers. Egress containment rests on monitor *mediation* (the capability
  model), not on a memory wall. A bus-level wall (RISC-V IOPMP or an RTL gate) is Phase 5.
- **This SoC has no usable asynchronous timer** reachable from a user spin under Verilator, so
  the Warden is a cooperative, slice-budget scheduler; preempting a never-yielding loop is
  deferred.
- PMP guards the CPU's own loads and stores, not a DMA master. That is the same Phase-5 gap.

## Roadmap

- **Phase 4: FPGA bring-up (ULX3S).** Synthesis and place-and-route with yosys + nextpnr-ecp5,
  flash to real silicon, real network egress over an M-owned ESP32 link, an OLED showing the
  verdict, and a proof that SD/network DMA is M-only. *Gated on acquiring the board.*
- **Phase 5: hardening.** A bus-level egress gate (IOPMP) so a compartment truly cannot reach
  egress, an authenticated bitstream, and a machine-checked model of the six stages.

## Repository layout

```
crates/abi         wire ABI + zero-copy request decode (no_std)
crates/monitor     the TCB: parse, capabilities, predicates, flow, egress, audit, mediate (no_std, forbid-unsafe)
crates/monitor-bin bare-metal images: boot, PMP, trap trampoline, Endpoint, Warden (the only unsafe)
crates/brom        the measured-boot ROM (BLAKE2s)
crates/wire        COBS + CRC32 framing (no_std)
crates/host-sdk    host-side request builder / response parser
crates/policyc     the policy manifest compiler
sim/               LiteX SoC generator, memory map, toolchain setup (sim/README.md)
xtask/             the build + QEMU + Verilator runner
docs/              the architecture manual, specs, and the implementation plans
```

## Prior art this builds on

Anderson 1972 (the reference monitor); Keystone and Sanctorum (M-mode security monitors with
PMP); Apple's SPTM (a monitor more privileged than the kernel); seL4 (small, verified kernels);
Denning 1976 (lattice information flow); the OWASP Top 10 for Agentic Applications.

## License

MIT, see [LICENSE](LICENSE).
