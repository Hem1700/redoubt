# Redoubt

> A *redoubt* is a small, self-contained, defensible stronghold — the last, smallest
> position you can actually hold and trust.

**Redoubt is a fun, open-source, security-focused operating system for a RISC-V FPGA
soft-core.** The goal: a real, hackable, inspectable security OS you can build, run on
hardware you hold in your hand, attack, and learn from — with everything open, end to end.

> **Status: research & design phase.** No OS code yet. This repo currently documents the
> architecture study and the buildable-stack research that the design is being grounded
> in. Nothing here is decided by fiat — the design is being worked out in the open.

---

## The idea

Most security work — parsing hostile files, running untrusted code — happens on a stack
you can't actually trust: a monolithic OS with a multi-million-line kernel on a closed
CPU. Redoubt explores the opposite: a **small, auditable, hardware-isolated, open**
security OS on a RISC-V soft-core you can inspect down to the RTL, where the interesting
security properties are *visible and hackable*, not just claimed.

It's inspired directly by bunnie Huang's **Precursor / Betrusted / Baochip** line (an
open security device running the **Xous** Rust microkernel on a **VexRiscv** FPGA
soft-core) and informed by studying how **Apple** builds security at scale.

## The buildable stack (all open toolchain)

| Layer | Choice | Notes |
|-------|--------|-------|
| Board | **ULX3S** (Lattice ECP5-85F) | Fully open toolchain (yosys/nextpnr/verilator); runs RISC-V soft-cores. |
| SoC builder | **LiteX** | Generates the SoC (DRAM, UART, SD, JTAG, MMU option) so we don't hand-build hardware bring-up. |
| CPU | **VexRiscv** (RV32, MMU-capable) | Same core as Precursor/Baochip. |
| OS | **Redoubt** — fork Xous *or* from-scratch Rust microkernel | The open design decision; see the studies. |

## Research in this repo

- [`docs/study/2026-09-22-architecture-study-apple-baochip.md`](docs/study/2026-09-22-architecture-study-apple-baochip.md)
  — grounded study of **Apple platform security** (SEP, PAC, Memory Integrity
  Enforcement, SPTM/TXM/Exclaves) and the **Baochip-1x** (VexRiscv+MMU, secure elements,
  glitch sensors, "mostly open" RTL, Xous). Extracts the design principles both share.
- [`docs/study/2026-09-22-fpga-build-path.md`](docs/study/2026-09-22-fpga-build-path.md)
  — how a fun, open-source security OS on an FPGA actually gets built: Precursor as the
  existence proof, the ULX3S + LiteX + VexRiscv stack, and the genuine "fun-decisions."
- [`docs/superpowers/specs/2026-09-22-redoubt-m0-m1-design.md`](docs/superpowers/specs/2026-09-22-redoubt-m0-m1-design.md)
  — an **early** microkernel design draft (QEMU-first). Predates the "fun/FPGA/open"
  reframing and the architecture study; being rescoped toward the FPGA + LiteX path.
  Kept for history, not current gospel.

## Key findings so far (short version)

- Apple and Baochip independently converged on two moves: **a tiny hyper-privileged trust
  anchor beneath the kernel** (Apple SPTM/SEP) and **compartmentalizing the kernel's
  power** (Apple Exclaves; Xous servers). *The kernel is not the most-trusted thing.*
- Apple's memory safety is now **hardware-tag-centric** (synchronous EMTE + type-aware
  allocators); on open RISC-V, tagging is still research (HDFI/HyperFlow/Raft).
- **Precursor proves** an individual can build the open, inspectable, MMU-isolated,
  capability-OS-on-FPGA stack. That's the template Redoubt builds on.

## Open decisions (being worked out)

1. **Fork Xous vs. write a from-scratch Rust microkernel** (vs. hybrid: boot something on
   the FPGA first, then decide).
2. **The "security fun hook"** — live-attackable isolation with visible containment,
   physical glitch/tamper detection, a hardware RNG, a secure-boot-bypass CTF, or a
   secure-vault gadget.
3. Board (**ULX3S** recommended) and whether to add a small SPI LCD for demos.

## Related

- Earlier exploration this project grew out of:
  [grounded-vuln-confirmation](https://github.com/Hem1700/grounded-vuln-confirmation)
  (a separate repo — differential sanitizer oracle for vulnerability confirmation).

## License

MIT — see [LICENSE](LICENSE).
