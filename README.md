# Redoubt

> A *redoubt* is a small, self-contained, defensible stronghold — the last, smallest
> position you can actually hold and trust.

**Redoubt is a hardware-rooted reference-monitor OS for AI agents.** It is a tiny,
inspectable, unbypassable trust anchor on an open RISC-V FPGA soft-core that mediates every
tool call and external effect an autonomous agent makes — enforcing capabilities,
typed-argument predicates, and information-flow labels **deterministically** — so a fully
hijacked agent (prompt injection, goal hijack, tool poisoning) still **cannot exceed its
granted authority**.

Open source, end to end, and built to be audited: the whole point is a trust base small
enough for one person to read.

> **Status: research & design phase.** No OS code yet. This repo currently holds the
> architecture study and the full v1 architecture. Design is being worked out in the open.

---

## Why (the purpose)

Autonomous AI agents break the assumption every existing secure OS makes — that the "user"
has stable, honest intent. An agent's intent is **hijackable** (prompt injection), it runs
**arbitrary untrusted tools**, and it is simultaneously the **user and the threat**. No
existing OS (seL4, Xous/Baochip, Qubes) was designed for that user. Current agent-security
efforts (Progent, IFC-for-agents, ActPlane, Governed-MCP, MS/NVIDIA) build the enforcement
**in software on Linux** — a huge, unverifiable TCB. **Redoubt makes the reference monitor
the hardware-rooted, tiny, inspectable trust anchor below the agent runtime** — so it holds
even if the agent *and* the OS above are fully compromised. That's the white space.

The key discipline: enforce at the **structured tool-call boundary** (tool id + typed args
+ data labels) with **non-AI logic** — never by judging the agent's fuzzy reasoning.

## The stack (all open toolchain)

| Layer | Choice |
|-------|--------|
| Board | **ULX3S** (Lattice ECP5-85F) — open yosys/nextpnr toolchain |
| SoC builder | **LiteX** (VexRiscv + LiteDRAM + peripherals) |
| CPU | **VexRiscv** (RV32, M/S/U + PMP; MMU optional) |
| OS | **Redoubt** — M-mode reference monitor (TCB) + Warden (S) + compartments (U) |

Topology: the LLM/agent runs on an untrusted **host**; Redoubt on the FPGA owns egress
(network/storage) and secrets and mediates every request — an **HSM + firewall for agent
tool calls**.

## Documents

**Architecture**
- **Visual architecture doc (with diagrams):** [`docs/architecture/redoubt-architecture.html`](docs/architecture/redoubt-architecture.html) — rendered page with hand-authored SVG diagrams. Live: https://claude.ai/artifact/JxwwGRqx5ktiZck2hGadoX
- [`docs/design/2026-09-22-redoubt-architecture-v1.md`](docs/design/2026-09-22-redoubt-architecture-v1.md)
  — the full v1 architecture (threat model, privilege model, reference monitor, capability
  & policy model, tool-call ABI, egress, IFC labels, PMP memory map, SoC, boot/RoT, TCB
  budget, worked example, security analysis).
- [`docs/design/2026-09-22-hardware-plan.md`](docs/design/2026-09-22-hardware-plan.md)
  — board choice (ULX3S), topology, rooting (M-mode + PMP + measured boot), v2 RTL gate.

**Research / study**
- [`docs/study/2026-09-22-architecture-study-apple-baochip.md`](docs/study/2026-09-22-architecture-study-apple-baochip.md)
  — Apple platform security (SEP, PAC, MIE, SPTM/TXM/Exclaves) + Baochip-1x; shared principles.
- [`docs/study/2026-09-22-baochip-precision-deep-dive.md`](docs/study/2026-09-22-baochip-precision-deep-dive.md)
  — a precise read of Baochip's design taste (BIO blocking registers) and its lessons.
- [`docs/study/2026-09-22-fpga-build-path.md`](docs/study/2026-09-22-fpga-build-path.md)
  — how a security OS on an FPGA is actually built (Precursor, ULX3S/LiteX/VexRiscv).
- [`docs/study/2026-09-22-security-os-landscape-and-whitespace.md`](docs/study/2026-09-22-security-os-landscape-and-whitespace.md)
  — the secure-OS landscape and where the genuine white space is (the AI-agent era).
- [`docs/study/2026-09-22-agent-threat-model-and-minimal-primitive.md`](docs/study/2026-09-22-agent-threat-model-and-minimal-primitive.md)
  — OWASP agentic threat model + the minimal deterministic enforcement primitive.

*(An early QEMU-microkernel design draft lives under `docs/superpowers/specs/` — superseded
by the agent-reference-monitor direction; kept for history.)*

## Related
- [grounded-vuln-confirmation](https://github.com/Hem1700/grounded-vuln-confirmation) — an
  earlier exploration this project grew out of.

## License

MIT — see [LICENSE](LICENSE).
