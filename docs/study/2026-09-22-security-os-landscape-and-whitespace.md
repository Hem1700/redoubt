# Research: the security-OS landscape and where the genuine white space is

- **Date:** 2026-09-22
- **Question:** if we build a security OS, *what new can we offer?* Research first.
- Findings + honest gap analysis. Sources inline.

## 1. The landscape (what already exists, and its angle)
| OS | Security angle | Note |
|----|----------------|------|
| **seL4** | Formally *verified* microkernel; capabilities | The gold standard for assurance |
| **KataOS / Sparrow** (Google) | seL4-based, Rust, verifiably-secure platform for *embedded ML* | Closest to "secure OS for ML," but embedded/ambient sensing focus |
| **Qubes OS** | Isolation via *hypervisor* (each app in a VM) | Big TCB (Xen+Linux); desktop |
| **Genode / Sculpt** | Component OS on microkernels; capability-based | "Most consistently delivers the microkernel promise" |
| **Fuchsia / Zircon** (Google) | Microkernel, capability handles | ~maintenance mode since 2024 |
| **Redox / Theseus / Hubris / Tock** | Rust OSes (safety via language) | Tock now secures ~10M devices |
| **Xous / Precursor / Baochip** (bunnie) | Rust microkernel + inspectable HW; **protect the user's secrets** | Our neighbor; a *vault* for a human's keys/identity |

**Takeaway:** the "secure microkernel + capabilities + Rust + inspectable hardware" ground
is *thoroughly occupied*. Building another of those = a replica. Baochip owns "protect the
human's secrets on a trustworthy device."

## 2. Grounded open problems (from the literature)
- **Formal verification ≠ safe against microarchitecture:** seL4 (8.7k LoC, 200k LoC of
  proof) had its confidentiality guarantee **broken by Spectre** — verification didn't
  cover speculative/constant-time behavior.
  ([OS formal methods](https://arxiv.org/pdf/1608.00678))
- **Microkernels still don't get adopted:** IPC overhead, interface/glue complexity, and
  Linux ecosystem lock-in — not a security failure, an *adoption* failure.
  ([FOSDEM 2026](https://fosdem.org/2026/schedule/event/CF88E8-facing_the_complexity_the_challenges_of_adopting_microkernels_for_cloud_infrastr/),
  [Microkernel Goes General, OSDI'24](https://www.usenix.org/system/files/osdi24-chen-haibo.pdf))
- **Kernel CVEs are exploding:** >9,300 in mainstream OS kernels since 2004; **~3,300 in
  2024 alone (10× jump)**, amplified by AI-generated code.
  ([Fuzzing OS survey](https://arxiv.org/pdf/2502.13163))

## 3. The emerging frontier (this is the new thing): **securing AI agents *like* operating systems**
A distinct research area formed in **2026** — and it argues the OS abstractions (isolate
resources, separate privileges, mediate communication) are exactly what autonomous AI
agents now need:
- **"Toward Securing AI Agents Like Operating Systems"** — agents face the same problems
  as OSes. ([2605.14932](https://arxiv.org/abs/2605.14932))
- **AgenticOS: An Intent-Oriented Secure OS Architecture for Autonomous AI Agents** — the
  security boundary is built around *"does this external effect conform to the declared
  task intent"* rather than low-level resource access. **A new security model
  (intent-based, not resource-based).** ([2606.21129](https://arxiv.org/html/2606.21129))
- **Governed MCP: Kernel-Level Tool Governance for AI Agents** — kernel-level governance
  of MCP tool calls; hypervisor-vs-kernel isolation for *adversarial* agents. (Directly on
  top of the MCP tool-poisoning problem.) ([2604.16870](https://arxiv.org/pdf/2604.16870))
- Industry: **Microsoft Agent Governance Toolkit**, **NVIDIA OpenShell** — runtime
  security/sandboxing for agents.

**Why this is genuinely new:** every existing security OS (seL4, Xous, Baochip, Qubes)
assumes the "user" is a human or a process with *stable, honest intent*. An autonomous AI
agent breaks that assumption in three ways at once:
1. Its **intent is fluid and hijackable** (prompt injection / tool poisoning).
2. It runs **arbitrary untrusted tools** (MCP servers, code, plugins) as a matter of course.
3. It is simultaneously the **user *and* a potential threat**.

No existing OS was designed for a user like that.

## 4. The white space (what *we* can offer that's new)
> **A hardware-rooted, open, tiny-TCB operating system for the AI-agent era: the safe
> substrate on which an autonomous agent runs untrusted tools — where every external
> effect is mediated against declared intent, and a small trust anchor the (possibly
> hijacked) agent cannot bypass enforces it.**

Why this is *new* and *ours*, not a replica:
- **Different purpose from Baochip:** Baochip protects a *human's secrets* (a vault).
  Redoubt would contain an *AI agent and its untrusted tools* (a hazmat lab for agents).
  Opposite problem.
- **The competition is software-only:** AgenticOS, Governed MCP, MS, NVIDIA all bolt
  governance *on top of Linux* — huge TCB, unverifiable, closed hardware. **Nobody has
  built the hardware-rooted, open, inspectable, tiny-TCB version.** That's the gap.
- **It's dead-center in Hem's unique background:** FORGE (multi-agent), the MCP
  tool-poisoning scanner, the MCP SDK SSRF CVE, agent security — plus memory-safety and
  offensive expertise. Almost nobody can do *both* the agent-security half and the
  low-level OS/hardware half.
- **It reuses the good lessons without being a clone:** microkernel + capabilities +
  inspectable HW (from Baochip/seL4) become the *substrate*; the *novel* layer is
  **intent-mediated, capability-gated tool execution with a hardware trust anchor.**

## 5. Honest risks / competition
- The agent-security space is **hot and moving fast** (multiple 2026 papers + MS/NVIDIA).
  We are *not* first to "secure agents"; we would be first to the **hardware-rooted, open,
  tiny-TCB OS** version. Need to stay narrow and demonstrate, not out-scope the field.
- Intent-based enforcement is **hard to define precisely** — "declared intent" is fuzzy;
  the rigorous, checkable core needs care (this is where it could become hand-wavy).
- Doing it on an FPGA soft-core constrains performance — fine for a demonstrator, not a
  datacenter agent host.

## 6. Other gaps considered (and why they're weaker for us)
- **Constant-time/side-channel-safe verified microkernel** (the seL4-Spectre gap): real,
  but PhD-group scale, not a fun solo build.
- **Microkernel adoption/compatibility** (run Linux apps on a microkernel): huge systems
  engineering, not a security-*novelty* flag.

## 7. Open question (to discuss, not concluded)
Does "**the hardware-rooted, open, tiny-TCB OS for safely running AI agents and their
untrusted tools**" feel like a purpose worth building — novel, yours, and distinct from
Baochip? If yes, the next research step is to go deep on the *threat model of an
autonomous agent* and what the minimal enforcement primitive (intent + capability) would
actually be.
