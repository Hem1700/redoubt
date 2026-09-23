# Redoubt — Design Spec: Sub-project 1 (M0–M1)

- **Date:** 2026-09-22
- **Status:** Draft for review
- **Scope of this document:** the first sub-project (M0–M1). The full vision (M0–M5) is
  summarized for context but is *not* specified here; later milestones get their own specs.
- **Working name:** Redoubt (a small, defensible stronghold — the metaphor for a trusted
  core small enough to actually defend and audit). Rename freely.

---

## 1. Motive & thesis (why this exists)

Everyone who does security work runs attacker-controlled input — malware, hostile file
formats, captured traffic, sketchy binaries — on a stack they cannot trust: a monolithic
OS with a multi-million-line kernel TCB, on a closed CPU. "Isolation" today (containers,
VMs) *shares that same huge TCB* and hopes. Parsers of hostile input are the single most
reliable memory-corruption surface.

**Thesis (the principle to prove):** the trusted base for handling hostile input can be
made small enough for one person to audit, memory-safe by language, and rooted in
inspectable hardware — such that *fully compromising an analysis compartment yields the
attacker nothing*: no capabilities, no host access, no lateral movement.

**Optimization target:** renown/research — a credible demonstration of the principle
(publishable, keynote-shaped, a reference repository), not a deployable product. "Done"
means the principle is demonstrated and *measured*, not shipped to end users.

## 2. What success looks like (headline metrics)

The project is judged on numbers, not adjectives:

1. **TCB size:** lines of code in the trusted core (kernel + anything a compromised
   compartment must trust). Target for M0–M1: **kernel ≤ ~3,000 lines of Rust**, tracked
   in CI and reported in the README. The contrast with Linux/Qubes TCB is the pitch.
2. **Ambient authority:** zero. A compartment can name/affect only resources reachable
   through capabilities it was explicitly given. Demonstrated by test.
3. **Containment:** an adversarial test where compartment A attempts to read/write
   compartment B's memory and to invoke authority it was not granted, and **fails**
   (page fault / capability lookup failure), captured as a CI artifact.

## 3. Non-goals (explicitly out of scope)

- **Not** a Linux/POSIX-compatible system; it will **not** run existing tools (Ghidra,
  nmap, …). Running the existing ecosystem is a permanent non-goal for the research
  artifact (would require a compat layer / virtualization = a different, huge project).
- **Not** a general-purpose desktop OS.
- **Not** a Qubes replacement for daily use.
- **M0–M1 specifically:** no FPGA, no custom hardware, no real hostile-input analyzer
  yet, no networking, no persistence, no multicore. Those are M2+.

## 4. Full vision for context (M0–M5, not specified here)

| Milestone | Outcome |
|-----------|---------|
| **M0** | Microkernel boots on QEMU `virt` RV64: traps, timer, threads, console. |
| **M1** | Capability system + synchronous IPC + **two provably-isolated compartments** talking over a cap-gated endpoint. *(end of this spec)* |
| M2 | Compartment broker + one confined hostile-input analyzer + "pop the parser, gain nothing" containment demo. |
| M3 | Port to an open RISC-V soft-core (VexRiscv/CVA6) on an FPGA (ULX3S/Arty); isolation backed by RISC-V PMP. |
| M4 | Custom hardware isolation primitive (memory tagging / capability check) in the soft-core; OS enforces with it; measure vs PMP-only. |
| M5 | Polished demonstrator + writeup/talk; optional TinyTapeout of the primitive. |

## 5. Architecture (M0–M1)

### 5.1 Target platform
- **ISA:** RISC-V RV64GC, S-mode kernel via SBI (OpenSBI as M-mode firmware, provided by
  QEMU `-bios default`).
- **Machine:** QEMU `virt`. Console via the SBI console / NS16550 UART. Timer via SBI
  timer / `stimecmp`.
- **Language/runtime:** Rust, `no_std`, `riscv64gc-unknown-none-elf`. No external kernel
  dependencies beyond a minimal, audited set (see §7). One `unsafe` boundary, documented.

### 5.2 Components (each independently understandable)

**Trusted core (the TCB — counts toward the metric):**
1. **boot** — entry, stack setup, BSS clear, jump to Rust `kmain`. (asm + minimal Rust)
2. **trap** — trap/interrupt vector, save/restore, dispatch to syscall/timer/fault
   handlers.
3. **mm** — physical frame allocator (bump + free-list) and Sv39 page-table management;
   creates per-address-space mappings. Kernel owns all page tables.
4. **cap** — the capability space: a per-task table mapping local cap indices to kernel
   objects (untyped memory, address space, thread, endpoint). Unforgeable: user code only
   ever holds indices; the kernel dereferences them.
5. **task** — threads + address spaces; scheduler (round-robin, cooperative + timer
   preempt is fine for M1).
6. **ipc** — synchronous message-passing over **endpoint** objects (see §5.4).
7. **syscall** — the small syscall surface (see §5.3).

**Not trusted (outside the TCB):**
- **compartment A**, **compartment B** — user-mode tasks in separate address spaces,
  each with its own capability space, linked against a tiny userland shim (`libredoubt`).

### 5.3 Syscall surface (keep it minimal — every syscall is attack surface)
M0–M1 target: **≤ 8 syscalls.**
- `send(cap_endpoint, msg)` / `recv(cap_endpoint) -> msg` — IPC.
- `call(cap_endpoint, msg) -> msg` — send+recv convenience (client side).
- `yield()` — cooperative scheduling.
- `cap_copy(dst_slot, src_cap, rights)` / `cap_delete(slot)` — capability management
  (rights can only be *attenuated*, never amplified).
- `debug_putc(char)` — console, **temporary**, only for M0 bring-up; removed/omitted from
  untrusted compartments in M1 (console becomes a capability to a console endpoint).

Anything not on this list is unreachable by a compartment. No `open`, no ambient FS, no
ambient network — there is nothing to name without a capability.

### 5.4 Capability & IPC model
- A **capability** = a kernel-guarded reference to a kernel object, held by user code only
  as an opaque slot index into its own cap space. The kernel resolves index → object on
  every syscall; a bad index is a syscall error, not a memory access.
- **Endpoints** are the IPC rendezvous objects. Holding a `send` capability to an endpoint
  lets you send; holding a `recv` capability lets you receive. Rights are split so a
  client can hold send-only and a server recv-only.
- **Zero ambient authority:** a freshly created compartment has an *empty* cap space
  except for exactly the capabilities the broker (in M1: the root task) installs. To talk
  to B, A must have been handed a `send` cap to a shared endpoint. It has no way to
  fabricate one.
- **Isolation:** separate Sv39 address spaces; the kernel maps only that task's own frames
  into its page table. There is no shared writable memory in M1 (messages are copied
  through the kernel by value, bounded size, e.g. ≤ 512 bytes).

### 5.5 Data flow — the M1 demonstration
```
root task (trusted, minimal):
  - creates endpoint E
  - spawns A with a SEND cap to E
  - spawns B with a RECV cap to E
A: builds a message, call(E, msg)
B: recv(E) -> msg, processes, replies
kernel: copies msg bytes A->B by value; A and B never share a page
```
Then the **containment test** (the point of the whole exercise):
- A attempts to load/store an address known to be in B's address space → **page fault**
  (A's page table has no such mapping); A is terminated, B and the kernel are unaffected.
- A attempts `send` on a cap slot it was never given / a guessed index → **syscall error**
  (empty/typed-wrong slot); no effect on B.
- A attempts to `cap_copy` with amplified rights → **rejected**.
Each attempt and its rejection is logged and captured as a CI artifact.

## 6. Testing strategy

- **Host unit tests** for pure logic (capability table operations, page-table math,
  message encoding) compiled for the host target where feasible.
- **QEMU integration tests:** boot the kernel headless in QEMU, drive scenarios, assert on
  console output / exit code (`sifive_test` device or SBI shutdown with a status).
  - `test_boot` (M0): kernel reaches `kmain`, timer ticks N times, prints a banner.
  - `test_ipc_roundtrip` (M1): A→B message round-trips with correct payload.
  - `test_containment_memory` (M1): A's cross-address-space access faults; B survives.
  - `test_containment_capability` (M1): A's forged/absent-cap syscall errors; B survives.
  - `test_no_rights_amplification` (M1): `cap_copy` cannot add rights.
- **TCB line count** computed in CI (`tokei`/`cloc` over the trusted crates) and failed if
  it exceeds the budget — keeps the headline metric honest.
- TDD where practical: write the QEMU assertion first, then the kernel code to satisfy it.

## 7. Toolchain, dependencies, TCB hygiene
- Rust (pinned toolchain via `rust-toolchain.toml`), target `riscv64gc-unknown-none-elf`.
- QEMU `qemu-system-riscv64` for run/test. On macOS: `brew install qemu`.
- Kernel dependencies limited and audited; candidates: `riscv` (register access) — or
  hand-roll the few CSR ops to keep the TCB fully in-repo. **No** allocator crates in the
  TCB beyond the in-repo frame allocator. Every third-party line in the TCB counts toward
  the metric and must be justified.
- One documented `unsafe` module boundary (CSR/asm, page-table writes); the rest of the
  kernel is safe Rust.

## 8. Success criteria (exit bar for this sub-project)
- **M0:** `cargo run` boots the kernel in QEMU, prints a banner, services timer
  interrupts, and cleanly shuts down. `test_boot` green in CI.
- **M1:** two compartments in separate address spaces exchange a message *only* via a
  cap-gated endpoint; all three containment tests pass (memory, capability, rights); the
  TCB line-count gate passes at ≤ ~3,000 lines. README reports the current TCB number.

## 9. Risks & unknowns
- **Scheduler/timer plumbing on RV64 S-mode** (SBI timer, `stimecmp` vs SBI TIME
  extension) — bring-up friction; mitigated by starting cooperative, adding preemption
  after IPC works.
- **Page-table bugs** are silent and dangerous — mitigated by the containment tests being
  first-class CI, not afterthoughts.
- **TCB budget pressure** as features land — mitigated by the CI line-count gate forcing
  explicit trade-offs.
- **macOS dev ergonomics** — all kernel work is in QEMU (arch-independent of the host);
  Apple-clang/libFuzzer quirks are irrelevant here. Rust cross-compiles cleanly.

## 10. Open questions for reviewer (you)
1. Working name **Redoubt** — keep, or pick your own before we make anything public?
2. TCB budget of ~3,000 lines for M0–M1 — comfortable, or tighter (seL4 kernel is ~10k C;
   smaller is a stronger claim)?
3. Do you want M1 to already include a *second* endpoint / third compartment to show
   transitive least-privilege, or keep M1 minimal (A↔B only) and defer that to M2?
