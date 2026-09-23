# Architecture Study: Apple Platform Security & Baochip-1x

- **Date:** 2026-09-22
- **Purpose:** Study two reference security architectures *before* designing anything.
  Findings and extracted design principles only — **no design conclusions in this
  document.** Conclusions come after discussion.
- **Sources:** linked inline.

---

## Part 1 — Baochip-1x (bunnie Huang) — the open, small, high-assurance blueprint

Source: [bunnie's blog](https://www.bunniestudios.com/blog/2026/baochip-1x-a-mostly-open-22nm-soc-for-high-assurance-applications/),
[Xous @ 39c3](https://fahrplan.events.ccc.de/congress/2025/fahrplan/event/xous-a-pure-rust-rethink-of-the-embedded-operating-system)

### Compute
- **Main CPU:** 350 MHz **VexRiscv (RV32) with an MMU** — notable because it's "the first
  microcontroller in its class with an MMU," enabling per-application virtual address
  spaces ("secure, loadable apps, each in its own virtual memory space"). Descends from
  the Precursor FPGA soft-core.
- **BIO (Bao I/O coprocessor):** quad **700 MHz PicoRV32** cores dedicated to
  deterministic I/O, offloaded from the main CPU.

### Memory
- **4 MiB nonvolatile ReRAM** (Crossbar; 32-byte page size, faster writes than flash).
- **2 MiB SRAM** with **ECC**.
- MMU → virtual memory, address-space relocation, swap.

### Secure elements
- **Hardware-protected key slots** (keys not exposed to software).
- **TRNG.**
- **AES + crypto accelerators** (bunnie notes potential side-channel considerations;
  Xous adds *chaffed AES* as a software countermeasure).
- **One-way / monotonic counters** → anti-rollback.

### Physical / anti-tamper
- **Glitch sensors** → detect fault-injection (voltage/clock glitching).
- **Security mesh** → perimeter/tamper monitoring.

### Openness & verifiability
- **"Mostly open":** all *computational / data-transforming* RTL is open on GitHub; the
  closed parts are "effectively wires" (AXI fabric, USB PHY, analog PLL/regulators/pads).
- **IRIS** — non-destructive infra-red silicon inspection to verify the fabricated
  silicon matches the design ("shine IR through it").
- 22 nm TSMC, production-qualified.

### OS: Xous
- Pure-Rust microkernel, **capability-based**, **message-passing**, **MMU-enforced**
  process isolation, small footprint (fits 2–6 MiB RAM).
- Replaces RTOS patterns with a capability security model.

### Principles Baochip embodies
1. **Inspectability over absolute openness** (pragmatic: open the parts that transform
   data; verify silicon optically).
2. **MMU-based isolation even in an MCU** — hardware isolation, not language-only.
3. **Keys never in software** (hardware key slots).
4. **Physical-attack resistance is first-class** (glitch sensors, mesh).
5. **Small, auditable, Rust, capability-based OS** matched to the hardware.

---

## Part 2 — Apple platform security — best-executed HW/SW co-design at scale

### 2.1 Secure Enclave Processor (SEP)
Sources: [Apple SoC security](https://support.apple.com/en-om/guide/security/sec87716a080/web),
[US8832465B2](https://patents.google.com/patent/US8832465B2/en)
- **SoC-within-a-SoC:** a separate processor with its own security peripherals, isolated
  from the application processors.
- **Own immutable Boot ROM** = hardware root of trust; the SEP **executes directly from
  secure ROM** (no copy to modifiable RAM), ROM inaccessible outside SEP.
- **Secure mailbox:** the *only* interface between the app processor and SEP is a
  hardware-controlled mailbox — AP writes a message, SEP reads/responds; no other access
  in production silicon.
- **Key wrapping:** software only ever receives *wrapped* (encrypted) keys; the raw key
  is delivered in hardware to the crypto engine — insecure software never sees it.
- Runs an **Apple-customized L4 microkernel** (SEP OS), signed and verified by SEP Boot ROM.

### 2.2 Memory safety: PAC → MIE (EMTE + type-aware allocators)
Sources: [Apple MIE blog](https://security.apple.com/blog/memory-integrity-enforcement/),
[8ksec MIE deep dive](https://www.8ksec.io/mie-deep-dive-kernel/)
- **PAC (Pointer Authentication, 2018, A12):** cryptographic signatures on pointers →
  breaks ROP/JOP by making forged code pointers detectable.
- **MIE (A19/M5, 2025) — three pillars:**
  1. **Secure type-aware allocators** (`kalloc_type` 2022, `xzone malloc`, WebKit
     `libpas`): use *type information* to place allocations so attackers can't create
     "overlapping interpretations of memory." Page-granularity segregation.
  2. **Enhanced MTE (EMTE), synchronous, 4-bit tags, 16-byte granule:** each allocation
     gets a secret tag; hardware blocks mismatched access. Adjacent allocations differ →
     kills linear overflow; freed memory retagged → kills UAF. **Synchronous** (not
     async) so there's *no race window*.
  3. **Tag Confidentiality Enforcement:** protects tags/metadata (via SPTM) and closes
     speculative/Spectre-V1 and timing side channels that could leak tags.
- **Stated philosophy:** memory-corruption bugs are "interchangeable," so disrupt entire
  **exploitation strategies**, not individual bugs; **defense in depth** (allocator +
  tags); make exploitation **economically infeasible** (they estimate 25+ Spectre-V1
  sequences needed for >95% exploitability); **HW/SW co-design** so protection is
  always-on without a performance tax, across the kernel + 70+ userland processes.

### 2.3 Shrinking the TCB below the kernel: SPTM / TXM / Exclaves
Sources: [Apple OS integrity](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web),
[Deep dive (arXiv 2510.09272)](https://arxiv.org/abs/2510.09272),
[iOS exploit starterpack: SPTM/TXM](https://tin-z.github.io/ios-exploit-starterpack/en/sptm-txm/)
- **SPTM (Secure Page Table Monitor, A15+/M2+):** runs in a **guarded execution level
  (GL2), *more privileged than the XNU kernel*.** It is the **sole gatekeeper of page
  tables and physical-frame types** (frame types like `SPTM_UNTYPED`, `XNU_DEFAULT`,
  TXM/Exclave types). Even a **fully compromised kernel cannot change page tables outside
  its assigned domain.** Entered from XNU via a `GENTER` instruction. Replaced the older
  PPL, with a smaller attack surface that **does not rely on trusting the kernel.**
- **TXM (Trusted Execution Monitor, GL0):** code-signing and entitlement enforcement
  moved *out of* XNU into an isolated monitor. Privilege separation means a **TXM
  compromise ≠ SPTM bypass.**
- **Exclaves:** sensitive services (microphone, camera, sensors) isolated into
  `SK_DOMAIN` compartments under a **Secure Kernel (GL1)** — the monolithic kernel is no
  longer omnipotent. Apple is moving XNU toward a **compartmentalized, microkernel-inspired**
  model.

### Principles Apple embodies
1. **The kernel is not the most trusted thing.** The most security-critical enforcement
   (page tables, code signing) lives in *small components more privileged/isolated than
   the kernel* (SPTM, TXM, SEP). Compromising the big kernel does not grant those powers.
2. **Assume memory-corruption bugs exist; neutralize the exploitation strategy** (MIE).
3. **Hardware/software co-design** — silicon feature (EMTE, GL levels, SEP) + OS designed
   to use it; co-design removes the performance tax.
4. **Synchronous, always-on enforcement** (no race windows).
5. **Compartmentalize the monolith** (Exclaves) — reduce the blast radius of any one
   compromise.
6. **Root of trust in immutable minimal ROM**, verified boot chain.

---

## Part 3 — Cross-cutting patterns observed in BOTH (grounded, not conclusions)

1. **Isolation is hardware-enforced, never language-only.** Baochip: MMU. Apple: MMU +
   GL privilege levels + EMTE + SEP separation.
2. **Shrink and elevate the trust anchor.** Apple: SPTM/TXM/SEP more privileged/isolated
   than the kernel. Baochip: hardware key slots + secure elements the CPU can't bypass.
   Both push the *most* trusted logic into something *smaller* than the main OS.
3. **Capability / message-passing OS.** Xous (capabilities, IPC) and SEP OS (L4
   microkernel) are both small capability/microkernel designs, not monoliths.
4. **Assume compromise; limit blast radius.** SEP mailbox-only interface; Apple Exclaves;
   MIE assumes bugs exist. Design so a popped component gains little.
5. **Verifiability/inspectability as a security property.** Baochip: open RTL + IRIS
   optical verification. Apple: published security research, but closed silicon.
6. **Physical/side-channel awareness.** Baochip: glitch sensors, mesh, chaffed AES.
   Apple: Tag Confidentiality Enforcement vs. Spectre/timing; SEP isolation.

---

## Part 4 — Honest observations & open questions (for discussion, NOT conclusions)

- Both architectures independently converged on the **same two moves**: (a) a *tiny,
  hyper-privileged monitor beneath/around the kernel* (Apple SPTM/SEP), and (b)
  *compartmentalizing the kernel's power* (Apple Exclaves; Xous servers). This is the
  dominant modern pattern — worth understanding deeply before deviating.
- **Apple's memory-safety enforcement is now hardware-tag-centric (EMTE),** but that's
  ARM-MTE-derived and closed. On **open RISC-V**, hardware memory tagging is *research*
  (HDFI, HyperFlow, TMDFI, Raft), not standardized — so anyone open-source wanting
  Apple-grade memory safety has to build or adapt the tagging hardware themselves.
- **Baochip proves a small team can ship the open, inspectable, MMU-isolated,
  capability-OS stack** — but it does **not** have EMTE-style hardware memory tagging or
  an SPTM-style page-table monitor. Its memory-safety story is "Rust + MMU isolation,"
  not hardware tag enforcement.
- **Apple's SPTM idea (a page-table/enforcement monitor more privileged than the kernel)
  has, as far as this study found, no open-source RISC-V equivalent** built into a small
  high-assurance stack.
- Questions these raise (to discuss, not answer here):
  - Which of these principles matter for *our* threat model (hostile-input parsing),
    and which are for different threats (physical, spyware persistence)?
  - Where is the honest gap between "what Apple does (closed, huge silicon budget)" and
    "what Baochip does (open, tiny)" — and is that gap a place to contribute or a place
    that's gapped *for good reasons*?
  - How much of Apple's design depends on resources (silicon area, a fabbed SEP, ARM MTE)
    that an FPGA soft-core simply cannot replicate?

*Next step: discuss these findings together and decide where to go deeper — no
architecture chosen yet.*
