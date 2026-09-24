# Redoubt Component Manual — Author Brief (READ FULLY BEFORE WRITING)

You are writing one or two chapters of the Redoubt architecture book. Redoubt is a
**hardware-rooted reference-monitor OS for AI agents**: a tiny, unbypassable trust anchor on
an open RISC-V FPGA soft-core (ULX3S / ECP5-85F, LiteX + VexRiscv) that mediates every tool
call an agent makes, enforcing capabilities + typed-argument predicates + information-flow
labels DETERMINISTICALLY, so a fully prompt-injected agent still cannot exceed its granted
authority. The LLM/agent runs on an untrusted HOST; Redoubt owns egress + secrets.

## 0. Before you write, READ these (they are your source of truth)
- `docs/architecture/components/09-monitor.html`  ← THE STYLE + DEPTH + VOICE EXEMPLAR. Match it exactly.
- `docs/design/2026-09-22-redoubt-architecture-v1.md`  ← canonical technical facts.
- `docs/study/*.md` as relevant to your chapter (Apple/Baochip, agent threat model, landscape, fpga path).

## 1. HOUSE STYLE — non-negotiable (classic spec / print)
OPEN `09-monitor.html` and **copy its entire `<title>`…`<style>` head block VERBATIM** into your
file (change only the `<title>` text). This gives you: Source Serif 4 on WHITE, justified body
with hyphenation, RFC masthead, numbered sections, Figure captions, footnotes, dark-mode. Then
mirror its DOM structure:
- `.masthead` with `.docmeta` (Redoubt Architecture · Component Specification · Doc **RDBT-ARCH-NN**
  · Status **Draft** · Chapter **N / 13**), an `<h1>` title, and an `.abstract` paragraph.
- Optional `.note` "Note to first-time readers" primer IF your chapter introduces new jargon.
- Numbered `<h2><span class="n">N.1</span>…`, `N.2`, … sections.
- `<figure>` with a hand-authored SVG and `<figcaption><span class="fl">Figure N-1.</span> …`.
- Superscript footnotes `<sup><a href="#nX">X</a></sup>` and an `<ol class="notes">` at the end.
- `<footer>` like the exemplar.
FORBIDDEN: cream/beige backgrounds, display/editorial serifs, rounded "card" grids, teal-on-dark
tech-doc styling. If you add an SVG, colour it ONLY with the exemplar's classes (f-s1, f-s2,
f-none, s-ln, s-acc, s-cur, s-mut, t-acc, t-mut, mk, mk-acc, dash) + currentColor — NEVER
`fill="var(--x)"` as an attribute (it doesn't render).

## 2. VOICE — write like a human, teach a beginner
- Beginner-accessible: define jargon when it first appears; use plain analogies (the exemplar uses
  an embassy guard, a coat-check tag for a capability, a doorman with a guest list for predicates).
  Ramp gently, then go deep. Layered, not dumbed-down.
- Human, NOT AI-sounding. AVOID: relentless three-part lists, the "X, not Y" cadence, bold on
  everything, em-dashes doing comma-work, section intros that restate the heading, mission-statement
  ledes. USE: contractions, varied sentence length, direct address, honest asides, real opinions,
  concrete scenarios.

## 3. DEPTH — each chapter is a long textbook chapter (like the Monitor)
Cover, as applies to your component: purpose/role; how it works internally (mechanisms, data
structures with field tables, algorithms/pseudocode); at least one worked example; edge cases and
failure modes; the invariants it maintains; **alternatives considered and rejected, with reasons**;
open questions; and a Notes/footnotes section. Aim for real substance (the Monitor chapter is ~400
lines of HTML). Do NOT write a summary.

## 4. CANONICAL FACTS — stay consistent; do not invent contradictions
- Trust tiers: **T0** Monitor (M-mode) + BROM + PMP = the TCB; **T1** Warden microkernel (S-mode,
  scheduling/IPC, liveness only); **T2** compartments — Endpoint (USB framing), net/storage drivers
  (U-mode); HOST fully untrusted.
- ISA/HW: RV32IMAC, modes M>S>U. PMP = machine-only regs whitelisting phys ranges for S/U; pmpcfg
  byte [7]L [4:3]A(0 off/1 TOR/2 NA4/3 NAPOT) [2]X [1]W [0]R; uses TOR; needs **Smepmp** (fallback
  L=1). VexRiscv (SpinalHDL) on ULX3S ECP5-85F; SoC via LiteX; open toolchain (yosys/nextpnr).
- Memory map: 0x0000_0000 BROM (M:RX) · 0x1000_0000 MON_CODE/MON_DATA/SECRETS (M-only) ·
  0x2000_0000 WARDEN (S) · 0x3000_0000 COMPARTMENTS (U) · 0x4000_0000 SHARED_REQ (M+U) ·
  0x8000_0000 SDRAM · 0xF000_0000 EGRESS_MMIO (ESP32/SD/TRNG, M-only).
- Mediation ABI (ecall, a7=opcode, a0..): MEDIATE 0x52440001; SESSION_OPEN 0x52440010; REVOKE
  0x52440011; CLOSE 0x52440012; ATTEST_READ 0x52440020. Request in SHARED_REQ.
- Status/reason codes: 0x00 ALLOW; 0x10 DENY_NO_CAP; 0x11 DENY_TOOL; 0x12 DENY_ARG; 0x13 DENY_FLOW;
  0x14 DENY_MALFORMED; 0x15 DENY_REVOKED; 0x16 DENY_QUOTA; 0x20 ERR_EGRESS; 0x21 ERR_TIMEOUT;
  0x2F ERR_INTERNAL.
- Capability = unforgeable 16-byte record; host holds only an opaque handle (index into a per-session
  cspace [Cap;32], sessions ≤8). Cap fields: ctype(0 Empty/1 Net/2 File/3 Secret/4 Tool), rights,
  tool_id, pred_ref, flow_ref, secret_ref, aux, epoch. Attenuation-only derive; epoch bump = O(1)
  revocation; secrets are inject-only (never returned).
- Policy = small TOTAL declarative manifest compiled to fixed tables; predicate ops EQ, IN_SET,
  PREFIX, SUFFIX, HOST_IN_SET, SCHEME_EQ, RANGE, LEN_LE.
- IFC = minimal Denning lattice: confidentiality PUBLIC ⊑ SECRET, integrity UNTRUSTED ⊑ TRUSTED;
  2-bit labels; BOUNDARY-only (be honest: it does NOT track flows inside the host LLM); declassify
  only via explicit capability.
- Wire: USB CDC-ACM, COBS frame + CRC32; TypedArg TLV tags 0x01 URL{scheme,host,port,path}, 0x02
  PATH, 0x03 ENUM, 0x04 INT, 0x05 BYTES, 0x06 LABELSET. Endpoint frames only; Monitor re-derives.
- TCB budget: Monitor ≤ 2,500 LoC no_std Rust; BROM ≤ 300; CI `tokei` gate.
- Egress: network via ESP32 over an M-owned link (HONEST CAVEAT: ESP32 firmware is in the egress
  path; wired-Ethernet is a v2 upgrade); storage via LiteSDCard (M-only); TRNG = ring-oscillator +
  NIST SP 800-90B health tests.
- Boot: BROM measures Monitor with BLAKE2s vs a baked H_expected → halt on mismatch; Monitor then
  programs+locks PMP before any S/U runs; attestation = audit hash-chain head via ATTEST_READ.
- Out of scope (v1), state honestly where relevant: microarchitectural/timing side channels;
  physical/fault-injection; bitstream authenticity; host-side agent-memory poisoning; multi-agent
  collusion; availability/self-DoS.
If you need a fact not defined here or in the spec, pick a sensible value AND flag it in the ledger.

## 5. Footnote sources you may cite (superscript → Notes)
Anderson 1972 (reference monitor); Apple Platform Security / SPTM / SEP (arXiv:2510.09272);
Keystone (arXiv:1907.10119) & Sanctorum (arXiv:1812.10605); seL4 Reference Manual; OWASP Top 10 for
Agentic Applications 2026; Denning 1976 (lattice IFC); HiStar & Flume (DIFC); NIST SP 800-90B; COBS
(Cheshire & Baker); BLAKE2 RFC 7693; RISC-V Privileged ISA + Smepmp; VexRiscv; LiteX.

## 6. Chapter map (13 chapters; 09 Monitor already written)
01 Overview & the problem · 02 Threat model & trust tiers · 03 Privilege & isolation (PMP) ·
04 SoC, board & memory map · 05 Boot & root of trust · 06 Wire protocol & the tool-call ABI ·
07 Capabilities · 08 Policy & the compiler · 09 The Monitor (DONE) · 10 Information-flow control ·
11 Warden, compartments & sessions · 12 Egress & secrets · 13 Assurance (TCB, verification,
security analysis, roadmap). Cross-reference other chapters by name/number freely.

## 7. Deliverable + ledger report
Write each chapter to `docs/architecture/components/NN-shortname.html`. Then APPEND (do not rewrite)
a report block to `docs/architecture/LEDGER.md` with exactly this shell form so appends don't clash:

    cat >> docs/architecture/LEDGER.md <<'EOF'
    ### <agent-name> — chapters NN, MM   (<timestamp>)
    - files: components/NN-x.html (Llines), components/MM-y.html (Llines)
    - diagrams: <what SVGs you drew>
    - facts used: <the canonical facts you relied on>
    - assumptions/flags: <anything you invented or were unsure of — OWNER MUST CHECK>
    - cross-refs: <chapters you referenced>
    - self-check vs brief: style copied verbatim [y/n]; beginner primer [y/n]; alternatives-rejected [y/n]; footnotes [y/n]; depth ok [y/n]
    - notes for the owner: <anything to double-check>
    EOF

Do the work well. The owner (orchestrator) will read your ledger entry, open your file, and judge it
against this brief — and will rewrite it if it drifts. Make that unnecessary.
