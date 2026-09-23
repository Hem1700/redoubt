# Research: agent threat model + the minimal enforcement primitive

- **Date:** 2026-09-22
- **Purpose:** with Redoubt's purpose locked (hardware-rooted OS to safely run AI agents +
  untrusted tools), find (a) the concrete agent threat model and (b) the *minimal,
  deterministic* enforcement primitive a tiny trust anchor can check. Research first.

## 1. The threat model is already standardized (OWASP Agentic Top 10, 2026)
OWASP published **Top 10 for Agentic Applications 2026** (ASI01–ASI10): treats an agent as
a *principal* with goals, tools, memory, and inter-agent protocols as distinct attack
surfaces. Key items:
- **ASI01 Agent Goal Hijack** — attacker manipulates objectives; agents cannot reliably
  distinguish legit instructions from malicious content (prompt injection, direct/indirect).
- **Tool misuse / tool poisoning** — malicious tool descriptions/behavior (our MCP
  tool-poisoning-scanner territory).
- **Memory poisoning** — persistent corruption of agent memory across sessions.
- **Identity/privilege abuse → ASI10 Rogue Agents.**
Refs: [OWASP GenAI](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
[MATRA attack-surface modeling](https://arxiv.org/pdf/2605.10763),
[pentests on agent systems](https://arxiv.org/pdf/2605.27042).

**Framing consequence:** the agent's *reasoning* is attacker-influenceable and must be
treated as **untrusted**. We cannot secure the agent by making it "think correctly."

## 2. The key insight that dissolves the "intent is fuzzy" trap
From the privilege-control / IFC literature (grounded):

> "Agent behavior is inherently non-deterministic… security requires **deterministic
> enforcement that holds regardless of how the LLM reasons, even under adversarial
> influence.** **Tool calls expose a structured interface (tool names and typed
> arguments), unlike the agent's unstructured reasoning, making them a natural point for
> deterministic security enforcement.**"

So: **don't judge fuzzy "intent" (that's the AI-reviewing-AI trap).** Enforce at the
**structured tool-call / effect boundary** with deterministic policy. The agent's brain
can be fully hijacked; it still cannot emit a tool call that violates policy, because a
non-AI monitor checks the *structured* call, not the *reasoning*.
Refs: [Progent: privilege control](https://arxiv.org/pdf/2504.11703),
[Securing AI Agents with Information-Flow Control](https://arxiv.org/pdf/2505.23643),
[ActPlane: OS-level policy for agent harnesses](https://arxiv.org/pdf/2606.25189),
[Microsoft least-privilege for agents](https://www.microsoft.com/en-us/security/blog/2026/07/16/least-privilege-for-ai-agents-identity-access-and-tool-binding/).

## 3. The minimal enforcement primitive: a reference monitor at the tool boundary
The literature converges on the **classical reference monitor** (Anderson, 1972):
an enforcement point that is **(a) tamper-proof, (b) always invoked (complete mediation),
(c) small enough to verify.** Applied to a new attacker class (autonomous agents) and a
new mediated operation (tool calls / external effects).
Ref: [Governed MCP](https://arxiv.org/pdf/2604.16870),
[agent containment reference architecture](https://www.cequence.ai/blog/ai/agent-containment-reference-architecture/),
[formal policy enforcement for agentic systems](https://arxiv.org/pdf/2602.16708).

What the monitor enforces (deterministic, checkable):
- **Capabilities** — the agent/tool holds only unforgeable grants for specific tools,
  endpoints, files, secrets. No ambient authority.
- **Typed-argument constraints** — the *arguments* of a tool call must satisfy a policy
  (e.g., `http.get(url)` only to an allowlisted origin — echoes our MCP SSRF CVE).
- **Information-flow labels** — data carries confidentiality/integrity labels; the monitor
  blocks flows that violate policy (e.g., a secret must not flow to an outbound tool).
- **Complete mediation** — *every* tool call / external effect passes the monitor; there
  is no side door.

**Containment guarantee (deterministic):** a fully prompt-injected / goal-hijacked agent
**cannot exceed the capabilities the monitor enforces**, because enforcement is on the
structured call, decided by non-AI logic.

## 4. Why this unifies everything we studied (and stays minimal)
- **Reference monitor = the "tiny trust anchor below the kernel"** — Apple SPTM, the
  RISC-V M-mode security monitor (Keystone/Dorami), *the redoubt itself.*
- **Deterministic enforcement at a structured boundary** = Hem's own rule ("verdict must
  be deterministic, never AI-judged"), now applied to agents.
- **ONE load-bearing primitive** (complete mediation by a capability reference monitor) =
  Baochip's lesson ("do more with less mechanism"), not a pile of layers.
- **Hardware-rooted + inspectable** = Baochip lesson; the monitor lives *below* the agent
  runtime and can't be bypassed even if everything above it is compromised.
- **Purpose** = the AI-agent white space (Hem's MCP/agent-security + memory-safety edge).

## 5. What's novel vs. the existing agent-security work
Progent, IFC-for-agents, ActPlane, Governed MCP, MS/NVIDIA all build the reference
monitor **in software, on Linux** (huge, unverifiable TCB; the monitor runs at the same or
lower trust than the thing it polices). **Redoubt's novelty:** the reference monitor is the
**hardware-rooted, tiny, inspectable trust anchor** — more privileged than the agent
runtime and the OS above it — so it holds even if the agent *and* the upper OS are fully
compromised. Nobody has built the *hardware-rooted, open, tiny-TCB* agent reference monitor.

## 6. The thesis (for review)
> **Redoubt is a hardware-rooted reference-monitor OS for AI agents: a tiny, inspectable,
> unbypassable trust anchor on an open RISC-V soft-core that mediates every tool call and
> external effect an agent makes — enforcing capabilities, typed-argument constraints, and
> information-flow labels deterministically — so a fully hijacked agent still cannot exceed
> its granted authority.**

## 7. Open questions (next research/design, not concluded)
- **Scope the threat model precisely:** which OWASP items are in-scope for v1 (goal hijack
  + tool misuse + exfiltration look core; memory poisoning and multi-agent collusion maybe
  later)?
- **Where does the agent's "brain" (the LLM) run** — off-device (host) with Redoubt as the
  mediating trust anchor for its tool calls, or on-device? (Off-device is realistic and
  keeps the FPGA's job small and sharp.)
- **What is the minimal policy language** the monitor evaluates (capabilities + arg
  predicates + labels) that stays deterministic and tiny?
- **What's the killer demo:** "prompt-inject the agent live; watch Redoubt deny the
  exfiltration/tool call it wasn't granted" — visible containment.
