# Hardware plan (v1)

- **Date:** 2026-09-22
- **Status:** decided (board + rooting). Derived from the locked thesis.

## Topology (what the thesis forces)
The LLM/agent brain runs on the **host** (untrusted, may be hijacked). Redoubt on the FPGA
is the **hardware-rooted reference monitor** the agent's effects must pass through. The
agent has **no direct authority** — it issues *structured tool-call requests* to Redoubt,
which holds the real capabilities/secrets and **owns the egress**, then performs or denies.

```
[ Host: LLM + agent + untrusted tools ]         untrusted
        │ structured tool-call requests (USB)
        ▼
[ REDOUBT on ULX3S ]  reference monitor: caps + typed-arg predicates + info-flow labels
        │ deterministic check -> perform or DENY
        ▼
 controlled egress: network (ESP32 wifi) + storage (microSD)   ← Redoubt owns these
```
Effectively: **an HSM + firewall for agent tool calls.**

## Board: ULX3S (Lattice ECP5 LFE5U-85F, ~$135)
Chosen for: biggest FPGA in budget (85K LUT — comfortable for VexRiscv + LiteX + monitor),
**fully open toolchain** (yosys / nextpnr / prjtrellis), lowest friction, most demo-ready.

| Requirement | ULX3S resource |
|-------------|----------------|
| FPGA logic | ECP5 **85F** (85K LUT) |
| DRAM (OS + policy state) | **32 MB SDRAM** (MT48LC32M16) |
| Host link (agent → Redoubt) | USB (FT231X: USB-serial + JTAG) |
| Controlled network egress | **ESP32** (wifi), driven by the FPGA — agent has no direct path |
| Controlled storage egress | **microSD** |
| NV store (policy/secrets/keys, boot) | **QSPI flash** (IS25LP128F) + microSD |
| Entropy (TRNG) | ring-oscillator TRNG in FPGA fabric (LiteX) |
| Demo feedback ("ALLOWED/DENIED") | **11 LEDs** (guaranteed) + SSD1331 **OLED** footprint (optional, nicer) + HDMI |

**Honest caveat:** ESP32 as the network-egress path means the ESP32's (closed-ish)
firmware is in the egress trust path. Acceptable for a v1 demonstrator (the agent still
can't reach it except through Redoubt). For a purist "Redoubt owns the wire," a
wired-Ethernet ECP5 board (ECPIX-5 / Colorlight) is the later upgrade. Recorded, not
blocking.

## Internal rooting (v1): M-mode software monitor + PMP + measured boot
- **CPU:** VexRiscv on LiteX, configured **M/S/U + PMP** (MMU/Sv32 optional; PMP is the
  load-bearing isolation for v1).
- **Reference monitor = M-mode software**, its integrity rooted by:
  - **PMP** (hardware-enforced): S-mode OS and U-mode agent-facing services **cannot**
    touch the monitor's memory or the secret/egress regions except through the monitor.
  - **Measured boot**: boot ROM measures the monitor image before handing control up.
- **Why this is "hardware-rooted enough" for v1:** PMP is hardware-enforced and only
  M-mode-configurable, so the monitor sits below the S-mode OS and the agent-facing stack
  and is unbypassable by them — matching the Keystone/Dorami M-mode-SM pattern.

## v2 (the distinctive silicon, later): custom RTL mediation gate
A custom **LiteX RTL peripheral** on the egress bus (network/storage/secret engines) that
enforces capabilities **in hardware**, so not even compromised M-mode software can bypass
it. This is Redoubt's novel silicon contribution and the "build a chip" milestone — scoped
to one elegant primitive (Baochip lesson). Deferred until v1 works.

## Software/SoC stack (all open)
- **LiteX** generates the SoC (VexRiscv, SDRAM controller via LiteDRAM, UART, SPI/SD,
  QSPI, GPIO/LED, links to ESP32).
- **Redoubt** = the M-mode monitor + minimal S-mode services + U-mode agent-facing endpoint.
- Toolchain: yosys + nextpnr-ecp5 + prjtrellis; RISC-V GCC/LLVM; fujprog/openFPGALoader to
  flash the ULX3S.

## To order
- **ULX3S 85F** (Crowd Supply / Mouser / distributors). Consider the variant with ESP32
  populated (for network egress) and, optionally, the SSD1331 OLED for the demo.
