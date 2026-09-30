#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Redoubt Phase 2 — simulated RISC-V SoC generator (VexRiscv + PMP, Verilator).
#
# This is the FIRST task of Phase 2 (V1): stand up a LiteX/Verilator SoC built
# around the prebuilt VexRiscv "secure" core (rv32ima + PMP: 16 regions, TOR)
# and boot the Phase-1 monitor image on it at the SoC memory map.
#
# Two responsibilities live here, and ONLY here:
#
#   1. The canonical memory map (Ch 3 §3.5) is defined ONCE, in `MEMORY_MAP`
#      below, and emitted to `sim/memory_map.json` (ruling P2-2: single source
#      of truth). The Rust side (pmp.rs in V2, the link scripts) consumes that
#      JSON; addresses are never hand-duplicated.
#
#   2. The SoC itself: the secure CPU with its reset vector at MON_CODE, the
#      canonical regions as bus slaves / declared regions, a "sim" UART whose
#      CSRs live inside the EGRESS_MMIO window at 0xF000_0000, and the monitor
#      image baked into the MON RAM so Verilator boots it directly.
#
# The sim toolchain (LiteX venv + oss-cad-suite Verilator) is provisioned
# locally and gitignored; see sim/README.md. This script is driven by
# `cargo xtask verilator` but is also runnable standalone (see `main`).

import argparse
import hashlib
import json
import os
import struct

from migen import *

from litex.build.generic_platform import Pins, Subsignal
from litex.build.io import CRG
from litex.build.sim import SimPlatform
from litex.build.sim.config import SimConfig

from litex.soc.integration.soc import SoCRegion
from litex.soc.integration.soc_core import SoCCore
from litex.soc.integration.builder import Builder

# ---------------------------------------------------------------------------
# Canonical memory map — Ch 3 §3.5 (ruling P2-2: THE single source of truth).
#
# Each entry: base, size, and the per-privilege permission string the hardware
# PMP will later enforce (M / S / U). "---" means no access from that mode.
# `backing` tells the generator how this region is realised in the sim SoC:
#   "ram"     : a writable+executable RAM slave (real block RAM in Verilator)
#   "rom"     : a read/exec RAM slave preloaded with the monitor image
#   "csr"     : the LiteX CSR/MMIO window (the UART lives here) — EGRESS_MMIO
#   "declare" : address-space reservation only (no backing store yet)
#   "sdram"   : backed by external SDRAM at `sdram_base` (arrives in a later task)
#
# For THIS task (V1) only MON_CODE, MON_DATA and EGRESS_MMIO (the UART) must be
# live to boot + print the banner; the rest are declared so V2 (PMP) and V4
# (Warden round-trip) have their addresses and can grow real backing later.
# ---------------------------------------------------------------------------
MEMORY_MAP = [
    # name          base          size        M      S      U        backing
    ("BROM",        0x0000_0000,  0x0000_4000, "r-x", "---", "---",   "declare"),
    ("MON_CODE",    0x1000_0000,  0x0000_8000, "r-x", "---", "---",   "rom"),
    ("MON_DATA",    0x1000_8000,  0x0001_8000, "rw-", "---", "---",   "ram"),
    ("SECRETS",     0x1002_0000,  0x0000_4000, "rw-", "---", "---",   "ram"),
    ("EGRESS_MMIO", 0xF000_0000,  0x0001_0000, "rw-", "---", "---",   "csr"),
    ("WARDEN",      0x2000_0000,  0x0010_0000, "rwx", "rwx", "---",   "ram"),
    ("SHARED_REQ",  0x4000_0000,  0x0000_1000, "rw-", "---", "rw-",   "ram"),
    ("COMPT_0",     0x3000_0000,  0x0010_0000, "---", "---", "rw-",   "sdram"),
]

# The compartment window (COMPT_0) is backed by external SDRAM at this base in
# later tasks. Recorded in the emitted JSON so V4 can wire it up.
SDRAM_BASE = 0x8000_0000

# Default reset vector: MON_CODE (V1/V2 boot + pmp scenarios). Phase-2 V3's
# measured-boot BROM at 0x0 flips this to 0x0 via `--reset-address 0`, so the
# CPU resets into the BROM, which measures MON_CODE and only then jumps to it.
RESET_ADDRESS = 0x1000_0000

# The measured-boot BROM (V3) hashes the monitor's FULL loaded/executed image:
# from MON_CODE base through the end of the last loaded-with-content section
# (.utext, after the link-sim.ld relayout), i.e. .text + .rodata + .data + .utext.
# The length is derived from the built ELF (`monitor_image_len`) — the SINGLE
# source — used for the hash here AND baked into the BROM (see `emit_h_expected`),
# so the two never drift and every executed byte is covered.

# CSR / EGRESS_MMIO window base. LiteX's default CSR base coincides with the
# canonical EGRESS_MMIO base, so the two are unified: the UART is a CSR-mock
# inside EGRESS_MMIO. These UART register addresses are deterministic for this
# fixed SoC config (csr_data_width=32, csr_paging=0x800) and are consumed by
# the sim UART driver in crates/monitor-bin/src/uart.rs.
CSR_BASE       = 0xF000_0000
UART_RXTX      = 0xF000_1800   # write a byte here to transmit
UART_TXFULL    = 0xF000_1804   # reads nonzero while the TX FIFO is full

SYS_CLK_FREQ = int(1e6)


def _perm_bits(m, s, u):
    return {"m": m, "s": s, "u": u}


def memory_map_dict(reset_address=RESET_ADDRESS):
    """The canonical memory map as a plain dict, ready to serialise."""
    regions = []
    for name, base, size, m, s, u, backing in MEMORY_MAP:
        entry = {
            "name":  name,
            "base":  base,
            "size":  size,
            "base_hex": f"0x{base:08x}",
            "end_hex":  f"0x{base + size:08x}",
            "perms": _perm_bits(m, s, u),
            "backing": backing,
        }
        if backing == "sdram":
            entry["sdram_base"] = SDRAM_BASE
        regions.append(entry)
    return {
        "// note": "GENERATED by sim/redoubt_soc.py (ruling P2-2). Do not hand-edit.",
        "reset_address": reset_address,
        "reset_address_hex": f"0x{reset_address:08x}",
        "cpu": {"type": "vexriscv", "variant": "secure", "isa": "rv32ima"},
        "csr": {
            "base": CSR_BASE,
            "uart_rxtx": UART_RXTX,
            "uart_txfull": UART_TXFULL,
        },
        "regions": regions,
    }


def emit_memory_map(path, reset_address=RESET_ADDRESS):
    with open(path, "w") as f:
        json.dump(memory_map_dict(reset_address), f, indent=2)
        f.write("\n")
    print(f"redoubt_soc: wrote memory map -> {path}")


# ---------------------------------------------------------------------------
# Sim platform: just the clock/reset and the serial (UART) pads the LiteX
# "sim" UART + serial2console module drive to stdout.
# ---------------------------------------------------------------------------
_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),
    ("serial", 0,
        Subsignal("source_valid", Pins(1)),
        Subsignal("source_ready", Pins(1)),
        Subsignal("source_data",  Pins(8)),
        Subsignal("sink_valid",   Pins(1)),
        Subsignal("sink_ready",   Pins(1)),
        Subsignal("sink_data",    Pins(8)),
    ),
]


class Platform(SimPlatform):
    def __init__(self):
        SimPlatform.__init__(self, "SIM", _io)


class RedoubtSimSoC(SoCCore):
    # Place the CSR/MMIO window at the canonical EGRESS_MMIO base.
    mem_map = {**SoCCore.mem_map, "csr": CSR_BASE}

    def __init__(self, image_words=None, brom_words=None, reset_address=RESET_ADDRESS):
        platform = Platform()
        self.crg = CRG(platform.request("sys_clk"))

        SoCCore.__init__(self, platform, clk_freq=SYS_CLK_FREQ,
            ident            = "Redoubt Phase 2 Sim SoC",
            cpu_type         = "vexriscv",
            cpu_variant      = "secure",   # prebuilt PMP core: rv32ima, 16 TOR regions
            # We supply our own image + regions; no integrated ROM/SRAM/BIOS.
            integrated_rom_size      = 0,
            integrated_sram_size     = 0,
            integrated_main_ram_size = 0,
            csr_data_width   = 32,
            uart_name        = "sim",
            with_timer       = True,
        )

        # -- Canonical regions -------------------------------------------------
        # MON_CODE + MON_DATA are backed by a single, size-aligned RAM spanning
        # both (0x1000_0000 .. 0x1002_0000, 128 KiB) so the monitor ELF — .text
        # in MON_CODE, .data/.bss/stack in MON_DATA — loads and runs directly.
        # The two logical regions remain distinct in memory_map.json for the V2
        # PMP split. A wishbone slave's origin must be aligned to its (power-of-
        # two-rounded) size, which a standalone 96 KiB MON_DATA at 0x1000_8000
        # would violate; the unified RAM sidesteps that cleanly.
        mon_base = self.region("MON_CODE")["base"]
        mon_size = self.region("MON_CODE")["size"] + self.region("MON_DATA")["size"]
        self.add_ram("mon_ram", origin=mon_base, size=mon_size,
                     contents=image_words or [], mode="rwx")

        # Other backed regions (declared live for V2/V4; small block RAMs).
        for name in ("SECRETS", "WARDEN", "SHARED_REQ"):
            r = self.region(name)
            self.add_ram(_slave(name), origin=r["base"], size=r["size"], mode="rwx")

        # BROM (Phase-2 V3 measured boot). When a brom image is supplied it is
        # backed by a real RAM at 0x0 preloaded with the measured-boot ROM, and
        # the reset vector points here (the CPU resets into the BROM, which
        # measures MON_CODE then jumps to it). Otherwise (V1/V2 boot/pmp) BROM
        # stays a declared-only address reservation.
        brom_r = self.region("BROM")
        if brom_words is not None:
            self.add_ram("brom", origin=brom_r["base"], size=brom_r["size"],
                         contents=brom_words, mode="rwx")
        else:
            self.bus.add_region("brom",
                SoCRegion(origin=brom_r["base"], size=brom_r["size"], linker=True))

        # COMPT_0 (SDRAM-backed in V4) stays a declared-only reservation.
        compt = self.region("COMPT_0")
        self.bus.add_region(_slave("COMPT_0"),
            SoCRegion(origin=compt["base"], size=compt["size"], linker=True))

        # EGRESS_MMIO is the CSR window (already created at CSR_BASE); the UART
        # CSRs live inside it. No extra slave needed.

        # -- Reset vector ------------------------------------------------------
        self.cpu.set_reset_address(reset_address)

    @staticmethod
    def region(name):
        for n, base, size, m, s, u, backing in MEMORY_MAP:
            if n == name:
                return {"base": base, "size": size, "backing": backing}
        raise KeyError(name)


def _slave(name):
    return name.lower()


# ---------------------------------------------------------------------------
# Load a bare-metal RISC-V ELF's PT_LOAD segments into a RAM image, returned as
# a list of little-endian 32-bit words for LiteX `add_ram(contents=...)`. Doing
# this in-process means the build needs no external objcopy / llvm-tools: the
# monitor ELF from cargo is consumed directly. Only 32-bit little-endian ELFs
# (the monitor image) are supported.
# ---------------------------------------------------------------------------
def load_elf_image_bytes(elf_path, base, size):
    """Lay the ELF's PT_LOAD segments into a `size`-byte, zero-initialised image
    spanning `[base, base+size)`; return it as a bytearray. Byte-addressable so
    the BROM measurement (a fixed byte range) and the tamper injection can work
    on the exact bytes the sim will load."""
    with open(elf_path, "rb") as f:
        elf = f.read()
    if elf[:4] != b"\x7fELF":
        raise SystemExit(f"{elf_path}: not an ELF")
    if elf[4] != 1 or elf[5] != 1:
        raise SystemExit(f"{elf_path}: expected 32-bit little-endian ELF")
    e_phoff   = struct.unpack_from("<I", elf, 28)[0]
    e_phentsz = struct.unpack_from("<H", elf, 42)[0]
    e_phnum   = struct.unpack_from("<H", elf, 44)[0]
    image = bytearray(size)
    loaded = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from("<8I", elf, off)
        if p_type != 1 or p_filesz == 0:   # PT_LOAD only
            continue
        if not (base <= p_vaddr and p_vaddr + p_filesz <= base + size):
            raise SystemExit(
                f"{elf_path}: PT_LOAD @0x{p_vaddr:08x}+0x{p_filesz:x} "
                f"outside RAM [0x{base:08x},0x{base + size:08x})")
        dst = p_vaddr - base
        image[dst:dst + p_filesz] = elf[p_offset:p_offset + p_filesz]
        loaded += p_filesz
    if loaded == 0:
        raise SystemExit(f"{elf_path}: no PT_LOAD segments found")
    print(f"redoubt_soc: loaded {loaded} bytes from {os.path.basename(elf_path)} "
          f"into RAM (0x{base:08x}, {size} bytes)")
    return image


def _words_from_bytes(image):
    """Pad to a 4-byte multiple and pack into 32-bit little-endian words."""
    if len(image) % 4:
        image = image + bytes(4 - (len(image) % 4))
    return list(struct.unpack("<%dI" % (len(image) // 4), image))


def load_elf_ram_image(elf_path, base, size):
    return _words_from_bytes(load_elf_image_bytes(elf_path, base, size))


def _mon_ram_extent():
    base = RedoubtSimSoC.region("MON_CODE")["base"]
    size = (RedoubtSimSoC.region("MON_CODE")["size"]
            + RedoubtSimSoC.region("MON_DATA")["size"])
    return base, size


def monitor_image_len(mon_elf):
    """Length of the monitor's measured image: MON_CODE base through the end of
    the last loaded-WITH-CONTENT section. Uses max(p_vaddr + p_filesz) over
    PT_LOAD segments with filesz > 0, so .bss (filesz 0, placed after .utext by
    the V3 relayout) is excluded and the range is fully-loaded and contiguous.
    THE single source for the BROM's HASH_LEN and this module's hash + tamper
    checks."""
    base = RedoubtSimSoC.region("MON_CODE")["base"]
    with open(mon_elf, "rb") as f:
        elf = f.read()
    e_phoff   = struct.unpack_from("<I", elf, 28)[0]
    e_phentsz = struct.unpack_from("<H", elf, 42)[0]
    e_phnum   = struct.unpack_from("<H", elf, 44)[0]
    end = base
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from("<8I", elf, off)
        if p_type == 1 and p_filesz > 0:   # PT_LOAD with actual content
            end = max(end, p_vaddr + p_filesz)
    length = end - base
    if length <= 0:
        raise SystemExit(f"{mon_elf}: could not determine loaded image length")
    return length


def mon_ram_bytes(mon_elf, tamper_offset=None):
    """The exact MON RAM image the sim loads, with an optional single-byte
    tamper (XOR 0xFF at `tamper_offset`) applied AFTER measurement — models an
    image whose loaded bytes no longer match the baked H_EXPECTED."""
    base, size = _mon_ram_extent()
    image = load_elf_image_bytes(mon_elf, base, size)
    if tamper_offset is not None:
        length = monitor_image_len(mon_elf)
        if not (0 <= tamper_offset < length):
            raise SystemExit(
                f"--tamper-offset {tamper_offset} must be inside the measured "
                f"range [0, 0x{length:x}) so the tamper is actually detected")
        image[tamper_offset] ^= 0xFF
        print(f"redoubt_soc: TAMPER flipped MON RAM byte @offset 0x{tamper_offset:x} "
              f"(measured range is [0, 0x{length:x}))")
    return image


def brom_ram_bytes(brom_elf):
    r = RedoubtSimSoC.region("BROM")
    return load_elf_image_bytes(brom_elf, r["base"], r["size"])


def emit_h_expected(mon_elf, path):
    """BLAKE2s-256 of the monitor's full measured image → a 36-byte file at
    `path`: a 4-byte little-endian length prefix (the measured HASH_LEN) followed
    by the 32-byte digest. The BROM's build.rs bakes BOTH from this one file, so
    the length and hash are single-sourced from the built ELF and can never drift
    from what this function (and the BROM at run time) measure:
    [MON_CODE_BASE, MON_CODE_BASE + length)."""
    length = monitor_image_len(mon_elf)
    image = mon_ram_bytes(mon_elf)
    digest = hashlib.blake2s(bytes(image[:length]), digest_size=32).digest()
    with open(path, "wb") as f:
        f.write(struct.pack("<I", length))
        f.write(digest)
    print(f"redoubt_soc: measured 0x{length:x} bytes; "
          f"H_EXPECTED = {digest.hex()} -> {path}")
    return digest


def _write_init(path, words):
    with open(path, "w") as f:
        for w in words:
            f.write(f"{w:08x}\n")


def emit_init(output_dir, mon_elf, brom_elf=None, tamper_offset=None):
    """Rewrite ONLY the $readmemh .init files a Verilated Vsim reads at startup
    (sim_mon_ram.init, and sim_brom.init if a brom image is given). This swaps
    the measured-boot scenario's memory contents WITHOUT re-Verilating — the SoC
    structure (regions, reset vector) is identical across the three sub-tests."""
    gateware = os.path.join(output_dir, "gateware")
    mon_words = _words_from_bytes(mon_ram_bytes(mon_elf, tamper_offset))
    _write_init(os.path.join(gateware, "sim_mon_ram.init"), mon_words)
    if brom_elf is not None:
        brom_words = _words_from_bytes(brom_ram_bytes(brom_elf))
        _write_init(os.path.join(gateware, "sim_brom.init"), brom_words)
    print(f"redoubt_soc: rewrote .init files in {gateware}")


# ---------------------------------------------------------------------------
# Generate: emit the SoC Verilog (monitor image baked into MON RAM) plus the
# Verilator build script + sim_config.js into <output_dir>/gateware. This does
# NOT compile — `cargo xtask verilator` runs the generated build_sim.sh (and
# then Vsim) itself, as a native process, so it can stream the UART and kill
# after the banner. Keeping the compile out of this (x86_64 Rosetta) Python is
# also what lets the native (arm64) toolchain do the Verilate cleanly; see
# sim/README.md. `--no-compile-software` is implied: the LiteX BIOS is never
# built (there is no RISC-V GCC), we load our own image.
# ---------------------------------------------------------------------------
def generate_sim(image_path, output_dir, threads=1, brom_path=None,
                 reset_address=RESET_ADDRESS):
    if image_path is None:
        raise SystemExit("generate requires --image <monitor ELF>")

    mon_base, mon_size = _mon_ram_extent()
    image_words = load_elf_ram_image(image_path, mon_base, mon_size)

    brom_words = None
    if brom_path is not None:
        brom_words = _words_from_bytes(brom_ram_bytes(brom_path))

    soc = RedoubtSimSoC(image_words=image_words, brom_words=brom_words,
                        reset_address=reset_address)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=SYS_CLK_FREQ)
    sim_config.add_module("serial2console", "serial")

    builder = Builder(soc,
        output_dir       = output_dir,
        compile_software = False,   # no BIOS / RISC-V GCC; we load our own image
        compile_gateware = False,
        csr_csv          = os.path.join(output_dir, "csr.csv"),
    )
    # run=False: emit Verilog + build_sim.sh + sim_config.js, do NOT Verilate
    # or run here.
    builder.build(
        sim_config  = sim_config,
        interactive = False,
        run         = False,
        threads     = threads,
    )

    gateware_dir = os.path.join(output_dir, "gateware")
    build_script = os.path.join(gateware_dir, "build_sim.sh")
    if not os.path.isfile(build_script):
        raise SystemExit(f"expected {build_script} after generate")
    print(f"redoubt_soc: generated SoC -> {gateware_dir}")
    print(f"redoubt_soc: verilate with: (cd {gateware_dir} && bash build_sim.sh)")
    return gateware_dir


def main():
    ap = argparse.ArgumentParser(description="Redoubt Phase 2 sim SoC generator")
    ap.add_argument("--emit-memory-map", metavar="PATH",
                    help="write the canonical memory map JSON and exit")
    ap.add_argument("--image", metavar="ELF",
                    help="monitor image (bare-metal riscv32 ELF) to bake into MON RAM")
    ap.add_argument("--output-dir", default="sim/build",
                    help="LiteX/Verilator build directory (default: sim/build)")
    ap.add_argument("--threads", default=1, type=int,
                    help="Verilator simulation threads")
    ap.add_argument("--generate", action="store_true",
                    help="generate the SoC Verilog + Verilator build script with --image baked in")
    ap.add_argument("--brom-image", metavar="ELF",
                    help="measured-boot ROM image (V3) to bake into the BROM region at 0x0")
    ap.add_argument("--reset-address", metavar="ADDR", default=None,
                    help="override the CPU reset vector (e.g. 0 for BROM); default MON_CODE")
    ap.add_argument("--emit-h-expected", metavar="PATH",
                    help="write BLAKE2s-256 of the monitor's measured MON_CODE bytes (32 raw bytes) and exit")
    ap.add_argument("--emit-init", action="store_true",
                    help="rewrite ONLY the .init files (mon_ram + brom) for a scenario, no re-Verilate")
    ap.add_argument("--tamper-offset", metavar="N", type=lambda s: int(s, 0), default=None,
                    help="flip one MON RAM byte at this offset when writing .init (tamper test)")
    args = ap.parse_args()

    reset = (RESET_ADDRESS if args.reset_address is None
             else int(args.reset_address, 0))

    if args.emit_h_expected:
        if not args.image:
            ap.error("--emit-h-expected requires --image")
        emit_h_expected(args.image, args.emit_h_expected)
        return

    if args.emit_init:
        if not args.image:
            ap.error("--emit-init requires --image")
        emit_init(args.output_dir, args.image, brom_elf=args.brom_image,
                  tamper_offset=args.tamper_offset)
        return

    if args.emit_memory_map:
        emit_memory_map(args.emit_memory_map, reset)
        if not args.generate:
            return

    if args.generate:
        generate_sim(args.image, args.output_dir, threads=args.threads,
                     brom_path=args.brom_image, reset_address=reset)
        return

    if not args.emit_memory_map:
        ap.error("nothing to do: pass --emit-memory-map and/or --generate")


if __name__ == "__main__":
    main()
