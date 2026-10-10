#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Redoubt Phase 4 (F1) — the SAME SoC as sim/redoubt_soc.py, re-targeted from the
# Verilator sim platform to the real ULX3S (Lattice ECP5) board.
#
# One source of truth: this file imports the region map (MEMORY_MAP), CSR
# constants, EgressMock and ELF/image helpers from redoubt_soc.py. The ONLY
# differences from the sim SoC are the platform (real pins, 25 MHz osc -> PLL),
# a real UART, and LiteDRAM + SDR-SDRAM PHY for COMPT_0 at 0x8000_0000.
#
# Run via `cargo xtask synth` (LiteX elaborate -> yosys -> nextpnr-ecp5 ->
# ecppack); also runnable standalone (see main()).

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redoubt_soc as common  # noqa: E402

from migen import *  # noqa: E402,F403

from litex.gen import LiteXModule  # noqa: E402
from litex.soc.integration.soc import SoCRegion  # noqa: E402
from litex.soc.integration.soc_core import SoCCore  # noqa: E402
from litex.soc.integration.builder import Builder  # noqa: E402

from litex_boards.platforms import radiona_ulx3s  # noqa: E402
from litex_boards.targets.radiona_ulx3s import _CRG  # noqa: E402

from litedram import modules as litedram_modules  # noqa: E402
from litedram.phy import GENSDRPHY  # noqa: E402

# The board's SDRAM is 32 MB (16M x 16): MT48LC16M16 in litedram. (Newer board
# revisions ship a 64 MB AS4C32M16; pass --sdram-module AS4C32M16 for those.)
DEFAULT_SDRAM_MODULE = "MT48LC16M16"
DEFAULT_SYS_CLK_HZ = 50e6
SDRAM_BASE = common.SDRAM_BASE   # 0x8000_0000 (COMPT_0 backing)

# WARDEN is a 1 MiB region in the canonical map. The sim backs all of it with
# block RAM; the ECP5-85F has only ~468 KiB of EBR in total, so on the FPGA the
# region keeps its canonical base/size (memory_map.json is unchanged) but only
# the first WARDEN_BACKED bytes are backed by EBR. FLAGGED in the F1 report.
WARDEN_BACKED = 0x0002_0000   # 128 KiB


# The VexRiscv core declares 0x8000_0000..0xFFFF_FFFF as uncached IO, which would
# swallow the SDRAM window. Only the CSR/EGRESS_MMIO window is IO in Redoubt.
from litex.soc.cores.cpu.vexriscv.core import VexRiscv  # noqa: E402
VexRiscv.io_regions = {common.CSR_BASE: 0x1000_0000}


class RedoubtUlx3sSoC(SoCCore):
    # CSR window at the canonical EGRESS_MMIO base; LiteDRAM main RAM at
    # 0x8000_0000 (LiteX would default it to 0x4000_0000 = SHARED_REQ).
    mem_map = {**SoCCore.mem_map, "csr": common.CSR_BASE, "main_ram": SDRAM_BASE}
    # Pin CSR pages so uart/egress match the sim (and memory_map.json); the SDRAM
    # controller banks go after them.
    csr_map = {"ctrl": 0, "identifier_mem": 1, "timer0": 2, "uart": 3, "egress": 4, "sdram": 5}

    def __init__(self, device="LFE5U-85F", sys_clk_freq=DEFAULT_SYS_CLK_HZ,
                 sdram_module_cls=DEFAULT_SDRAM_MODULE, image_words=None,
                 brom_words=None, reset_address=0x0, revision="2.0"):
        platform = radiona_ulx3s.Platform(device=device, revision=revision,
                                          toolchain="trellis")
        self.crg = _CRG(platform, sys_clk_freq)

        SoCCore.__init__(self, platform, clk_freq=sys_clk_freq,
            ident            = "Redoubt Phase 4 ULX3S SoC",
            cpu_type         = "vexriscv",
            cpu_variant      = "secure",   # SAME prebuilt PMP core as the sim
            integrated_rom_size      = 0,
            integrated_sram_size     = 0,
            integrated_main_ram_size = 0,
            csr_data_width   = 32,
            uart_name        = "serial",
            with_timer       = True,
        )
        # Keep the UART / egress CSR pages at their canonical addresses: LiteX
        # allocates CSR pages in registration order, and the SDRAM controller
        # adds CSR banks; park those AFTER the egress page (page 4).

        # -- Regions: same table as the sim, same backing choices -------------
        mon_base = common.RedoubtSimSoC.region("MON_CODE")["base"]
        mon_size = (common.RedoubtSimSoC.region("MON_CODE")["size"]
                    + common.RedoubtSimSoC.region("MON_DATA")["size"])
        self.add_ram("mon_ram", origin=mon_base, size=mon_size,
                     contents=image_words or [], mode="rwx")

        for name in ("SECRETS", "SHARED_REQ", "SERIAL_IN"):
            r = common.RedoubtSimSoC.region(name)
            self.add_ram(name.lower(), origin=r["base"], size=r["size"], mode="rwx")

        w = common.RedoubtSimSoC.region("WARDEN")
        self.add_ram("warden", origin=w["base"], size=WARDEN_BACKED, mode="rwx")

        brom_r = common.RedoubtSimSoC.region("BROM")
        if brom_words is not None:
            self.add_ram("brom", origin=brom_r["base"], size=brom_r["size"],
                         contents=brom_words, mode="rwx")
        else:
            self.bus.add_region("brom",
                SoCRegion(origin=brom_r["base"], size=brom_r["size"], linker=True))

        # -- COMPT_0 backing: real SDR SDRAM via LiteDRAM at 0x8000_0000 -------
        self.mem_map["main_ram"] = SDRAM_BASE   # SoCCore init resets it to 0x4000_0000
        self.sdrphy = GENSDRPHY(platform.request("sdram"), sys_clk_freq)
        self.add_sdram("sdram",
            phy           = self.sdrphy,
            module        = getattr(litedram_modules, sdram_module_cls)(sys_clk_freq, "1:1"),
            origin        = SDRAM_BASE,
            l2_cache_size = 0,   # no L2: the PMP core's loads/stores go direct
        )

        # Egress CSR mock (same module as the sim).
        self.add_module(name="egress", module=common.EgressMock())

        self.cpu.set_reset_address(reset_address)


def generate_ulx3s(mon_elf, brom_elf, output_dir, device="LFE5U-85F",
                   sys_clk_freq=DEFAULT_SYS_CLK_HZ, sdram_module=DEFAULT_SDRAM_MODULE,
                   build=False):
    """Elaborate the ULX3S SoC (monitor + BROM baked into EBR) and emit the
    gateware dir (Verilog, .lpf, build_top.sh). `build=False` stops before PnR."""
    mon_base, mon_size = common._mon_ram_extent()
    image_words = common.load_elf_ram_image(mon_elf, mon_base, mon_size)
    brom_words = common._words_from_bytes(common.brom_ram_bytes(brom_elf))

    soc = RedoubtUlx3sSoC(device=device, sys_clk_freq=sys_clk_freq,
                          sdram_module_cls=sdram_module, image_words=image_words,
                          brom_words=brom_words, reset_address=0x0)
    builder = Builder(soc, output_dir=output_dir, compile_software=False,
                      compile_gateware=build,
                      csr_csv=os.path.join(output_dir, "csr.csv"))
    builder.build(run=build)
    check_csrs(os.path.join(output_dir, "csr.csv"))
    return os.path.join(output_dir, "gateware")


def check_csrs(csv_path):
    """Fail closed if the FPGA CSR layout drifts from memory_map.json (the UART
    and egress registers the monitor addresses MUST be where the map says)."""
    common._check_egress_csrs(csv_path)
    seen = {}
    with open(csv_path) as f:
        for line in f:
            p = line.strip().split(",")
            if len(p) > 2 and p[0] == "csr_register" and p[1] in ("uart_rxtx", "uart_txfull"):
                seen[p[1]] = int(p[2], 0)
    want = {"uart_rxtx": common.UART_RXTX, "uart_txfull": common.UART_TXFULL}
    if seen != want:
        raise SystemExit(f"UART CSR layout drift: got {seen}, expected {want}")


def main():
    ap = argparse.ArgumentParser(description="Redoubt ULX3S SoC generator")
    ap.add_argument("--image", required=True, help="monitor ELF (link-fpga.ld)")
    ap.add_argument("--brom-image", required=True, help="BROM ELF")
    ap.add_argument("--output-dir", default="sim/build-ulx3s")
    ap.add_argument("--device", default="LFE5U-85F",
                    choices=["LFE5U-45F", "LFE5U-85F"])
    ap.add_argument("--sys-clk-freq", type=float, default=DEFAULT_SYS_CLK_HZ)
    ap.add_argument("--sdram-module", default=DEFAULT_SDRAM_MODULE)
    args = ap.parse_args()
    gw = generate_ulx3s(args.image, args.brom_image, args.output_dir,
                        device=args.device, sys_clk_freq=args.sys_clk_freq,
                        sdram_module=args.sdram_module, build=False)
    print(f"redoubt_ulx3s: elaborated -> {gw}")


if __name__ == "__main__":
    main()
