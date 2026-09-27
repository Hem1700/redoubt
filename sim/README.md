# Redoubt Phase 2 — simulated RISC-V SoC (VexRiscv + PMP, Verilator)

This directory stands up a **simulated SoC** built around the prebuilt VexRiscv
`secure` core (rv32ima + PMP: 16 TOR regions) in LiteX/Verilator, and boots the
Phase-1 monitor image on it at the real SoC memory map. It is the foundation for
the rest of Phase 2: PMP lockdown (V2), measured boot (V3), and the Warden
round-trip (V4).

The V1 deliverable is the **boot proof**:

```
cargo xtask verilator -- boot
```

builds the monitor image for the SoC map, generates + Verilates the SoC with the
image baked into MON RAM, runs the Verilated model, and asserts the monitor's
banner `redoubt: monitor online` appears on the simulated UART.

## What's here (committed)

| File | Role |
|------|------|
| `redoubt_soc.py`  | The SoC generator **and** the single source of truth for the memory map (ruling P2-2). Defines `MEMORY_MAP`, emits `memory_map.json`, builds the LiteX SoC (secure CPU, canonical regions, EGRESS_MMIO=CSR window with the UART, reset vector at MON_CODE), and loads the monitor ELF into MON RAM. |
| `memory_map.json` | Generated from `redoubt_soc.py`. Consumed by the Rust side (V2 `pmp.rs`, link scripts). **Do not hand-edit** — regenerate with `--emit-memory-map`. |
| `requirements.txt`| Pinned LiteX/migen Python packages. |
| `README.md`       | This file. |

## What's *not* committed (provisioned locally, gitignored)

- `sim/.venv/`         — LiteX in a **Python 3.10** venv (3.11 breaks migen's clock-domain naming).
- `sim/oss-cad-suite/` — the Verilator 5.053 toolchain.
- `sim/simdeps/`       — arm64 `json-c` + `libevent` static libs the LiteX Verilator sim links against (see "Apple-silicon note").
- `sim/build/`         — LiteX/Verilator build output (`gateware/obj_dir/Vsim`, etc.).

## Toolchain recipe

### 1. LiteX (Python 3.10 venv)

```
python3.10 -m venv sim/.venv
sim/.venv/bin/pip install -r sim/requirements.txt
```

### 2. Verilator (oss-cad-suite)

Unpack the oss-cad-suite bundle into `sim/oss-cad-suite/`. The harness sets its
env itself, but for a manual run:

```
export VERILATOR_ROOT="$PWD/sim/oss-cad-suite/share/verilator"
export PATH="$PWD/sim/oss-cad-suite/bin:$PATH"
```

### 3. Rust: nightly + `riscv32ima` (the compressed-free sim image)

The `secure` core is **rv32ima with no compressed-instruction decoder**, so the
sim image must contain **zero** `c.*` opcodes. On this stable toolchain
`-C target-feature=-c` is **silently ignored** (verified: identical codegen), and
`core` for `riscv32imac` is itself compressed. So the sim image is built for the
compressed-free **`riscv32ima-unknown-none-elf`** target, whose `core` is compiled
from source with `build-std` on nightly:

```
rustup toolchain install nightly --profile minimal -c rust-src
```

`cargo xtask verilator` invokes `rustup run nightly cargo build … -Z build-std=core`
automatically. (The QEMU image stays `riscv32imac` + `imac`; QEMU decodes C.)

### 4. Apple-silicon note (`sim/simdeps`)

The LiteX Verilator sim core links `json-c` and `libevent`. On this machine the
only ones present are **x86_64** (Intel Homebrew at `/usr/local`), but the Command
Line Tools are **arm64-only**, so x86_64 compiles can't run (`xcrun` has no x86_64
`libxcrun`). The fix is a native **arm64** build, which needs arm64 copies of those
two libraries. Build them once into `sim/simdeps` (static):

```
# libevent (autotools)
curl -L -o libevent.tgz \
  http://deb.debian.org/debian/pool/main/libe/libevent/libevent_2.1.12-stable.orig.tar.gz
tar xzf libevent.tgz && cd libevent-2.1.12-stable
./configure --prefix="$PWD/../../sim/simdeps" --disable-shared --enable-static \
  --disable-openssl --disable-samples --disable-libevent-regress \
  CC=clang CFLAGS="-arch arm64"
make -j4 && make install && cd ..

# json-c 0.13.1 (autotools; 0.17 needs the x86_64 cmake, which is broken here)
curl -L -o json-c.tgz https://s3.amazonaws.com/json-c_releases/releases/json-c-0.13.1.tar.gz
tar xzf json-c.tgz && cd json-c-0.13.1
./configure --prefix="$PWD/../../sim/simdeps" --disable-shared --enable-static \
  CC=clang CFLAGS="-arch arm64 -Wno-implicit-const-int-float-conversion -Wno-implicit-int-float-conversion"
make -j4 && make install
```

`cargo xtask verilator` passes `-I sim/simdeps/include` / `-L sim/simdeps/lib` to
the Verilate step. On a Linux host with system `json-c`/`libevent`, `sim/simdeps`
is unnecessary and the default `-I/-L` can be empty.

## How `cargo xtask verilator -- boot` works

1. **Build the sim image** — `rustup run nightly cargo build -p monitor-bin
   --features sim --target riscv32ima-unknown-none-elf -Z build-std=core`, linked
   with `crates/monitor-bin/link-sim.ld` (per-image `RUSTFLAGS`, own
   `CARGO_TARGET_DIR=target/sim`; the QEMU image is untouched — ruling P2-1).
2. **Emit** `sim/memory_map.json` and **generate** the SoC Verilog with the ELF
   baked into MON RAM (`sim/.venv/bin/python redoubt_soc.py --emit-memory-map …
   --generate --image <elf>`).
3. **Verilate** `sim/build/gateware/build_sim.sh` natively, with the Verilator env
   and the `sim/simdeps` include/lib paths, producing `gateware/obj_dir/Vsim`.
4. **Run** `Vsim`, stream the UART, assert the banner `redoubt: monitor online`,
   then kill it — the LiteX sim has no sifive finisher, so a UART sentinel is the
   pass criterion.

A full run Verilates the whole SoC and takes a few minutes; be patient.

## Memory map (Ch 3 §3.5)

Canonical, defined once in `redoubt_soc.py` and emitted to `memory_map.json`:

| Region | Range | M | S | U |
|--------|-------|---|---|---|
| BROM        | `0x0000_0000`–`0x0000_2000` | R-X | — | — |
| MON_CODE    | `0x1000_0000`–`0x1000_8000` | R-X | — | — |
| MON_DATA    | `0x1000_8000`–`0x1002_0000` | RW- | — | — |
| SECRETS     | `0x1002_0000`–`0x1002_4000` | RW- | — | — |
| WARDEN      | `0x2000_0000`–`0x2010_0000` | RWX | RWX | — |
| COMPT_0     | `0x3000_0000`–`0x3010_0000` | — | — | RW- (SDRAM-backed, V4) |
| SHARED_REQ  | `0x4000_0000`–`0x4000_1000` | RW- | — | RW- |
| EGRESS_MMIO | `0xF000_0000`–`0xF001_0000` | RW- | — | — (= LiteX CSR window; UART lives here) |

Reset vector for V1 is **MON_CODE** (`0x1000_0000`); the measured-boot BROM at
`0x0` arrives in V3.
