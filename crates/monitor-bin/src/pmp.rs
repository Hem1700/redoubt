//! Phase-2 V2 — PMP lockdown for the LiteX/VexRiscv-`secure` sim SoC.
//!
//! `lock_regions()` is the monitor's first M-mode security act: it programs
//! and LOCKS the physical-memory-protection entries so that lower-privilege
//! (U-mode) code cannot reach the secrets, the egress hardware, the monitor's
//! own memory, or the Warden's memory, while U's own region still works.
//!
//! # Grounded on THIS core (verified against `VexRiscv_Secure.v`, not assumed)
//! The prebuilt `secure` VexRiscv PmpPlugin was read out of the gateware. Three
//! facts shape everything here and are the load-bearing V2 findings:
//!
//! 1. **NAPOT-only, with a nonstandard size encoding.** Every `dGuard`/`iGuard`
//!    hit term is hardwired to `pmpcfg[4:3] == 2'b11` (NAPOT); TOR (`2'b01`) and
//!    NA4 (`2'b10`) never match. The `PmpSetter` slices asymmetrically —
//!    `base = pmpaddr[29:5]` but `mask = ~ones[30:6]` — so a *standard* NAPOT
//!    `pmpaddr` encodes a region **one quarter** the intended size (empirically:
//!    a standard 4 KiB `pmpaddr` matched only 1 KiB). The verified encoding is
//!    `pmpaddr = (base>>2) | ((size>>1) - 1)`, and — because the size field is
//!    effectively 4x — each region's base must be aligned to **4x its size**.
//!    Granularity is 128 B. See `napot()`.
//!
//! 1b. **Uncached MMIO bypasses PMP.** `stageB_bypassCache = isIoAccess`
//!    (`addr[31]`), and on the bypass path the DataCache's `accessError` ignores
//!    `badPermissions` (the PMP permission result). So any access to the IO
//!    window `0x8000_0000..=0xFFFF_FFFF` — which includes EGRESS_MMIO at
//!    `0xF000_0000` (MMIO must be uncached, so it MUST live there) — is NOT
//!    PMP-enforceable. Egress isolation on this core is therefore by monitor
//!    mediation (the compartment holds no egress capability; the Phase-1
//!    `mediate` demo proves it), not by PMP. PMP walls only the CACHED TCB
//!    memory (secrets, monitor code/data, Warden — all below `0x8000_0000`).
//!    This is a documented V2 reduction; V3/V4 inherit it.
//!
//! 2. **M + U only, no Supervisor.** `misa` advertises no `S` bit and there are
//!    no `sstatus`/`sepc`/`stvec`/`medeleg` CSRs; all traps target M
//!    (`exceptionTargetPrivilege == 2'b11`). The prober therefore runs in
//!    U-mode (the untrusted compartment) — the strongest, least-privileged wall
//!    test. The map's S-owned WARDEN grant and its S/U split belong to V4.
//!
//! 3. **Plain PMP, no Smepmp/ePMP.** A matching entry's `R/W/X` apply to *every*
//!    mode; `L=1` only additionally extends the entry to M. There is no
//!    "M-only" permissioned entry: a locked `R-X` MON_CODE rule would grant U
//!    read+execute of the monitor's code. The correct plain-PMP realization of
//!    an M-only region is therefore **omission** — an *undescribed* address is
//!    denied to U by default (`allowRead = privilege==M`) and reached by M by
//!    exemption. Verified: with no entry matching, the hardware returns
//!    `allow = (CsrPlugin_privilege == 2'b11)`.
//!
//! Consequences for the entry table (documented in the V2 report):
//!   * MON_CODE, MON_DATA, SECRETS, EGRESS_MMIO, WARDEN, BROM, COMPT_0 are all
//!     **undescribed** → U-denied, M-exempt. These are the walls, by omission.
//!   * The only DESCRIBED entries are the U-reachable windows:
//!       - entry 0: SHARED_REQ, NAPOT, `RW-`, `L=1` — U's mailbox (own region),
//!         and the target of the lock-immutability check.
//!       - entry 1: UTEXT, NAPOT, `R-X`, `L=1` — a 2 KiB executable window at
//!         `0x1001_E000` (in mon_ram's tail, 8 KiB-aligned to satisfy the 4x
//!         NAPOT rule) that hosts the baked-in U prober so U has somewhere to
//!         fetch from without exposing the rest of the monitor image. (Models
//!         the compartment's own code region; V4 moves this to COMPT_0.)
//!   * entries 2..15 are left `A=OFF`, UNLOCKED, so V3 (stack guard) and V4
//!     (Warden/compartment windows) can still program them.
//!
//! All `unsafe` (CSR writes) is confined to this `sim`-only module; `monitor`
//! and `abi` remain `#![forbid(unsafe_code)]` and untouched.

// Not every generated region const is consumed by V2 (V3/V4 use the rest);
// silence dead_code for the whole PMP module rather than the generated file.
#![allow(dead_code)]

// Single source of truth (ruling P2-2): region bases/sizes come from
// sim/memory_map.json via build.rs — never hand-copied.
include!(concat!(env!("OUT_DIR"), "/memory_map_gen.rs"));

// --- pmpcfg byte fields ----------------------------------------------------
const CFG_R: u32 = 1 << 0;
const CFG_W: u32 = 1 << 1;
const CFG_X: u32 = 1 << 2;
const CFG_A_NAPOT: u32 = 0b11 << 3;
const CFG_L: u32 = 1 << 7;

/// entry 0 — SHARED_REQ: NAPOT, RW-, locked.
const CFG0_SHARED_REQ: u32 = CFG_L | CFG_A_NAPOT | CFG_R | CFG_W; // 0x9b
/// entry 1 — UTEXT: NAPOT, R-X, locked.
const CFG1_UTEXT: u32 = CFG_L | CFG_A_NAPOT | CFG_R | CFG_X; // 0x9d

/// The full `pmpcfg0` word: byte0 = entry0, byte1 = entry1, bytes2/3 = OFF.
const PMPCFG0_WORD: u32 = CFG0_SHARED_REQ | (CFG1_UTEXT << 8);

/// Size of the U-executable window. Power of two; the linker places `.utext`
/// at `0x1001_E000`, which is aligned to `4*UTEXT_SIZE` (8 KiB) as this core's
/// NAPOT encoding requires (see `napot`).
pub const UTEXT_SIZE: u32 = 0x800; // 2 KiB

extern "C" {
    /// Start of the `.utext` section (linker-placed, `UTEXT_SIZE`-aligned).
    /// This is the single source for the U-code window base — the address
    /// lives only in `link-sim.ld`; Rust reads the symbol.
    static _uprobe_entry: u8;
}

/// Address of the baked-in U prober / base of the UTEXT NAPOT window.
pub fn utext_base() -> u32 {
    // Address-of only; never dereferences the extern static.
    core::ptr::addr_of!(_uprobe_entry) as u32
}

/// Encode a NAPOT `pmpaddr` for `[base, base+size)` on THIS core's nonstandard
/// PmpSetter (see module note, fact 1). `size` must be a power of two and
/// `base` must be aligned to `4*size`. Verified against `VexRiscv_Secure.v`:
/// `pmpaddr = (base>>2) | ((size>>1) - 1)` matches exactly `[base, base+size)`.
const fn napot(base: u32, size: u32) -> u32 {
    (base >> 2) | ((size >> 1) - 1)
}

// --- raw CSR access (the only unsafe in the PMP path) ----------------------
macro_rules! csrw {
    ($csr:literal, $v:expr) => {
        core::arch::asm!(concat!("csrw ", $csr, ", {0}"), in(reg) $v, options(nomem, nostack))
    };
}
macro_rules! csrr {
    ($csr:literal) => {{
        let v: u32;
        core::arch::asm!(concat!("csrr {0}, ", $csr), out(reg) v, options(nomem, nostack));
        v
    }};
}

/// Program + LOCK the PMP entries per the memory map. MUST be the monitor's
/// first M-mode act, before any U-mode instruction runs. After it returns, the
/// locked trusted windows (SHARED_REQ, UTEXT) are immutable until reset, and
/// every other address is denied to U by default.
pub fn lock_regions() {
    let shared = napot(SHARED_REQ_BASE, SHARED_REQ_SIZE);
    let utext = napot(utext_base(), UTEXT_SIZE);
    unsafe {
        // Addresses first, then cfg — once cfg locks an entry, further writes
        // to its addr/cfg are ignored by hardware.
        csrw!("pmpaddr0", shared);
        csrw!("pmpaddr1", utext);
        // Entries 4..15 (pmpcfg1/2/3): explicitly OFF + unlocked for V3/V4.
        csrw!("pmpcfg1", 0u32);
        csrw!("pmpcfg2", 0u32);
        csrw!("pmpcfg3", 0u32);
        // Lock entries 0 (SHARED_REQ RW) and 1 (UTEXT R-X); 2/3 = OFF.
        csrw!("pmpcfg0", PMPCFG0_WORD);
    }
}

/// Review-Focus 4: after lock, an M-mode rewrite of a locked `pmpcfg`/`pmpaddr`
/// entry must be a no-op. Attempt to clear entry 0's cfg and move its addr, then
/// read both back; returns true iff nothing changed and the locked bytes are
/// still exactly what `lock_regions()` wrote.
pub fn immutability_check() -> bool {
    unsafe {
        let before_cfg = csrr!("pmpcfg0");
        let before_addr = csrr!("pmpaddr0");
        // Locked → both writes are ignored by the PmpPlugin write FSM.
        csrw!("pmpcfg0", 0u32);
        csrw!("pmpaddr0", 0xFFFF_FFFFu32);
        let after_cfg = csrr!("pmpcfg0");
        let after_addr = csrr!("pmpaddr0");
        before_cfg == after_cfg
            && before_addr == after_addr
            && after_cfg == PMPCFG0_WORD
    }
}
