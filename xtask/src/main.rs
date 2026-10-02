use anyhow::Context;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("loc-gate") => loc_gate(),
        Some("qemu") => {
            // `cargo xtask qemu -- mediate` reaches us as ["qemu", "--",
            // "mediate"] (the alias contributes one `--`). Drop any `--`
            // separators and treat the first remaining token as the
            // scenario selector.
            let rest: Vec<String> = args.filter(|a| a != "--").collect();
            qemu(rest.first().map(String::as_str))
        }
        Some("verilator") => {
            // `cargo xtask verilator -- boot` -> ["verilator", "--", "boot"].
            let rest: Vec<String> = args.filter(|a| a != "--").collect();
            match rest.first().map(String::as_str) {
                Some("measure") => verilator_measure(),
                other => verilator(other),
            }
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
        None => anyhow::bail!(
            "usage: cargo xtask <loc-gate|qemu [-- mediate]|verilator -- <boot|pmp|measure|mediate|endpoint>>"
        ),
    }
}

/// Counts non-blank, non-comment-only lines of Rust source under `path`.
///
/// `path` may be a directory (counted recursively) or a single file.
/// Returns `None` if `path` does not exist.
fn count_rust_lines(path: impl AsRef<Path>) -> Option<usize> {
    let path = path.as_ref();
    if !path.exists() {
        return None;
    }
    let mut total = 0usize;
    if path.is_dir() {
        for entry in walk_rs_files(path) {
            total += count_lines_in_file(&entry);
        }
    } else {
        total += count_lines_in_file(path);
    }
    Some(total)
}

fn walk_rs_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                files.push(p);
            }
        }
    }
    files
}

fn count_lines_in_file(path: &Path) -> usize {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return 0;
    };
    count_significant_lines(&contents)
}

/// True if `trimmed` marks the start of a test-only block we should skip:
/// a `#[cfg(test)]` attribute, or a `mod tests` item (with or without a
/// trailing `{`).
fn is_test_marker(trimmed: &str) -> bool {
    if trimmed.starts_with("#[cfg(test)]") {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("mod tests") {
        let rest = rest.trim_start();
        return rest.is_empty() || rest.starts_with('{') || rest.starts_with(';');
    }
    false
}

/// Counts non-blank lines, excluding anything inside a `#[cfg(test)]` /
/// `mod tests { ... }` block (tracked by brace depth), so unit tests do not
/// count against the TCB LoC budget.
fn count_significant_lines(contents: &str) -> usize {
    let mut count = 0usize;
    let mut depth = 0i32;
    let mut skip_from_depth: Option<i32> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        let brace_delta = line.matches('{').count() as i32 - line.matches('}').count() as i32;

        if skip_from_depth.is_none() && is_test_marker(trimmed) {
            skip_from_depth = Some(depth);
            depth += brace_delta;
            continue;
        }

        if let Some(start_depth) = skip_from_depth {
            depth += brace_delta;
            if depth <= start_depth {
                skip_from_depth = None;
            }
            continue;
        }

        depth += brace_delta;
        if !trimmed.is_empty() {
            count += 1;
        }
    }

    count
}

fn loc_gate() -> anyhow::Result<()> {
    let mon = count_rust_lines("crates/monitor/src").unwrap_or(0); // excludes tests via cfg
    anyhow::ensure!(mon <= 2500, "monitor TCB {mon} > 2500 LoC budget");

    // V3: the boot ROM is now its own crate (was a stale, never-created
    // crates/monitor-bin/src/boot.rs). Cap the smallest trust element at 300 LoC.
    let brom = count_rust_lines("crates/brom/src").unwrap_or(0);
    anyhow::ensure!(brom <= 300, "boot ROM {brom} > 300 LoC budget");

    // V3 (Phase-1 deferred follow-up): the sim-only M-mode `unsafe` modules are
    // TCB too. Tally arch + pmp + simtrap and hold them under a sensible cap.
    let arch = count_rust_lines("crates/monitor-bin/src/arch.rs").unwrap_or(0);
    let pmp = count_rust_lines("crates/monitor-bin/src/pmp.rs").unwrap_or(0);
    let simtrap = count_rust_lines("crates/monitor-bin/src/simtrap.rs").unwrap_or(0);
    // V4: the shared fixtures and the sim `mediate` driver are TCB too.
    let fixtures = count_rust_lines("crates/monitor-bin/src/fixtures.rs").unwrap_or(0);
    let simmediate = count_rust_lines("crates/monitor-bin/src/simmediate.rs").unwrap_or(0);
    let tcb = arch + pmp + simtrap + fixtures + simmediate;
    anyhow::ensure!(tcb <= 2000, "monitor-bin M-mode TCB {tcb} > 2000 LoC budget");

    println!(
        "loc-gate ok: monitor={mon} brom={brom} \
         monitor-bin-tcb={tcb} (arch={arch} pmp={pmp} simtrap={simtrap} \
         fixtures={fixtures} simmediate={simmediate})"
    );
    Ok(())
}

const BOOT_BANNER: &str = "redoubt: monitor online";
const QEMU_TIMEOUT: Duration = Duration::from_secs(15);

/// The exact UART lines the `mediate` scenario must emit — the three
/// containment demo verdicts, proof the injected secret went outbound but
/// not into the response, and the interrupt-masking (Review-Focus 7) frame
/// check. Asserted by `cargo xtask qemu -- mediate`.
const MEDIATE_EXPECTED_LINES: &[&str] = &[
    "mediate: benign=ALLOW",
    "mediate: benign-secret=outbound-present",
    "mediate: benign-secret=response-absent",
    "mediate: attack=DENY_ARG",
    "mediate: flow=DENY_FLOW",
    "mediate: irq-frame=OK",
];

/// Path to the workspace root, derived from this crate's own manifest
/// directory (`<repo>/xtask`) so this works regardless of the directory
/// `cargo xtask` was invoked from.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate lives one level below the workspace root")
        .to_path_buf()
}

/// Cross-builds `monitor-bin` for `riscv32imac-unknown-none-elf`, boots the
/// resulting ELF in `qemu-system-riscv32 -machine virt`, and asserts (a)
/// the boot banner appears on stdout and (b) QEMU exits cleanly (status 0),
/// which it does via the `sifive_test` finisher device at 0x0010_0000 once
/// `monitor-bin` writes 0x5555 to it. No human needs to watch the console.
fn qemu(scenario: Option<&str>) -> anyhow::Result<()> {
    let mediate = match scenario {
        None => false,
        Some("mediate") => true,
        Some(other) => anyhow::bail!("unknown qemu scenario: {other} (expected `mediate`)"),
    };

    let repo_root = repo_root();
    let monitor_bin_dir = repo_root.join("crates/monitor-bin");
    anyhow::ensure!(
        monitor_bin_dir.is_dir(),
        "expected crates/monitor-bin at {}",
        monitor_bin_dir.display()
    );

    // Build from within crates/monitor-bin so its own .cargo/config.toml
    // (target = riscv32imac-unknown-none-elf, linker script rustflags) is
    // picked up by cargo's directory-based config discovery.
    let build_status = Command::new("cargo")
        .current_dir(&monitor_bin_dir)
        .args([
            "build",
            "--target",
            "riscv32imac-unknown-none-elf",
            "-p",
            "monitor-bin",
        ])
        .status()
        .context("failed to spawn `cargo build` for monitor-bin")?;
    anyhow::ensure!(
        build_status.success(),
        "cargo build -p monitor-bin --target riscv32imac-unknown-none-elf failed"
    );

    let elf = repo_root.join("target/riscv32imac-unknown-none-elf/debug/monitor-bin");
    anyhow::ensure!(
        elf.is_file(),
        "expected monitor-bin ELF at {} after build",
        elf.display()
    );
    let elf_path = elf
        .to_str()
        .context("monitor-bin build output path is not valid UTF-8")?;

    let mut child = Command::new("qemu-system-riscv32")
        .args([
            "-machine",
            "virt",
            "-bios",
            elf_path,
            "-nographic",
            "-no-reboot",
            "-serial",
            "mon:stdio",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn qemu-system-riscv32 (is it installed and on PATH?)")?;

    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        buf
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + QEMU_TIMEOUT;
    let exit_status = loop {
        if let Some(status) = child.try_wait().context("failed to poll qemu process")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "qemu-system-riscv32 did not exit within {:?}; \
                 monitor-bin likely never reached the sifive_test finisher",
                QEMU_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    print!("{stdout}");
    eprint!("{stderr}");

    anyhow::ensure!(
        stdout.contains(BOOT_BANNER),
        "qemu stdout did not contain the expected boot banner {BOOT_BANNER:?}"
    );
    anyhow::ensure!(
        exit_status.success(),
        "qemu-system-riscv32 exited with {exit_status:?}; expected a clean exit \
         (monitor-bin writes 0x5555 to the sifive_test finisher on success, 0x3333 on panic)"
    );

    if mediate {
        for line in MEDIATE_EXPECTED_LINES {
            anyhow::ensure!(
                stdout.contains(line),
                "qemu stdout did not contain the expected mediate line {line:?}"
            );
        }
        println!(
            "cargo xtask qemu -- mediate: PASS (boot banner + all {} mediate verdict lines + clean exit)",
            MEDIATE_EXPECTED_LINES.len()
        );
    } else {
        println!("cargo xtask qemu: PASS (boot banner observed, qemu exited 0)");
    }
    Ok(())
}

// ===========================================================================
// Phase-2 V1: Verilator harness.
//
// `cargo xtask verilator -- boot` mirrors the qemu() runner (build image ->
// run -> assert-on-UART -> timeout), but for the LiteX/VexRiscv-secure SoC in
// Verilator instead of QEMU:
//
//   1. Build the SIM monitor image (ruling P2-1 dual target). The `secure`
//      core is rv32ima with NO compressed decoder, and stable rustc silently
//      ignores `-C target-feature=-c`; so the sim image is built for the
//      compressed-free `riscv32ima-unknown-none-elf` target via nightly
//      `-Z build-std=core`, linked with link-sim.ld at MON_CODE. The QEMU
//      image (imac) and `cargo xtask qemu` are untouched.
//   2. Emit the canonical memory map to sim/memory_map.json (ruling P2-2).
//   3. Generate the SoC Verilog (venv Python) with the image baked into MON RAM.
//   4. Verilate + compile the model (native), producing gateware/obj_dir/Vsim.
//   5. Run Vsim, stream the UART, and assert the boot banner appears; the LiteX
//      sim has no sifive finisher, so success = banner observed, then we kill.
//
// Toolchain locations + the SIM_* env are documented in sim/README.md. All of
// sim/{.venv,oss-cad-suite,simdeps} are provisioned locally and gitignored.
// ===========================================================================

/// Verilator toolchain paths, all under the worktree.
struct SimPaths {
    repo: PathBuf,
}

impl SimPaths {
    fn new() -> Self {
        Self { repo: repo_root() }
    }
    fn venv_python(&self) -> PathBuf { self.repo.join("sim/.venv/bin/python") }
    fn oss_bin(&self) -> PathBuf { self.repo.join("sim/oss-cad-suite/bin") }
    fn verilator_root(&self) -> PathBuf { self.repo.join("sim/oss-cad-suite/share/verilator") }
    fn simdeps_include(&self) -> PathBuf { self.repo.join("sim/simdeps/include") }
    fn simdeps_lib(&self) -> PathBuf { self.repo.join("sim/simdeps/lib") }
    fn generator(&self) -> PathBuf { self.repo.join("sim/redoubt_soc.py") }
    fn memory_map(&self) -> PathBuf { self.repo.join("sim/memory_map.json") }
    fn link_script(&self) -> PathBuf { self.repo.join("crates/monitor-bin/link-sim.ld") }
    fn sim_target_dir(&self) -> PathBuf { self.repo.join("target/sim") }
    fn sim_elf(&self) -> PathBuf {
        self.repo
            .join("target/sim/riscv32ima-unknown-none-elf/debug/monitor-bin")
    }
    fn build_dir(&self) -> PathBuf { self.repo.join("sim/build") }
    fn gateware_dir(&self) -> PathBuf { self.build_dir().join("gateware") }
    fn vsim(&self) -> PathBuf { self.gateware_dir().join("obj_dir/Vsim") }
    fn brom_link_script(&self) -> PathBuf { self.repo.join("crates/brom/link-brom.ld") }
}

/// PATH with the oss-cad-suite bin (verilator) prepended.
fn path_with_oss(p: &SimPaths) -> String {
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", p.oss_bin().display(), existing)
}

/// Timeout for the Verilated run to reach the banner. The sim runs at 1 MHz
/// and prints the banner within a few simulated ms; 90s covers CI variance.
const VERILATOR_RUN_TIMEOUT: Duration = Duration::from_secs(90);

/// UART lines the `pmp` scenario must observe, in the deterministic order the
/// prober produces them. Addresses mirror `sim/memory_map.json` (the probe
/// targets in `simtrap.rs`); this list is the test oracle for
/// `cargo xtask verilator -- pmp`.
///
/// `PMP-LOCK=OK` = lock_regions() ran + own-region magic seeded;
/// `PMP-IMMUTABLE=OK` = post-lock M rewrite of a locked pmpcfg was a no-op;
/// each `PMP-FAULT` = a U-mode load PMP denied (mcause 5), one per forbidden
/// (cached) target (SECRETS, MON_DATA, MON_CODE, WARDEN, an undescribed gap,
/// the SECRETS boundary byte, and the SHARED_REQ NAPOT edge+1);
/// `PMP-OWN=OK` = U's own region (SHARED_REQ) read back the magic;
/// `PMP-DONE` = prober finished, monitor idles.
///
/// EGRESS_MMIO (0xf000_0000) is intentionally absent: it is uncached IO and
/// this VexRiscv-secure core bypasses PMP for uncached accesses, so it is not
/// PMP-deniable (egress is monitor-mediated instead). See the V2 report.
const PMP_EXPECTED_LINES: &[&str] = &[
    "PMP-LOCK=OK",
    "PMP-IMMUTABLE=OK",
    "PMP-FAULT mcause=5 addr=0x10020100", // SECRETS
    "PMP-FAULT mcause=5 addr=0x10008000", // MON_DATA
    "PMP-FAULT mcause=5 addr=0x10000000", // MON_CODE
    "PMP-FAULT mcause=5 addr=0x20000000", // WARDEN
    "PMP-FAULT mcause=5 addr=0x50000000", // undescribed gap (Review-Focus 2)
    "PMP-FAULT mcause=5 addr=0x10023fff", // SECRETS last byte (boundary)
    "PMP-OWN=OK",                         // SHARED_REQ own-region control read
    "PMP-FAULT mcause=5 addr=0x40001000", // SHARED_REQ NAPOT edge+1 (boundary)
    "PMP-DONE",
];

/// Lines that, if seen, mean a wall failed open or a control read went wrong —
/// the scenario must fail if any appears.
const PMP_FORBIDDEN_LINES: &[&str] = &[
    "PMP-IMMUTABLE=FAIL",
    "PMP-OWN=BAD",
    "PMP-FAIL",
    "addr=0x40000800", // a fault at the own-region control address = wall too tight
];

/// UART lines the Verilated `mediate` scenario (Phase-2 V4) must observe: one
/// deterministic line per canonical case, byte-identical in shape to the QEMU
/// `mediate` demo's, plus the sink-driven evidence. M + U model (no S-mode).
const SIM_MEDIATE_EXPECTED_LINES: &[&str] = &[
    "MEDIATE-ARMED",
    "mediate: benign=ALLOW",
    "mediate: benign-secret=outbound-present", // secret is in the EGRESS_MMIO record
    "mediate: benign-secret=response-absent",  // ...and nowhere in U-visible memory
    "mediate: attack=DENY_ARG",
    "mediate: attack-sink=not-driven",
    "mediate: flow=DENY_FLOW",
    "mediate: flow-sink=not-driven",
    "MEDIATE-DONE",
];

/// UART lines the Verilated `endpoint` scenario (Phase-3 W2) must observe. The
/// Endpoint (U-mode courier) deframes the seeded SERIAL_IN stream; M mediates only
/// what is relayed. Frames: 0 valid benign, 1 bad CRC, 2 garbage inner, 3 attack,
/// 4 COBS-invalid, 5 truncated.
const SIM_ENDPOINT_EXPECTED_LINES: &[&str] = &[
    "ENDPOINT-ARMED",
    "endpoint: frame0=ALLOW",            // (a) valid framed benign -> relayed -> ALLOW (parity)
    "endpoint: frame1=DROPPED reason=CRC", // (b) CRC-corrupt -> dropped, never mediated
    "endpoint: frame2=DENY_MALFORMED",   // (c) no authority: bad inner request still denied
    "endpoint: frame3=DENY_ARG",         // (c) ...wrong-host attack frame still denied
    "endpoint: frame4=DROPPED reason=COBS",
    "endpoint: frame5=DROPPED reason=COBS", // truncated tail (delimiter lost)
    "endpoint: frames=6",
    "endpoint: relayed=3",
    "endpoint: dropped=3",               // dropped-frame counter
    "endpoint: sink-calls=1",            // only the benign frame drove the sink
    "endpoint: secret=absent",
    "ENDPOINT-DONE",
];

/// Frames that must be dropped: ANY other `endpoint: frame<i>=` line for them
/// (a verdict) would mean M mediated a corrupt frame.
const SIM_ENDPOINT_DROPPED_FRAMES: &[u32] = &[1, 4, 5];

const SIM_ENDPOINT_FORBIDDEN_LINES: &[&str] = &[
    "ENDPOINT-FAIL",
    "UNEXPECTED-RELAY",
    "RELAY-MISMATCH",
    "secret=LEAK",
    "M-FAULT",
    "PMP-FAIL",
];

/// Any of these means containment (or the harness) failed — fail closed.
const SIM_MEDIATE_FORBIDDEN_LINES: &[&str] = &[
    "MEDIATE-FAIL",
    "outbound-MISSING",
    "response-LEAK",
    "sink=DRIVEN",
    "M-FAULT",
    "PMP-FAIL",
];

fn verilator(scenario: Option<&str>) -> anyhow::Result<()> {
    let (pmp, mediate, endpoint) = match scenario {
        Some("boot") => (false, false, false),
        Some("pmp") => (true, false, false),
        Some("mediate") => (false, true, false),
        Some("endpoint") => (false, false, true),
        None => anyhow::bail!("usage: cargo xtask verilator -- <boot|pmp|measure|mediate|endpoint>"),
        Some(other) => anyhow::bail!(
            "unknown verilator scenario: {other} (expected `boot`, `pmp`, `measure`, `mediate` or `endpoint`)"
        ),
    };

    let p = SimPaths::new();

    // Preflight: the locally-provisioned toolchain must be present.
    anyhow::ensure!(p.venv_python().is_file(),
        "missing LiteX venv Python at {} — see sim/README.md", p.venv_python().display());
    anyhow::ensure!(p.verilator_root().is_dir(),
        "missing Verilator at {} — see sim/README.md", p.verilator_root().display());
    anyhow::ensure!(p.simdeps_lib().is_dir(),
        "missing arm64 json-c/libevent at {} — build them per sim/README.md", p.simdeps_lib().display());

    // --- Step 1: build the SIM monitor image (rv32ima, compressed-free). ---
    // nightly + build-std/core for the tier-3 riscv32ima target; link-sim.ld
    // via per-image rustflags (ruling P2-1); its own target dir so the QEMU
    // (imac) artifact is never touched.
    // (Ruling P2-3: nightly pinned inside `nightly_build` so the compressed-free
    // guarantee — stable ignores `-C target-feature=-c`; the `secure` core has no
    // C decoder — can't drift.) The `mediate` image is built `--release` in its
    // own target dir: the debug `monitor::mediate` pipeline + BLAKE2 is ~220 KiB,
    // far past the 128 KiB mon_ram; release fits with ample headroom.
    println!("cargo xtask verilator: building sim monitor image (riscv32ima, build-std)...");
    // The endpoint image links wire into a 4 KiB U window (its own script).
    let link_script = if endpoint {
        p.repo.join("crates/monitor-bin/link-sim-endpoint.ld")
    } else {
        p.link_script()
    };
    let (sim_elf, sim_features, sim_release, sim_dir) = if endpoint {
        let dir = p.repo.join("target/sim-endpoint");
        (dir.join("riscv32ima-unknown-none-elf/release/monitor-bin"), "endpoint", true, dir)
    } else if mediate {
        let dir = p.repo.join("target/sim-mediate");
        (dir.join("riscv32ima-unknown-none-elf/release/monitor-bin"), "mediate", true, dir)
    } else {
        (p.sim_elf(), "sim", false, p.sim_target_dir())
    };
    nightly_build(&p, "monitor-bin", &link_script, Some(sim_features), sim_release, &sim_dir, None)?;
    anyhow::ensure!(sim_elf.is_file(),
        "expected sim ELF at {} after build", sim_elf.display());

    // --- Step 2 + 3: emit memory_map.json + generate the SoC Verilog. ------
    println!("cargo xtask verilator: emitting memory_map.json + generating SoC...");
    let gen = Command::new(p.venv_python())
        .current_dir(&p.repo)
        .args([
            p.generator().to_str().unwrap(),
            "--emit-memory-map", p.memory_map().to_str().unwrap(),
            "--generate",
            "--image", sim_elf.to_str().unwrap(),
            "--output-dir", p.build_dir().to_str().unwrap(),
        ])
        .status()
        .context("failed to run redoubt_soc.py (LiteX generate)")?;
    anyhow::ensure!(gen.success(), "redoubt_soc.py generate failed");

    // --- Step 4: Verilate + compile the model (native). -------------------
    // build_sim.sh runs verilator + the C++ compile. It must run natively (not
    // under the x86_64 Rosetta Python) and link the arm64 json-c/libevent from
    // sim/simdeps (CFLAGS/LDFLAGS), with the Verilator env set.
    println!("cargo xtask verilator: verilating (this takes minutes)...");
    let compile = Command::new("bash")
        .current_dir(p.gateware_dir())
        .arg("build_sim.sh")
        .env("VERILATOR_ROOT", p.verilator_root())
        .env("PATH", path_with_oss(&p))
        .env("CFLAGS", format!("-I{}", p.simdeps_include().display()))
        .env("LDFLAGS", format!("-L{}", p.simdeps_lib().display()))
        .status()
        .context("failed to run build_sim.sh (verilate)")?;
    anyhow::ensure!(compile.success(), "verilate/compile failed");
    anyhow::ensure!(p.vsim().is_file(),
        "expected Verilated model at {} after verilate", p.vsim().display());

    // --- Step 5: run Vsim, stream the UART, assert the banner. ------------
    println!("cargo xtask verilator: running the Verilated SoC...");
    let mut child = Command::new(p.vsim())
        .current_dir(p.gateware_dir())
        .env("VERILATOR_ROOT", p.verilator_root())
        .env("PATH", path_with_oss(&p))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn the Verilated Vsim")?;

    // Reader threads accumulate stdout/stderr; the sim never self-terminates,
    // so we poll the captured UART for the banner and kill on success/timeout.
    let stdout_buf = Arc::new(Mutex::new(String::new()));
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let sb = Arc::clone(&stdout_buf);
    let stdout_reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match stdout_pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut s) = sb.lock() {
                        s.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
            }
        }
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    // Wait for the scenario's terminal sentinel (boot: the banner; pmp: the
    // prober's final `PMP-DONE`), then kill. The sim never self-terminates.
    let done_marker = if endpoint {
        "ENDPOINT-DONE"
    } else if mediate {
        "MEDIATE-DONE"
    } else if pmp {
        "PMP-DONE"
    } else {
        BOOT_BANNER
    };
    let deadline = Instant::now() + VERILATOR_RUN_TIMEOUT;
    let mut saw_done = false;
    loop {
        // The mediate scenario also stops on its fail-closed terminal line.
        if stdout_buf
            .lock()
            .map(|s| s.contains(done_marker) || (mediate && s.contains("MEDIATE-FAIL"))
                    || (endpoint && s.contains("ENDPOINT-FAIL")))
            .unwrap_or(false)
        {
            saw_done = true;
            break;
        }
        // If the sim exited on its own without the sentinel, stop waiting.
        if child.try_wait().context("failed to poll Vsim")?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_reader.join();
    let stderr = stderr_reader.join().unwrap_or_default();
    let stdout = stdout_buf.lock().map(|s| s.clone()).unwrap_or_default();
    print!("{stdout}");
    if !saw_done {
        eprint!("{stderr}");
    }

    // Every scenario requires the boot banner first.
    anyhow::ensure!(
        stdout.contains(BOOT_BANNER),
        "Verilated SoC did not print the boot banner {BOOT_BANNER:?} within {:?}",
        VERILATOR_RUN_TIMEOUT
    );

    if endpoint {
        for bad in SIM_ENDPOINT_FORBIDDEN_LINES {
            anyhow::ensure!(
                !stdout.contains(bad),
                "endpoint: observed failure marker {bad:?} (fail closed).\nUART:\n{stdout}"
            );
        }
        anyhow::ensure!(
            saw_done,
            "endpoint: monitor did not reach `ENDPOINT-DONE` within {:?}; UART so far:\n{stdout}",
            VERILATOR_RUN_TIMEOUT
        );
        for line in SIM_ENDPOINT_EXPECTED_LINES {
            anyhow::ensure!(
                stdout.lines().any(|l| l == *line),
                "endpoint: missing expected UART line {line:?}.\nUART:\n{stdout}"
            );
        }
        // A dropped frame must have NO verdict line: its only line is DROPPED.
        for i in SIM_ENDPOINT_DROPPED_FRAMES {
            let prefix = format!("endpoint: frame{i}=");
            for l in stdout.lines().filter(|l| l.starts_with(&prefix)) {
                anyhow::ensure!(
                    l.starts_with(&format!("{prefix}DROPPED")),
                    "endpoint: corrupt frame {i} was mediated: {l:?}.\nUART:\n{stdout}"
                );
            }
        }
        println!(
            "\ncargo xtask verilator -- endpoint: PASS (U-mode Endpoint deframes SERIAL_IN on RTL: \
             valid benign frame -> ALLOW; CRC-corrupt / COBS-invalid / truncated frames dropped \
             (dropped=3) and never mediated; garbage inner -> DENY_MALFORMED and wrong-host \
             attack -> DENY_ARG — the Endpoint holds no authority; all {} lines observed)",
            SIM_ENDPOINT_EXPECTED_LINES.len()
        );
        return Ok(());
    }

    if mediate {
        for bad in SIM_MEDIATE_FORBIDDEN_LINES {
            anyhow::ensure!(
                !stdout.contains(bad),
                "mediate: observed failure marker {bad:?} — containment did not hold \
                 (fail closed).\nUART:\n{stdout}"
            );
        }
        anyhow::ensure!(
            saw_done,
            "mediate: monitor did not reach `MEDIATE-DONE` within {:?} — the U \
             compartment / mediate path stalled; UART so far:\n{stdout}",
            VERILATOR_RUN_TIMEOUT
        );
        for line in SIM_MEDIATE_EXPECTED_LINES {
            anyhow::ensure!(
                stdout.contains(line),
                "mediate: missing expected UART line {line:?}.\nUART:\n{stdout}"
            );
        }
        println!(
            "\ncargo xtask verilator -- mediate: PASS (U-compartment -> M `mediate` on RTL: \
             benign=ALLOW with the secret in the EGRESS_MMIO record and absent from U-visible \
             memory; wrong-host=DENY_ARG and secret-to-public=DENY_FLOW never drove the sink — \
             all {} lines observed)",
            SIM_MEDIATE_EXPECTED_LINES.len()
        );
        return Ok(());
    }

    if !pmp {
        anyhow::ensure!(
            saw_done,
            "Verilated SoC did not print the boot banner {BOOT_BANNER:?} within {:?}",
            VERILATOR_RUN_TIMEOUT
        );
        println!(
            "\ncargo xtask verilator -- boot: PASS (monitor booted on Verilated \
             VexRiscv-secure SoC; banner {BOOT_BANNER:?} observed on the sim UART)"
        );
        return Ok(());
    }

    // --- pmp scenario assertions (fail closed) ---------------------------
    anyhow::ensure!(
        saw_done,
        "pmp: monitor did not reach `PMP-DONE` within {:?} — the prober or a \
         PMP fault path stalled; UART so far:\n{stdout}",
        VERILATOR_RUN_TIMEOUT
    );
    for bad in PMP_FORBIDDEN_LINES {
        anyhow::ensure!(
            !stdout.contains(bad),
            "pmp: observed failure marker {bad:?} — a PMP wall did not hold as \
             expected (fail closed).\nUART:\n{stdout}"
        );
    }
    for line in PMP_EXPECTED_LINES {
        anyhow::ensure!(
            stdout.contains(line),
            "pmp: missing expected UART line {line:?} — the corresponding PMP \
             assertion did not hold.\nUART:\n{stdout}"
        );
    }
    println!(
        "\ncargo xtask verilator -- pmp: PASS (PMP locked + immutable; every \
         forbidden U-mode access faulted, own region worked, undescribed gap + \
         boundary denied — all {} lines observed)",
        PMP_EXPECTED_LINES.len()
    );
    Ok(())
}

// ===========================================================================
// Phase-2 V3: measured boot (BLAKE2s) + M-stack guard.
//
// `cargo xtask verilator -- measure` proves three things, fail-closed, on the
// Verilated SoC whose reset vector is the BROM at 0x0:
//
//   good boot       reset -> BROM -> measure MON_CODE -> match -> jump; the
//                   monitor banner appears.
//   --tamper        one MON_CODE byte is flipped AFTER hashing, so the loaded
//                   image != H_EXPECTED; the BROM prints BROM-TAMPER-HALT and
//                   the monitor banner NEVER appears (nothing past the BROM runs).
//   --stack-overflow a monitor built to overflow its M stack hits the LOCKED
//                   no-access guard page; the handler sees MPP==M and HALTs with
//                   an M-FAULT line (never resuming M past its own fault).
//
// To keep it to ONE (slow) Verilate: the SoC structure (regions, reset=0x0) is
// identical across the three sub-tests, so we Verilate once with the good images
// and, for the other two, rewrite only the $readmemh .init files (which Vsim
// re-reads at startup) via `redoubt_soc.py --emit-init`.
// ===========================================================================

/// Run one nightly `build-std` image (the sim monitor or the BROM) with a given
/// linker script, feature set, and (for the BROM) baked `H_EXPECTED` file.
#[allow(clippy::too_many_arguments)]
fn nightly_build(
    p: &SimPaths,
    package: &str,
    link_script: &Path,
    features: Option<&str>,
    release: bool,
    target_dir: &Path,
    h_expected: Option<&Path>,
) -> anyhow::Result<()> {
    let rustflags = format!("-C link-arg=-T{}", link_script.display());
    let mut args: Vec<String> = vec![
        "run".into(),
        "nightly-2026-09-26".into(),
        "cargo".into(),
        "build".into(),
        "-p".into(),
        package.into(),
    ];
    if let Some(f) = features {
        args.push("--features".into());
        args.push(f.into());
    }
    if release {
        args.push("--release".into());
    }
    args.extend([
        "--target".into(),
        "riscv32ima-unknown-none-elf".into(),
        "-Z".into(),
        "build-std=core".into(),
    ]);

    let mut cmd = Command::new("rustup");
    cmd.current_dir(&p.repo)
        .args(&args)
        .env("RUSTFLAGS", &rustflags)
        .env("CARGO_TARGET_DIR", target_dir);
    if let Some(h) = h_expected {
        cmd.env("REDOUBT_H_EXPECTED", h);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn nightly build for {package}"))?;
    anyhow::ensure!(status.success(), "nightly build of {package} failed");
    Ok(())
}

/// Run `redoubt_soc.py` with the given args (venv Python, from repo root).
fn run_soc_py(p: &SimPaths, args: &[&str]) -> anyhow::Result<()> {
    let mut full = vec![p.generator().to_str().unwrap().to_string()];
    full.extend(args.iter().map(|s| s.to_string()));
    let status = Command::new(p.venv_python())
        .current_dir(&p.repo)
        .args(&full)
        .status()
        .context("failed to run redoubt_soc.py")?;
    anyhow::ensure!(status.success(), "redoubt_soc.py {args:?} failed");
    Ok(())
}

/// Run the (already-Verilated) Vsim, stream its UART, and return the captured
/// stdout once any of `markers` is seen, the sim exits, or the timeout elapses.
/// The bool is whether a marker was observed.
fn run_vsim(p: &SimPaths, markers: &[&str]) -> anyhow::Result<(String, bool)> {
    let mut child = Command::new(p.vsim())
        .current_dir(p.gateware_dir())
        .env("VERILATOR_ROOT", p.verilator_root())
        .env("PATH", path_with_oss(p))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn the Verilated Vsim")?;

    let stdout_buf = Arc::new(Mutex::new(String::new()));
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let sb = Arc::clone(&stdout_buf);
    let stdout_reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match stdout_pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut s) = sb.lock() {
                        s.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
            }
        }
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + VERILATOR_RUN_TIMEOUT;
    let mut saw = false;
    loop {
        if stdout_buf
            .lock()
            .map(|s| markers.iter().any(|m| s.contains(m)))
            .unwrap_or(false)
        {
            saw = true;
            break;
        }
        if child.try_wait().context("failed to poll Vsim")?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    let stdout = stdout_buf.lock().map(|s| s.clone()).unwrap_or_default();
    Ok((stdout, saw))
}

fn verilator_measure() -> anyhow::Result<()> {
    let p = SimPaths::new();

    // Preflight: the locally-provisioned toolchain must be present.
    anyhow::ensure!(
        p.venv_python().is_file(),
        "missing LiteX venv Python at {} — see sim/README.md",
        p.venv_python().display()
    );
    anyhow::ensure!(
        p.verilator_root().is_dir(),
        "missing Verilator at {} — see sim/README.md",
        p.verilator_root().display()
    );
    anyhow::ensure!(
        p.simdeps_lib().is_dir(),
        "missing arm64 json-c/libevent at {} — see sim/README.md",
        p.simdeps_lib().display()
    );

    let sim_link = p.link_script();
    let brom_link = p.brom_link_script();

    // Per-scenario artifact locations (separate target dirs so the good and
    // stack-overflow images + their BROMs never clobber each other).
    let mon_good_dir = p.repo.join("target/sim");
    let mon_sf_dir = p.repo.join("target/sim-stackflow");
    let brom_good_dir = p.repo.join("target/brom-good");
    let brom_sf_dir = p.repo.join("target/brom-stackflow");
    let mon_good = mon_good_dir.join("riscv32ima-unknown-none-elf/debug/monitor-bin");
    let mon_sf = mon_sf_dir.join("riscv32ima-unknown-none-elf/debug/monitor-bin");
    let brom_good = brom_good_dir.join("riscv32ima-unknown-none-elf/release/brom");
    let brom_sf = brom_sf_dir.join("riscv32ima-unknown-none-elf/release/brom");
    let h_dir = p.repo.join("sim/h");
    std::fs::create_dir_all(&h_dir).ok();
    let h_good = h_dir.join("h_good.bin");
    let h_sf = h_dir.join("h_stackflow.bin");

    // --- Build order (matters): monitor images FIRST, then hash, then BROMs. --
    println!("measure: building the good + stack-overflow sim monitor images...");
    nightly_build(&p, "monitor-bin", &sim_link, Some("sim"), false, &mon_good_dir, None)?;
    nightly_build(&p, "monitor-bin", &sim_link, Some("stackflow"), false, &mon_sf_dir, None)?;
    anyhow::ensure!(mon_good.is_file(), "missing good sim image {}", mon_good.display());
    anyhow::ensure!(mon_sf.is_file(), "missing stackflow sim image {}", mon_sf.display());

    println!("measure: hashing MON_CODE (BLAKE2s-256) -> H_EXPECTED for each image...");
    run_soc_py(&p, &["--emit-h-expected", h_good.to_str().unwrap(),
                     "--image", mon_good.to_str().unwrap()])?;
    run_soc_py(&p, &["--emit-h-expected", h_sf.to_str().unwrap(),
                     "--image", mon_sf.to_str().unwrap()])?;

    println!("measure: building the BROM against each baked H_EXPECTED...");
    nightly_build(&p, "brom", &brom_link, None, true, &brom_good_dir, Some(&h_good))?;
    nightly_build(&p, "brom", &brom_link, None, true, &brom_sf_dir, Some(&h_sf))?;
    anyhow::ensure!(brom_good.is_file(), "missing good BROM {}", brom_good.display());
    anyhow::ensure!(brom_sf.is_file(), "missing stackflow BROM {}", brom_sf.display());

    // --- Generate the SoC (reset=0x0, BROM baked) + Verilate ONCE. -----------
    println!("measure: emitting memory map (reset=0x0) + generating SoC...");
    run_soc_py(&p, &["--emit-memory-map", p.memory_map().to_str().unwrap(),
                     "--reset-address", "0"])?;
    run_soc_py(&p, &["--generate",
                     "--image", mon_good.to_str().unwrap(),
                     "--brom-image", brom_good.to_str().unwrap(),
                     "--reset-address", "0",
                     "--output-dir", p.build_dir().to_str().unwrap()])?;

    println!("measure: verilating (once; this takes minutes)...");
    let compile = Command::new("bash")
        .current_dir(p.gateware_dir())
        .arg("build_sim.sh")
        .env("VERILATOR_ROOT", p.verilator_root())
        .env("PATH", path_with_oss(&p))
        .env("CFLAGS", format!("-I{}", p.simdeps_include().display()))
        .env("LDFLAGS", format!("-L{}", p.simdeps_lib().display()))
        .status()
        .context("failed to run build_sim.sh (verilate)")?;
    anyhow::ensure!(compile.success(), "verilate/compile failed");
    anyhow::ensure!(p.vsim().is_file(), "expected Vsim at {}", p.vsim().display());

    let build = p.build_dir();
    let build_s = build.to_str().unwrap();

    // --- Sub-test 1: good boot (init already = mon_good + brom_good). ---------
    println!("\nmeasure[1/3] good boot: reset -> BROM -> measure -> jump...");
    let (out1, saw1) = run_vsim(&p, &[BOOT_BANNER])?;
    print!("{out1}");
    anyhow::ensure!(saw1 && out1.contains(BOOT_BANNER),
        "measure good: monitor banner {BOOT_BANNER:?} never appeared (BROM did not jump)\nUART:\n{out1}");
    anyhow::ensure!(out1.contains("BROM-MEASURE-OK"),
        "measure good: BROM did not report a successful measurement\nUART:\n{out1}");
    anyhow::ensure!(!out1.contains("BROM-TAMPER-HALT"),
        "measure good: BROM wrongly reported tamper on a good image\nUART:\n{out1}");
    anyhow::ensure!(!out1.contains("M-FAULT"),
        "measure good: unexpected M-mode self-fault on a good image\nUART:\n{out1}");
    println!("measure[1/3] good boot: PASS (BROM-MEASURE-OK + banner)");

    // --- Sub-test 2: tamper -> BROM halts before the monitor. ----------------
    // Flip a byte at 0x9000 — in the `.text` tail that the OLD fixed-0x8000
    // measurement did NOT cover. That this now halts proves the measurement
    // spans the full executed image (the round-1 review finding).
    println!("\nmeasure[2/3] tamper: flip one .text byte at 0x9000 (past the old 0x8000)...");
    run_soc_py(&p, &["--emit-init",
                     "--image", mon_good.to_str().unwrap(),
                     "--brom-image", brom_good.to_str().unwrap(),
                     "--tamper-offset", "0x9000",
                     "--output-dir", build_s])?;
    let (out2, saw2) = run_vsim(&p, &["BROM-TAMPER-HALT"])?;
    print!("{out2}");
    anyhow::ensure!(saw2 && out2.contains("BROM-TAMPER-HALT"),
        "measure tamper: BROM did not print its tamper-halt line\nUART:\n{out2}");
    anyhow::ensure!(!out2.contains(BOOT_BANNER),
        "measure tamper: the monitor banner appeared — the BROM failed OPEN past a tampered image\nUART:\n{out2}");
    anyhow::ensure!(!out2.contains("BROM-MEASURE-OK"),
        "measure tamper: BROM reported a good measurement on a tampered image\nUART:\n{out2}");
    println!("measure[2/3] tamper: PASS (BROM-TAMPER-HALT, no monitor banner)");

    // --- Sub-test 3: M-stack overflow -> guard fault -> M-FAULT HALT. --------
    println!("\nmeasure[3/3] stack overflow: measured image overflows M stack into the guard...");
    run_soc_py(&p, &["--emit-init",
                     "--image", mon_sf.to_str().unwrap(),
                     "--brom-image", brom_sf.to_str().unwrap(),
                     "--output-dir", build_s])?;
    // Wait for the post-line M-HALT sentinel so the full `M-FAULT ...` line has
    // flushed before we kill (the fault line is the last thing the monitor emits
    // before halting, so without the sentinel a kill can truncate it).
    let (out3, saw3) = run_vsim(&p, &["M-HALT"])?;
    print!("{out3}");
    anyhow::ensure!(out3.contains(BOOT_BANNER),
        "measure stack-overflow: banner absent — BROM did not measure+jump the stackflow image\nUART:\n{out3}");
    anyhow::ensure!(out3.contains("STACK-GUARD-ARMED"),
        "measure stack-overflow: guard was never armed\nUART:\n{out3}");
    anyhow::ensure!(saw3 && out3.contains("M-FAULT mcause=7"),
        "measure stack-overflow: no M-origin store fault (M-FAULT mcause=7) observed\nUART:\n{out3}");
    anyhow::ensure!(out3.contains("addr=0x10018"),
        "measure stack-overflow: the fault did not land in the guard page (0x10018xxx)\nUART:\n{out3}");
    anyhow::ensure!(!out3.contains("PMP-DONE"),
        "measure stack-overflow: control resumed past the M fault (PMP-DONE seen) — fail OPEN\nUART:\n{out3}");
    println!("measure[3/3] stack overflow: PASS (banner + M-FAULT at guard, no resume)");

    println!(
        "\ncargo xtask verilator -- measure: PASS (good boot measured+jumped; \
         tamper halted before the monitor; M-stack overflow self-fault-HALTed at the guard)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::count_significant_lines;

    #[test]
    fn excludes_cfg_test_blocks() {
        let sample = "\
fn real_code() {
    1;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

fn more_real_code() {
    2;
}
";
        // Only the two real functions' lines should count (3 lines each);
        // everything inside the cfg(test) mod tests block must be excluded.
        assert_eq!(
            count_significant_lines(sample),
            6,
            "cfg(test) mod tests block lines should not be counted"
        );
    }
}
