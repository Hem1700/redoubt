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
            verilator(rest.first().map(String::as_str))
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
        None => anyhow::bail!("usage: cargo xtask <loc-gate|qemu [-- mediate]|verilator -- boot>"),
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
    let brom = count_rust_lines("crates/monitor-bin/src/boot.rs").unwrap_or(0);
    anyhow::ensure!(brom <= 300, "boot ROM {brom} > 300 LoC budget");
    println!("loc-gate ok: monitor={mon} brom={brom}");
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
}

/// PATH with the oss-cad-suite bin (verilator) prepended.
fn path_with_oss(p: &SimPaths) -> String {
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", p.oss_bin().display(), existing)
}

/// Timeout for the Verilated run to reach the banner. The sim runs at 1 MHz
/// and prints the banner within a few simulated ms; 90s covers CI variance.
const VERILATOR_RUN_TIMEOUT: Duration = Duration::from_secs(90);

fn verilator(scenario: Option<&str>) -> anyhow::Result<()> {
    match scenario {
        Some("boot") => {}
        None => anyhow::bail!("usage: cargo xtask verilator -- boot"),
        Some(other) => anyhow::bail!("unknown verilator scenario: {other} (expected `boot`)"),
    }

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
    println!("cargo xtask verilator: building sim monitor image (riscv32ima, build-std)...");
    let rustflags = format!("-C link-arg=-T{}", p.link_script().display());
    let build = Command::new("rustup")
        .current_dir(&p.repo)
        .args([
            "run", "nightly", "cargo", "build",
            "-p", "monitor-bin", "--features", "sim",
            "--target", "riscv32ima-unknown-none-elf",
            "-Z", "build-std=core",
        ])
        .env("RUSTFLAGS", &rustflags)
        .env("CARGO_TARGET_DIR", p.sim_target_dir())
        .status()
        .context("failed to spawn `rustup run nightly cargo build` for the sim image \
                  (is the `nightly` toolchain + `rust-src` installed? see sim/README.md)")?;
    anyhow::ensure!(build.success(), "sim monitor-bin build failed");
    anyhow::ensure!(p.sim_elf().is_file(),
        "expected sim ELF at {} after build", p.sim_elf().display());

    // --- Step 2 + 3: emit memory_map.json + generate the SoC Verilog. ------
    println!("cargo xtask verilator: emitting memory_map.json + generating SoC...");
    let gen = Command::new(p.venv_python())
        .current_dir(&p.repo)
        .args([
            p.generator().to_str().unwrap(),
            "--emit-memory-map", p.memory_map().to_str().unwrap(),
            "--generate",
            "--image", p.sim_elf().to_str().unwrap(),
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

    let deadline = Instant::now() + VERILATOR_RUN_TIMEOUT;
    let mut saw_banner = false;
    loop {
        if stdout_buf.lock().map(|s| s.contains(BOOT_BANNER)).unwrap_or(false) {
            saw_banner = true;
            break;
        }
        // If the sim exited on its own without the banner, stop waiting.
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
    if !saw_banner {
        eprint!("{stderr}");
    }

    anyhow::ensure!(
        saw_banner,
        "Verilated SoC did not print the boot banner {BOOT_BANNER:?} within {:?}",
        VERILATOR_RUN_TIMEOUT
    );
    println!(
        "\ncargo xtask verilator -- boot: PASS (monitor booted on Verilated \
         VexRiscv-secure SoC; banner {BOOT_BANNER:?} observed on the sim UART)"
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
