use anyhow::Context;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
        None => anyhow::bail!("usage: cargo xtask <loc-gate|qemu [-- mediate]>"),
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
