use std::path::Path;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("loc-gate") => loc_gate(),
        Some("qemu") => qemu(),
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
        None => anyhow::bail!("usage: cargo xtask <loc-gate|qemu>"),
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
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn loc_gate() -> anyhow::Result<()> {
    let mon = count_rust_lines("crates/monitor/src").unwrap_or(0); // excludes tests via cfg
    anyhow::ensure!(mon <= 2500, "monitor TCB {mon} > 2500 LoC budget");
    let brom = count_rust_lines("crates/monitor-bin/src/boot.rs").unwrap_or(0);
    anyhow::ensure!(brom <= 300, "boot ROM {brom} > 300 LoC budget");
    println!("loc-gate ok: monitor={mon} brom={brom}");
    Ok(())
}

fn qemu() -> anyhow::Result<()> {
    anyhow::bail!("cargo xtask qemu is implemented in Task 3")
}
