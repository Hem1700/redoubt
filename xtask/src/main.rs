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

fn qemu() -> anyhow::Result<()> {
    anyhow::bail!("cargo xtask qemu is implemented in Task 3")
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
