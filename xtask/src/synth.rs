//! `cargo xtask synth` — Phase 4 F1: ULX3S (ECP5) synthesis + timing gate.
//!
//! Flow: build the FPGA monitor + BROM images (link-fpga.ld, nightly riscv32ima
//! build-std) -> LiteX elaborates the ULX3S SoC (sim/redoubt_ulx3s.py) -> yosys
//! -> nextpnr-ecp5 -> ecppack. Then parse the nextpnr log, print the
//! utilisation + Fmax-vs-target, and FAIL if any clock misses its target
//! (LiteX runs nextpnr with `--timing-allow-fail`, so the gate is here).
//!
//! Usage: `cargo xtask synth [-- --device 85F|45F]`.

use super::{nightly_build, path_with_oss, run_soc_py, SimPaths};
use anyhow::Context;
use std::process::Command;

/// One `Max frequency for clock` result.
#[derive(Debug, Clone, PartialEq)]
pub struct ClockTiming {
    pub clock: String,
    pub fmax_mhz: f64,
    pub target_mhz: f64,
    pub pass: bool,
}

/// Final (post-route) Fmax result per clock: nextpnr prints the line once after
/// placement and once after routing; the LAST occurrence per clock wins.
pub fn parse_timing(log: &str) -> Vec<ClockTiming> {
    let mut out: Vec<ClockTiming> = Vec::new();
    for line in log.lines() {
        let Some(idx) = line.find("Max frequency for clock") else { continue };
        let rest = &line[idx + "Max frequency for clock".len()..];
        // `'name': 61.20 MHz (PASS at 50.00 MHz)`
        let Some(q1) = rest.find('\'') else { continue };
        let Some(q2) = rest[q1 + 1..].find('\'') else { continue };
        let clock = rest[q1 + 1..q1 + 1 + q2].to_string();
        let tail = &rest[q1 + 1 + q2 + 1..];
        let nums: Vec<f64> = tail
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .filter(|s| !s.is_empty() && s.chars().any(|c| c.is_ascii_digit()))
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() < 2 {
            continue;
        }
        let t = ClockTiming {
            clock: clock.clone(),
            fmax_mhz: nums[0],
            target_mhz: nums[1],
            pass: tail.contains("PASS"),
        };
        if let Some(e) = out.iter_mut().find(|e| e.clock == clock) {
            *e = t;
        } else {
            out.push(t);
        }
    }
    out
}

/// The `Device utilisation:` block, as raw `(resource, "used/total pct%")` rows.
pub fn parse_utilisation(log: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    // The block printed after packing/placement; take the LAST one.
    let mut cur: Vec<(String, String)> = Vec::new();
    let mut in_block = false;
    for line in log.lines() {
        if line.contains("Device utilisation:") || line.contains("Device utilization:") {
            in_block = true;
            cur = Vec::new();
            continue;
        }
        if in_block {
            let body = line.trim_start_matches("Info:").trim();
            if let Some((name, val)) = body.split_once(':') {
                if val.contains('/') {
                    cur.push((name.trim().to_string(), val.trim().to_string()));
                    continue;
                }
            }
            in_block = false;
            if !cur.is_empty() {
                rows = std::mem::take(&mut cur);
            }
        }
    }
    if !cur.is_empty() {
        rows = cur;
    }
    rows
}

pub fn synth(args: &[String]) -> anyhow::Result<()> {
    let mut device = "LFE5U-85F".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--device" => {
                let d = it.next().context("--device needs 85F or 45F")?;
                device = match d.as_str() {
                    "85F" | "LFE5U-85F" => "LFE5U-85F".into(),
                    "45F" | "LFE5U-45F" => "LFE5U-45F".into(),
                    o => anyhow::bail!("unknown --device {o} (85F|45F)"),
                };
            }
            o => anyhow::bail!("unknown synth arg {o}"),
        }
    }
    let tag = device.trim_start_matches("LFE5U-").to_string();

    let p = SimPaths::new();
    anyhow::ensure!(p.venv_python().is_file(), "missing LiteX venv at {}", p.venv_python().display());
    for tool in ["yosys", "nextpnr-ecp5", "ecppack"] {
        anyhow::ensure!(p.oss_bin().join(tool).exists(),
            "missing {tool} in {} — see sim/README.md", p.oss_bin().display());
    }

    // --- FPGA monitor + BROM images (link-fpga.ld; same sources as the sim). ---
    let link = p.repo.join("crates/monitor-bin/link-fpga.ld");
    let mon_dir = p.repo.join("target/fpga");
    let brom_dir = p.repo.join("target/fpga-brom");
    let mon = mon_dir.join("riscv32ima-unknown-none-elf/debug/monitor-bin");
    let brom = brom_dir.join("riscv32ima-unknown-none-elf/release/brom");
    let h_dir = p.repo.join("sim/h");
    std::fs::create_dir_all(&h_dir)?;
    let h = h_dir.join("h_fpga.bin");

    println!("cargo xtask synth: building FPGA monitor image (link-fpga.ld)...");
    nightly_build(&p, "monitor-bin", &link, Some("sim"), false, &mon_dir, None)?;
    anyhow::ensure!(mon.is_file(), "missing monitor ELF {}", mon.display());
    run_soc_py(&p, &["--emit-h-expected", h.to_str().unwrap(), "--image", mon.to_str().unwrap()])?;
    println!("cargo xtask synth: building BROM against the baked H_EXPECTED...");
    nightly_build(&p, "brom", &p.brom_link_script(), None, true, &brom_dir, Some(&h))?;
    anyhow::ensure!(brom.is_file(), "missing BROM ELF {}", brom.display());

    // --- LiteX elaborate (Verilog + .lpf + build script, no PnR yet). ---
    let out = p.repo.join(format!("sim/build-ulx3s-{tag}"));
    println!("cargo xtask synth: LiteX elaborating the ULX3S SoC ({device})...");
    let st = Command::new(p.venv_python())
        .current_dir(&p.repo)
        .args([
            p.repo.join("sim/redoubt_ulx3s.py").to_str().unwrap(),
            "--image", mon.to_str().unwrap(),
            "--brom-image", brom.to_str().unwrap(),
            "--output-dir", out.to_str().unwrap(),
            "--device", &device,
        ])
        .status()
        .context("failed to run redoubt_ulx3s.py")?;
    anyhow::ensure!(st.success(), "redoubt_ulx3s.py elaboration failed");

    // --- yosys -> nextpnr-ecp5 -> ecppack (LiteX's generated script). ---
    let gw = out.join("gateware");
    let log = out.join("synth.log");
    let logf = std::fs::File::create(&log)?;
    println!("cargo xtask synth: yosys + nextpnr-ecp5 + ecppack (20-40+ min); log: {}", log.display());
    let st = Command::new("bash")
        .current_dir(&gw)
        .arg("build_radiona_ulx3s.sh")
        .env("PATH", path_with_oss(&p))
        .stdout(logf.try_clone()?)
        .stderr(logf)
        .status()
        .context("failed to run the yosys/nextpnr build script")?;
    anyhow::ensure!(st.success(), "yosys/nextpnr/ecppack failed — see {}", log.display());

    // --- Report + timing gate. ---
    let text = std::fs::read_to_string(&log)?;
    let util = parse_utilisation(&text);
    let timing = parse_timing(&text);
    let mut report = format!("ULX3S synth report ({device})\n\nUtilisation (nextpnr-ecp5):\n");
    for (n, v) in &util {
        report += &format!("  {n:<16} {v}\n");
    }
    report += "\nTiming (Fmax vs target, post-route):\n";
    for t in &timing {
        report += &format!(
            "  {:<24} Fmax {:>7.2} MHz  target {:>6.2} MHz  {}\n",
            t.clock, t.fmax_mhz, t.target_mhz, if t.pass { "PASS" } else { "FAIL" }
        );
    }
    std::fs::write(out.join("report.txt"), &report)?;
    println!("\n{report}");

    let bit = gw.join("radiona_ulx3s.bit");
    anyhow::ensure!(bit.is_file(), "no bitstream at {}", bit.display());
    anyhow::ensure!(!timing.is_empty(), "no nextpnr timing summary found in {}", log.display());
    anyhow::ensure!(timing.iter().all(|t| t.pass && t.fmax_mhz >= t.target_mhz),
        "TIMING NOT MET — see report above / {}", log.display());
    println!("cargo xtask synth: PASS ({device}): bitstream {} ; timing met on every clock", bit.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_last_fmax_per_clock() {
        let log = "Info: Max frequency for clock 'a': 40.00 MHz (FAIL at 50.00 MHz)\n\
                   Info: Max frequency for clock 'a': 55.50 MHz (PASS at 50.00 MHz)\n\
                   Info: Max frequency for clock 'b': 120.1 MHz (PASS at 25.00 MHz)\n";
        let t = parse_timing(log);
        assert_eq!(t.len(), 2);
        assert!(t[0].pass && (t[0].fmax_mhz - 55.5).abs() < 1e-9 && t[0].target_mhz == 50.0);
    }

    #[test]
    fn parses_utilisation_block() {
        let log = "Info: Device utilisation:\nInfo:             TRELLIS_COMB:  9000/83640    10%\n\
                   Info:                    DP16KD:    40/  208    19%\nInfo: Placed 5 cells\n";
        let u = parse_utilisation(log);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].0, "TRELLIS_COMB");
    }
}
