use crate::{Common, Cover, Stability, util::Context};
use anyhow::{Context as _, Result, bail};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    process,
};

/// Maps (filename, line_number) to execution count.
type LineCounts = HashMap<(String, u32), u64>;

impl Stability {
    pub fn analyze_stability(&self, common: &Common) -> Result<()> {
        let cx = Context::new(common, self.target.clone())?;

        if self.runs < 2 {
            bail!(
                "Need at least 2 runs to measure stability (got {})",
                self.runs
            );
        }

        // Check that llvm tools are available
        check_tool("llvm-profdata")?;
        check_tool("llvm-cov")?;

        // Build coverage-instrumented binary
        eprintln!("    {} coverage binary", style("Building").red().bold());
        Cover::build_runner(common)?;
        eprintln!("    {} coverage binary", style("Finished").cyan().bold());

        let runner = cx
            .target_dir
            .join(format!("coverage/debug/{}", cx.bin_target));

        // Collect corpus files
        let corpus = collect_corpus(&self.input, &self.ziggy_output, &cx)?;
        if corpus.is_empty() {
            bail!("No corpus files found in {}", self.input.display());
        }
        eprintln!("    Found {} corpus files", corpus.len());

        let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;

        if let Some(threads) = self.jobs {
            rayon::ThreadPoolBuilder::default()
                .num_threads(threads)
                .build_global()
                .expect("Failed to initialize thread pool");
        }

        // Run the corpus N times, collecting LCOV data each time
        let mut run_data: Vec<LineCounts> = Vec::with_capacity(self.runs as usize);

        for run_idx in 0..self.runs {
            eprintln!(
                "    {} ({}/{})",
                style("Running corpus").red().bold(),
                run_idx + 1,
                self.runs
            );

            let run_dir = temp_dir.path().join(format!("run_{run_idx}"));
            fs::create_dir_all(&run_dir)?;
            let profraw_pattern = run_dir.join("cov-%p-%m.profraw");

            // Run all inputs in parallel
            let pb = ProgressBar::new(corpus.len() as u64);
            pb.set_style(
                ProgressStyle::with_template(
                    "    [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
            );

            corpus.par_iter().for_each(|input| {
                let _ = process::Command::new(runner.as_str())
                    .arg(input)
                    .stdin(process::Stdio::null())
                    .stdout(process::Stdio::null())
                    .stderr(process::Stdio::null())
                    .env("LLVM_PROFILE_FILE", &profraw_pattern)
                    .status();
                pb.inc(1);
            });
            pb.finish();

            // Collect profraw files, skipping empty ones (from processes that were
            // killed before the LLVM runtime initialized)
            let profraw_files: Vec<PathBuf> = fs::read_dir(&run_dir)?
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|ext| ext == "profraw")
                        && p.metadata().is_ok_and(|m| m.len() > 0)
                })
                .collect();

            if profraw_files.is_empty() {
                eprintln!(
                    "    {} No coverage data for run {} — all inputs may have crashed",
                    style("!!").yellow().bold(),
                    run_idx + 1
                );
                continue;
            }

            // Merge profraw files into profdata.
            // Use --failure-mode=warn to skip corrupt profiles (from crashing inputs)
            // instead of aborting the entire merge.
            let profdata = run_dir.join("merged.profdata");
            let merge = process::Command::new("llvm-profdata")
                .arg("merge")
                .arg("--sparse")
                .arg("--failure-mode=warn")
                .args(&profraw_files)
                .arg("-o")
                .arg(&profdata)
                .output()
                .context("Failed to run llvm-profdata merge")?;

            if !merge.status.success() {
                eprintln!(
                    "    {} llvm-profdata merge failed for run {}, skipping",
                    style("!!").yellow().bold(),
                    run_idx + 1
                );
                continue;
            }

            // Export as LCOV
            let export = process::Command::new("llvm-cov")
                .arg("export")
                .arg("--format=lcov")
                .arg(format!("--instr-profile={}", profdata.display()))
                .arg(runner.as_str())
                .output()
                .context("Failed to run llvm-cov export")?;

            if !export.status.success() {
                eprintln!(
                    "    {} llvm-cov export failed for run {}, skipping",
                    style("!!").yellow().bold(),
                    run_idx + 1
                );
                continue;
            }

            let lcov =
                String::from_utf8(export.stdout).context("llvm-cov produced invalid UTF-8")?;
            run_data.push(parse_lcov(&lcov));
        }

        if run_data.len() < 2 {
            bail!(
                "Only {} run(s) produced valid coverage data (need at least 2). \
                 Inputs may be crashing the coverage binary.",
                run_data.len()
            );
        }

        // Resolve source filter to an absolute path for matching
        let source_filter = self
            .source
            .as_ref()
            .map(|s| fs::canonicalize(s).unwrap_or_else(|_| s.clone()));

        // Analyze and report
        let successful_runs = run_data.len() as u32;
        let report = analyze_runs(&run_data, source_filter.as_deref());
        let cwd = env::current_dir().ok();
        print_report(
            &report,
            &cx.bin_target,
            corpus.len(),
            successful_runs,
            cwd.as_deref(),
        );

        Ok(())
    }
}

fn check_tool(name: &str) -> Result<()> {
    process::Command::new(name)
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .with_context(|| format!("{name} not found — please install LLVM tools"))?;
    Ok(())
}

fn collect_corpus(input: &Path, ziggy_output: &Path, cx: &Context) -> Result<Vec<PathBuf>> {
    let input_path = PathBuf::from(
        input
            .display()
            .to_string()
            .replace("{ziggy_output}", &ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target),
    );

    if input_path.is_dir() {
        Ok(fs::read_dir(&input_path)
            .with_context(|| format!("Cannot read corpus directory: {}", input_path.display()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect())
    } else if input_path.is_file() {
        Ok(vec![input_path])
    } else {
        bail!("Corpus path does not exist: {}", input_path.display());
    }
}

/// Parse LCOV format, extracting DA (line data) entries.
///
/// LCOV format:
///   SF:/path/to/file
///   DA:line_number,execution_count
///   end_of_record
fn parse_lcov(lcov: &str) -> LineCounts {
    let mut counts = LineCounts::new();
    let mut current_file = String::new();

    for line in lcov.lines() {
        if let Some(file) = line.strip_prefix("SF:") {
            current_file = file.to_string();
        } else if let Some(da) = line.strip_prefix("DA:")
            && let Some((line_str, count_str)) = da.split_once(',')
            && let (Ok(line_num), Ok(count)) = (line_str.parse::<u32>(), count_str.parse::<u64>())
        {
            counts.insert((current_file.clone(), line_num), count);
        }
    }

    counts
}

struct StabilityReport {
    total_lines: usize,
    stable_lines: usize,
    unstable_regions: Vec<UnstableRegion>,
}

struct UnstableRegion {
    file: String,
    line: u32,
    /// true if the line is executed in some runs but not in others
    is_branch_unstable: bool,
}

fn analyze_runs(runs: &[LineCounts], source_filter: Option<&Path>) -> StabilityReport {
    if runs.is_empty() {
        return StabilityReport {
            total_lines: 0,
            stable_lines: 0,
            unstable_regions: vec![],
        };
    }

    // Collect all (file, line) keys that were executed in at least one run
    let all_keys: HashSet<_> = runs.iter().flat_map(|r| r.keys().cloned()).collect();
    let executed_keys: Vec<_> = all_keys
        .into_iter()
        .filter(|key| runs.iter().any(|r| r.get(key).copied().unwrap_or(0) > 0))
        .filter(|key| {
            source_filter
                .map(|filter| Path::new(&key.0).starts_with(filter))
                .unwrap_or(true)
        })
        .collect();

    let mut unstable = Vec::new();
    let mut stable_count = 0;

    for key in &executed_keys {
        let counts: Vec<u64> = runs
            .iter()
            .map(|r| r.get(key).copied().unwrap_or(0))
            .collect();

        if counts.iter().all(|c| *c == counts[0]) {
            stable_count += 1;
        } else {
            let has_zero = counts.contains(&0);
            let has_nonzero = counts.iter().any(|c| *c > 0);
            unstable.push(UnstableRegion {
                file: key.0.clone(),
                line: key.1,
                is_branch_unstable: has_zero && has_nonzero,
            });
        }
    }

    unstable.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

    StabilityReport {
        total_lines: executed_keys.len(),
        stable_lines: stable_count,
        unstable_regions: unstable,
    }
}

struct LineGroup {
    file: String,
    start_line: u32,
    end_line: u32,
}

fn group_consecutive(regions: &[&UnstableRegion]) -> Vec<LineGroup> {
    if regions.is_empty() {
        return vec![];
    }

    let mut groups = Vec::new();
    let mut current = LineGroup {
        file: regions[0].file.clone(),
        start_line: regions[0].line,
        end_line: regions[0].line,
    };

    for region in &regions[1..] {
        if region.file == current.file && region.line <= current.end_line + 1 {
            current.end_line = region.line;
        } else {
            groups.push(current);
            current = LineGroup {
                file: region.file.clone(),
                start_line: region.line,
                end_line: region.line,
            };
        }
    }
    groups.push(current);
    groups
}

/// Make an absolute path relative to `base` when possible, for shorter display.
fn display_path(path: &str, base: Option<&Path>) -> String {
    if let Some(base) = base
        && let Ok(rel) = Path::new(path).strip_prefix(base)
    {
        return rel.display().to_string();
    }
    path.to_string()
}

fn print_report(
    report: &StabilityReport,
    target: &str,
    corpus_size: usize,
    runs: u32,
    cwd: Option<&Path>,
) {
    let stability_pct = if report.total_lines > 0 {
        (report.stable_lines as f64 / report.total_lines as f64) * 100.0
    } else {
        100.0
    };

    eprintln!();
    eprintln!(
        "    {} for {target}",
        style("Stability Report").green().bold()
    );
    eprintln!("    {}", "-".repeat(56));
    eprintln!("    Corpus size : {corpus_size} inputs");
    eprintln!("    Runs        : {runs}");
    eprintln!(
        "    Stability   : {:.1}% ({}/{} executed lines stable)",
        stability_pct, report.stable_lines, report.total_lines
    );

    if report.unstable_regions.is_empty() {
        eprintln!();
        eprintln!(
            "    {} No instability detected.",
            style("OK").green().bold()
        );
        return;
    }

    let (branch_unstable, count_jitter): (Vec<_>, Vec<_>) = report
        .unstable_regions
        .iter()
        .partition(|r| r.is_branch_unstable);

    if !branch_unstable.is_empty() {
        eprintln!();
        eprintln!(
            "    {} Unstable branches ({} lines):",
            style("!!").red().bold(),
            branch_unstable.len()
        );
        eprintln!("       Lines executed in some runs but not others:");
        eprintln!();

        for group in group_consecutive(&branch_unstable) {
            let f = display_path(&group.file, cwd);
            if group.start_line == group.end_line {
                eprintln!("         {f}:{}", group.start_line);
            } else {
                eprintln!("         {f}:{}-{}", group.start_line, group.end_line);
            }
        }
    }

    if !count_jitter.is_empty() {
        eprintln!();
        eprintln!(
            "    {} Variable-count lines ({} lines):",
            style("~~").yellow().bold(),
            count_jitter.len()
        );
        eprintln!("       Lines always executed but with varying hit counts:");
        eprintln!();

        for group in group_consecutive(&count_jitter) {
            let f = display_path(&group.file, cwd);
            if group.start_line == group.end_line {
                eprintln!("         {f}:{}", group.start_line);
            } else {
                eprintln!("         {f}:{}-{}", group.start_line, group.end_line);
            }
        }
    }
}
