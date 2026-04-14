use crate::{Common, Cover, util::Context, util::Utf8PathBuf};
use anyhow::{Context as _, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    env, fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process,
    str::FromStr,
};

thread_local! {
    static BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(8 * 1024));
}

impl Cover {
    pub fn generate_coverage(&self, common: &Common) -> Result<(), anyhow::Error> {
        let cx = Context::new(common, self.target.clone())?;

        let base_dir = cx.target_dir.join("coverage/debug");
        let coverage_target_dir = base_dir.join("deps");
        let cfg = Cfg::new(
            base_dir.join(&cx.bin_target),
            coverage_target_dir.join("coverage-%p-%m.profraw"),
        )?;

        eprintln!("Generating coverage");

        // build the runner
        Self::build_runner(common).context("instrumenting for coverage")?;

        if !self.keep {
            // We remove the previous coverage files
            Self::clean_old_cov(&cx)?;
        }

        let input_path = PathBuf::from(
            self.input
                .display()
                .to_string()
                .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                .replace("{target_name}", &cx.bin_target),
        );

        let coverage_corpus = if input_path.is_dir() {
            fs::read_dir(input_path)
                .context("opening corpus")?
                .flatten()
                .map(|e| e.path())
                .collect()
        } else {
            vec![input_path]
        };

        if let Some(threads) = self.jobs {
            rayon::ThreadPoolBuilder::default()
                .num_threads(threads)
                .build_global()
                .expect("Failure initializing thread pool");
        }

        let coverage_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target);

        if let Err(e) = fs::remove_dir_all(&coverage_dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(anyhow::Error::from(e))
                .with_context(|| format!("⚠️  couldn't remove {coverage_dir}"));
        }

        eprintln!("    Generating raw profiles");
        let pb = ProgressBar::new(coverage_corpus.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "    [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#--"),
        );
        let log_dir = self.ziggy_output.join(format!("{}/logs", &cx.bin_target));
        fs::create_dir_all(&log_dir).context("output dir for logs")?;
        let log_file = std::sync::Mutex::new(
            std::fs::File::create(log_dir.join("coverage.log")).context("logfile")?,
        );
        coverage_corpus.into_par_iter().for_each(|file| {
            #[expect(clippy::significant_drop_tightening)]
            BUF.with_borrow_mut(|buf| {
                buf.clear();
                let _ = cfg.profile(file.as_path(), buf);
                let mut log_file = log_file.lock().unwrap();
                let _ = log_file.write_all(buf);
                // use `lock_file` mutex to avoid contention on progress bar
                pb.inc(1);
            });
        });
        pb.finish();

        // We generate the code coverage report
        eprintln!("\n    Generating coverage report");

        let out_dir = PathBuf::from(coverage_dir);
        let profdata = out_dir.join("coverage.profraw");
        fs::create_dir_all(&out_dir).context("output dir for coverage")?;
        cfg.merge_profraw(&profdata, self.jobs)
            .context("llvm_profdata: merging profraw files")?;

        let mut fmt = 0_u8;
        let types = {
            for t in &self.output_types {
                match t {
                    ReportType::Html => fmt |= 1 << 0,
                    ReportType::Text => fmt |= 1 << 1,
                    ReportType::Json => fmt |= 1 << 2,
                    ReportType::LCov => fmt |= 1 << 3,
                }
            }
            [
                ReportType::Html,
                ReportType::Text,
                ReportType::Json,
                ReportType::LCov,
            ]
            .into_iter()
            .enumerate()
            .filter_map(|(s, t)| (fmt & (1 << s) != 0).then_some(t))
        };

        for t in types {
            cfg.report_coverage(&profdata, &out_dir, t, self.jobs)
                .with_context(|| format!("llvm_cov report of type `{t}`"))?;
        }

        Ok(())
    }

    /// Build the runner with the appropriate flags for coverage
    pub fn build_runner(common: &Common) -> Result<(), anyhow::Error> {
        let target_dir = common.target_dir()?;

        let mut coverage_rustflags =
            env::var("COVERAGE_RUSTFLAGS").unwrap_or_else(|_| "-Cinstrument-coverage".to_string());
        coverage_rustflags.push(' ');
        coverage_rustflags.push_str(&env::var("RUSTFLAGS").unwrap_or_default());

        let profiles_dir = target_dir.join("coverage/build-coverage-profraw");
        fs::create_dir_all(&profiles_dir)?;

        let build = common
            .cargo()
            .args([
                "rustc",
                "--features=ziggy/coverage",
                &format!("--target-dir={}", target_dir.join("coverage")),
            ])
            .env("RUSTFLAGS", coverage_rustflags)
            .env(
                "LLVM_PROFILE_FILE",
                profiles_dir.join("build-%p-%m.profraw"),
            )
            .spawn()
            .context("⚠️  couldn't spawn rustc for coverage")?
            .wait()
            .context("⚠️  couldn't wait for rustc during coverage")?;
        if !build.success() {
            bail!("⚠️  build failed");
        }

        fs::remove_dir_all(&profiles_dir)
            .with_context(|| format!("⚠️  error removing dir {profiles_dir}"))?;
        Ok(())
    }

    pub fn clean_old_cov(cx: &Context) -> Result<(), anyhow::Error> {
        if let Ok(dir) = fs::read_dir(&cx.target_dir) {
            for entry in dir.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "profraw") {
                    fs::remove_file(&path)
                        .with_context(|| format!("⚠️  couldn't remove {}", path.display()))?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Cfg {
    runner: Utf8PathBuf,
    prof_file_template: Utf8PathBuf,
    llvm_profdata: PathBuf,
    llvm_cov: PathBuf,
}

impl Cfg {
    pub fn new(runner: Utf8PathBuf, prof_file_template: Utf8PathBuf) -> Result<Self> {
        let profdata = env::var_os("LLVM_PROFDATA");
        let cov = env::var_os("LLVM_COV");
        let target_libdir = if profdata.is_none() || cov.is_none() {
            let bytes = std::process::Command::new(
                std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()),
            )
            .arg("--print=target-libdir")
            .output()
            .context("failed running `rustc --print=target-libdir")?
            .stdout;
            PathBuf::from(
                String::from_utf8(bytes).expect("invalid utf8 output from `rustc --print`"),
            )
        } else {
            PathBuf::new()
        };

        let llvm_profdata = if let Some(path) = profdata {
            PathBuf::from(path)
        } else {
            let mut libdir: PathBuf = target_libdir.clone();
            libdir.pop();
            libdir.push("bin");
            libdir.push("llvm-profdata");
            if !libdir.exists() {
                bail!("⚠️  llvm-profdata not found: try `rustup component add llvm-tools`");
            }
            libdir
        };

        let llvm_cov = if let Some(path) = cov {
            PathBuf::from(path)
        } else {
            let mut libdir: PathBuf = target_libdir;
            libdir.pop();
            libdir.push("bin");
            libdir.push("llvm-cov");
            if !libdir.exists() {
                bail!("⚠️  llvm-cov not found: try `rustup component add llvm-tools`");
            }
            libdir
        };

        Ok(Self {
            runner,
            prof_file_template,
            llvm_profdata,
            llvm_cov,
        })
    }

    fn profile(&self, seed: &Path, output: &mut Vec<u8>) -> Result<(), anyhow::Error> {
        // redirect stderr and stdout into buffer (via pipe)
        let (mut rx, tx) = std::io::pipe()?;

        let mut child = process::Command::new(&self.runner)
            .arg(seed)
            .stdin(std::process::Stdio::null())
            .stdout(tx.try_clone()?)
            .stderr(tx)
            .env("LLVM_PROFILE_FILE", &self.prof_file_template)
            .spawn()?;

        rx.read_to_end(output)?;
        let status = child.wait()?;
        if !status.success() {
            bail!("⚠️  runner failed with exit code `{status}`");
        }
        Ok(())
    }

    pub fn merge_profraw(&self, output: &Path, jobs: Option<usize>) -> Result<(), anyhow::Error> {
        let profiles = {
            let mut path = self.prof_file_template.clone();
            path.pop();
            fs::read_dir(path)?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "profraw"))
        };
        let status = std::process::Command::new(&self.llvm_profdata)
            .arg("merge")
            .arg("-sparse")
            .args(profiles)
            .arg("-o")
            .arg(output)
            .args(jobs.map(|n| format!("-j={n}")))
            .status()?;
        if !status.success() {
            bail!("⚠️  llvm-profdata failed with exit code `{status}`");
        }
        Ok(())
    }

    pub fn report_coverage(
        &self,
        merged_profile: &Path,
        output: &Path,
        format: ReportType,
        jobs: Option<usize>,
    ) -> Result<()> {
        use ReportType::{Html, Json, LCov, Text};

        let mut cov_cmd = std::process::Command::new(&self.llvm_cov);
        match format {
            Html => cov_cmd.args(["show", "-format=html"]),
            Text => cov_cmd.args(["show", "-format=text"]),
            Json => cov_cmd.args(["export", "-format=text"]),
            LCov => cov_cmd.args(["export", "-format=lcov"]),
        };
        match format {
            Text | Html => {
                cov_cmd.arg("-output-dir").arg(output).args([
                    "-show-directory-coverage",
                    "-show-line-counts-or-regions",
                    "-show-branches=count",
                ]);
            }
            Json => {
                cov_cmd.stdout(fs::File::create(output.join("coverage.json"))?);
            }
            LCov => {
                cov_cmd.stdout(fs::File::create(output.join("coverage.lcov"))?);
            }
        }
        let status = cov_cmd
            .arg("-instr-profile")
            .arg(merged_profile)
            .arg(&self.runner)
            .args(jobs.map(|n| format!("-j={n}")))
            .status()?;
        if !status.success() {
            bail!("⚠️  llvm-cov failed with exit code `{status}`");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportType {
    Html,
    Text,
    Json,
    LCov,
}

impl FromStr for ReportType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "html" => Self::Html,
            "text" | "txt" => Self::Text,
            "json" => Self::Json,
            "lcov" => Self::LCov,
            _ => anyhow::bail!("help: available types: `html`, `text`, `json`, `lcov`"),
        })
    }
}

impl fmt::Display for ReportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Html => write!(f, "html"),
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::LCov => write!(f, "lcov"),
        }
    }
}
