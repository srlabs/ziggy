use crate::{Cover, find_target};
use anyhow::{Context, Result, bail};
use cargo_metadata::camino::Utf8PathBuf;
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process,
};

thread_local! {
    static BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(8 * 1024));
}

impl Cover {
    pub fn generate_coverage(&mut self) -> Result<(), anyhow::Error> {
        process::Command::new("grcov")
            .arg("--version")
            .output()
            .context("grcov not found - please install by running `cargo install grcov`")?;

        eprintln!("Generating coverage");

        self.target =
            find_target(&self.target).context("⚠️  couldn't find the target to start coverage")?;

        if let Some(path) = &self.source
            && !path.try_exists()?
        {
            bail!("Source directory specified, but path does not exist!");
        }

        // build the runner
        Self::build_runner()?;

        if !self.keep {
            // We remove the previous coverage files
            Self::clean_old_cov()?;
        }

        let input_path = PathBuf::from(
            self.input
                .display()
                .to_string()
                .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                .replace("{target_name}", &self.target),
        );

        let coverage_corpus = if input_path.is_dir() {
            fs::read_dir(input_path)
                .unwrap()
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
            .replace("{target_name}", &self.target);

        delete_dir_or_file(&coverage_dir)?;

        // Get the absolute path for the coverage directory to ensure .profraw files
        // are created in the correct location, even in workspace scenarios
        let base_dir = super::target_dir().join("coverage/debug");
        let coverage_target_dir = base_dir.join("deps");
        let cfg = Cfg::new(
            base_dir.join(&self.target),
            coverage_target_dir.join("coverage-%p-%m.profraw"),
        );

        eprintln!("    Generating raw profiles");
        let pb = ProgressBar::new(coverage_corpus.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "    [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        let log_dir = self.ziggy_output.join(format!("{}/logs", &self.target));
        fs::create_dir_all(&log_dir)?;
        let log_file = std::sync::Mutex::new(std::fs::File::create(log_dir.join("coverage.log"))?);
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

        let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
        let workspace_root: String = metadata.workspace_root.into();
        let source_or_workspace_root = self
            .source
            .as_ref()
            .map_or_else(|| workspace_root.clone(), |s| s.display().to_string());

        let output_types = self.output_types.as_ref().map_or("html", String::as_str);

        // We generate the code coverage report
        eprintln!("\n    Generating coverage report");
        Self::run_grcov(
            &self.target,
            output_types,
            &coverage_dir,
            &source_or_workspace_root,
            self.jobs,
        )
    }

    /// Build the runner with the appropriate flags for coverage
    pub fn build_runner() -> Result<(), anyhow::Error> {
        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let mut coverage_rustflags =
            env::var("COVERAGE_RUSTFLAGS").unwrap_or_else(|_| "-Cinstrument-coverage".to_string());
        coverage_rustflags.push(' ');
        coverage_rustflags.push_str(&env::var("RUSTFLAGS").unwrap_or_default());
        let target_dir = format!("--target-dir={}", super::target_dir().join("coverage"));

        let build = process::Command::new(&cargo)
            .args(["rustc", "--features=ziggy/coverage", &target_dir])
            .env("RUSTFLAGS", coverage_rustflags)
            .env(
                "LLVM_PROFILE_FILE",
                super::target_dir().join("coverage/debug/deps/build-%p-%m.profraw"),
            )
            .spawn()
            .context("⚠️  couldn't spawn rustc for coverage")?
            .wait()
            .context("⚠️  couldn't wait for rustc during coverage")?;
        if !build.success() {
            bail!("⚠️  build failed");
        }
        Ok(())
    }

    pub fn run_grcov(
        target: &str,
        output_types: &str,
        coverage_dir: &str,
        source_or_workspace_root: &str,
        threads: Option<usize>,
    ) -> Result<(), anyhow::Error> {
        let coverage = process::Command::new("grcov")
            .args([
                crate::target_dir().join("coverage/debug/deps").as_str(),
                &format!("-b={}/coverage/debug/{target}", super::target_dir()),
                &format!("-s={source_or_workspace_root}"),
                &format!("-t={output_types}"),
                "--llvm",
                "--branch",
                "--ignore-not-existing",
                &format!("-o={coverage_dir}"),
            ])
            .args(threads.map(|threads| format!("--threads={threads}")))
            .spawn()
            .context("⚠️  cannot find grcov in your path, please install it")?
            .wait()
            .context("⚠️  couldn't wait for the grcov process")?;
        if !coverage.success() {
            bail!("⚠️  grcov failed");
        }
        Ok(())
    }

    pub fn clean_old_cov() -> Result<(), anyhow::Error> {
        // Use absolute path to ensure we clean the correct location in workspaces
        let coverage_deps_dir = super::target_dir().join("coverage/debug/deps");
        let pattern = coverage_deps_dir.join("*.profraw");

        if let Ok(profile_files) = glob(pattern.as_str()) {
            for file in profile_files.flatten() {
                let file_string = &file.display();
                fs::remove_file(&file)
                    .with_context(|| format!("⚠️  couldn't remove {file_string}"))?;
            }
        }
        Ok(())
    }
}

fn delete_dir_or_file(path: &str) -> Result<(), anyhow::Error> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // Some of the grcov output types produce folders, others produce files. This can result in errors when trying to delete them.
    if metadata.is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("⚠️  error removing dir {path}"))?;
    } else if metadata.is_file() {
        fs::remove_file(path).with_context(|| format!("⚠️  error removing file {path}"))?;
    } else {
        bail!("coverage output path exists but is neither a file nor a directory: {path}");
    }

    Ok(())
}

struct Cfg {
    runner: Utf8PathBuf,
    prof_file_template: Utf8PathBuf,
}

impl Cfg {
    fn new(runner: Utf8PathBuf, prof_file_template: Utf8PathBuf) -> Self {
        Self {
            runner,
            prof_file_template,
        }
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
            bail!("runner failed with exit code `{status}`");
        }
        Ok(())
    }
}
