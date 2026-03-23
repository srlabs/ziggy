use crate::{find_target, Cover};
use anyhow::{bail, Context, Result};
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{env, fs, path::PathBuf, process};

impl Cover {
    pub fn generate_coverage(&mut self) -> Result<(), anyhow::Error> {
        process::Command::new("grcov")
            .arg("--version")
            .output()
            .context("grcov not found - please install by running `cargo install grcov`")?;

        eprintln!("Generating coverage");

        self.target =
            find_target(&self.target).context("⚠️  couldn't find the target to start coverage")?;

        if let Some(path) = &self.source {
            if !path.try_exists()? {
                bail!("Source directory specified, but path does not exist!");
            }
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

        // Get the absolute path for the coverage directory to ensure .profraw files
        // are created in the correct location, even in workspace scenarios
        let base_dir = super::target_dir().join("coverage/debug");
        let coverage_bin = base_dir.join(&self.target);
        let coverage_target_dir = base_dir.join("deps");
        let profile_file = coverage_target_dir.join("coverage-%p-%m.profraw");

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

        eprintln!("    Generating raw profiles");
        let pb = ProgressBar::new(coverage_corpus.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "    [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        coverage_corpus.into_par_iter().for_each(|file| {
            let _ = process::Command::new(&coverage_bin)
                .arg(file)
                .stdout(process::Stdio::null())
                .stderr(process::Stdio::null())
                .env("LLVM_PROFILE_FILE", &profile_file)
                .status()
                .unwrap();
            pb.inc(1);
        });
        pb.finish();

        let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
        let workspace_root: String = metadata.workspace_root.into();
        let source_or_workspace_root = self
            .source
            .as_ref()
            .map_or_else(|| workspace_root.clone(), |s| s.display().to_string());

        let coverage_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target);

        Self::delete_dir_or_file(&coverage_dir)?;

        let output_types = self.output_types.as_ref().map_or("html", String::as_str);

        // We generate the code coverage report
        eprintln!("\n    Generating coverage report");
        Self::run_grcov(
            &self.target,
            output_types,
            &coverage_dir,
            &source_or_workspace_root,
            &workspace_root,
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
            .context("⚠️  couldn't wait for the rustc during coverage")?;
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
        workspace_root: &str,
    ) -> Result<(), anyhow::Error> {
        let coverage = process::Command::new("grcov")
            .args([
                workspace_root,
                &format!("-b={}/coverage/debug/{target}", super::target_dir()),
                &format!("-s={source_or_workspace_root}"),
                &format!("-t={output_types}"),
                "--llvm",
                "--branch",
                "--ignore-not-existing",
                &format!("-o={coverage_dir}"),
            ])
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

    pub fn delete_dir_or_file(path: &str) -> Result<(), anyhow::Error> {
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
}
