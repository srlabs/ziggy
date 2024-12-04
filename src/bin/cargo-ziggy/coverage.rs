use crate::{find_target, Cover};
use anyhow::{anyhow, Context, Result};
use glob::glob;
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

        // build the runner
        Cover::build_runner()?;

        if !self.keep {
            // We remove the previous coverage files
            Cover::clean_old_cov()?;
        }

        let mut shared_corpus = PathBuf::new();

        shared_corpus.push(
            self.input
                .display()
                .to_string()
                .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                .replace("{target_name}", &self.target)
                .as_str(),
        );

        let _ = process::Command::new(format!("./target/coverage/debug/{}", &self.target))
            .arg(format!("{}", shared_corpus.display()))
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let source_or_workspace_root = match &self.source {
            Some(s) => s.display().to_string(),
            None => {
                let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
                metadata.workspace_root.into()
            }
        };

        let coverage_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target);

        // We remove the previous coverage
        if let Err(error) = fs::remove_dir_all(&coverage_dir) {
            match error.kind() {
                std::io::ErrorKind::NotFound => {}
                e => return Err(anyhow!(e)),
            }
        };

        let output_types = match &self.output_types {
            Some(o) => o,
            None => "html",
        };

        // We generate the code coverage report
        Cover::run_grcov(
            &self.target,
            output_types,
            &coverage_dir,
            &source_or_workspace_root,
        )
    }

    /// Build the runner with the appropriate flags for coverage
    pub fn build_runner() -> Result<(), anyhow::Error> {
        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let mut coverage_rustflags = env::var("COVERAGE_RUSTFLAGS")
            .unwrap_or_else(|_| String::from("--cfg=coverage -Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));
        coverage_rustflags.push_str(&env::var("RUSTFLAGS").unwrap_or_default());

        let build = process::Command::new(cargo)
            .args([
                "rustc",
                "--target-dir=target/coverage",
                "--features=ziggy/coverage",
            ])
            .env("RUSTFLAGS", coverage_rustflags)
            .env("RUSTDOCFLAGS", "-Cpanic=unwind")
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC_BOOTSTRAP", "1") // Trick to avoid forcing user to use rust nightly
            .spawn()
            .context("⚠️  couldn't spawn rustc for coverage")?
            .wait()
            .context("⚠️  couldn't wait for the rustc during coverage")?;
        if !build.success() {
            return Err(anyhow!("⚠️  build failed"));
        }
        Ok(())
    }

    pub fn run_grcov(
        target: &str,
        output_types: &str,
        coverage_dir: &str,
        source_or_workspace_root: &str,
    ) -> Result<(), anyhow::Error> {
        process::Command::new("grcov")
            .args([
                ".",
                &format!("-b=./target/coverage/debug/{}", target),
                &format!("-s={source_or_workspace_root}"),
                &format!("-t={}", output_types),
                "--llvm",
                "--branch",
                "--ignore-not-existing",
                &format!("-o={coverage_dir}"),
            ])
            .spawn()
            .context("⚠️  cannot find grcov in your path, please install it")?
            .wait()
            .context("⚠️  couldn't wait for the grcov process")?;
        Ok(())
    }

    pub fn clean_old_cov() -> Result<(), anyhow::Error> {
        if let Ok(gcda_files) = glob("target/coverage/debug/deps/*.gcda") {
            for file in gcda_files.flatten() {
                let file_string = &file.display();
                fs::remove_file(&file)
                    .context(format!("⚠️  couldn't find {} during coverage", file_string))?;
            }
        }
        Ok(())
    }
}
