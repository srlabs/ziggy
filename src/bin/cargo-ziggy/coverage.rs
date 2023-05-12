use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

pub fn generate_coverage(
    target: &str,
    corpus: &Path,
    output: &Path,
    source: Option<PathBuf>,
) -> Result<(), anyhow::Error> {
    eprintln!("Generating coverage");

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let coverage_rustflags = env::var("COVERAGE_RUSTFLAGS").unwrap_or_else(|_| String::from("-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));

    // We build the runner with the appropriate flags for coverage
    process::Command::new(cargo)
        .args(["rustc", "--target-dir=target/coverage"])
        .env("RUSTFLAGS", coverage_rustflags)
        .env("RUSTDOCFLAGS", "-Cpanic=abort")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC_BOOTSTRAP", "1") // Trick to avoid forcing user to use rust nightly
        .spawn()?
        .wait()?;

    // We remove the previous coverage files
    if let Ok(gcda_files) = glob("target/coverage/debug/deps/*.gcda") {
        for file in gcda_files.flatten() {
            fs::remove_file(file)?;
        }
    }

    // We run the target against the corpus
    process::Command::new(format!("./target/coverage/debug/{target}"))
        .args([corpus
            .display()
            .to_string()
            .replace("{target_name}", target)])
        .spawn()?
        .wait()?;

    let source_or_workspace_root = match source {
        Some(s) => s.display().to_string(),
        None => {
            let metadata_output = std::process::Command::new("cargo")
                .arg("metadata")
                .output()
                .context("Failed to run cargo metadata")?;

            let stdout =
                String::from_utf8(metadata_output.stdout).context("Failed to read stdout")?;
            let metadata: serde_json::Value =
                serde_json::from_str(&stdout).context("Failed to parse JSON")?;

            metadata["workspace_root"]
                .as_str()
                .context("Failed to get workspace root")?
                .to_string()
        }
    };

    let output_dir = output
        .display()
        .to_string()
        .replace("{target_name}", target);

    // We remove the previous coverage
    if let Err(error) = fs::remove_dir_all(&output_dir) {
        match error.kind() {
            std::io::ErrorKind::NotFound => {}
            e => return Err(anyhow!(e)),
        }
    };

    // We generate the code coverage report
    process::Command::new("grcov")
        .args([
            ".",
            &format!("-b=./target/coverage/debug/{target}"),
            &format!("-s={source_or_workspace_root}"),
            "-t=html",
            "--llvm",
            "--branch",
            "--ignore-not-existing",
            &format!("-o={output_dir}"),
        ])
        .spawn()?
        .wait()?;

    Ok(())
}
