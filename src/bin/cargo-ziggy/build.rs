use crate::Build;
use anyhow::{anyhow, Context, Result};
use console::style;
use std::{env, process};

impl Build {
    /// Build the fuzzers
    pub fn build(&self) -> Result<(), anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        info!("Starting build command");

        if !self.no_afl {
            eprintln!("    {} afl", style("Building").red().bold());

            // Second fuzzer we build: AFL++
            let run = process::Command::new(cargo.clone())
                .args(["afl", "build", "--features=ziggy/afl"])
                .env("AFL_QUIET", "1")
                .spawn()?
                .wait()
                .context("Error spawning afl build command")?;

            if !run.success() {
                return Err(anyhow!(
                    "Error building afl fuzzer: Exited with {:?}",
                    run.code()
                ));
            }

            eprintln!("    {} afl", style("Finished").cyan().bold());
        }

        if !self.no_honggfuzz {
            eprintln!("    {} honggfuzz", style("Building").red().bold());

            use cargo_metadata::MetadataCommand;

            let metadata = MetadataCommand::new()
                .manifest_path("./Cargo.toml")
                .exec()
                .context("Error while running cargo metadata command")?;

            let target_directory =
                pathdiff::diff_paths(metadata.target_directory, env::current_dir()?)
                    .ok_or(anyhow!("could not compute relative target directory"))?;

            // Third fuzzer we build: Honggfuzz
            let run = process::Command::new(cargo)
                .args(["hfuzz", "build"])
                .env("CARGO_TARGET_DIR", target_directory)
                .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                .stdout(process::Stdio::piped())
                .spawn()?
                .wait()
                .context("Error spawning hfuzz build command")?;

            if !run.success() {
                return Err(anyhow!(
                    "Error building honggfuzz fuzzer: Exited with {:?}",
                    run.code()
                ));
            }

            eprintln!("    {} honggfuzz", style("Finished").cyan().bold());
        }
        Ok(())
    }
}
