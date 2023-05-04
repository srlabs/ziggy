use anyhow::{anyhow, Context, Result};
use console::style;
use std::{env, process};

// This method will build our fuzzers
pub fn build_fuzzers(no_afl: bool, no_honggfuzz: bool) -> Result<(), anyhow::Error> {
    // No fuzzers for you
    if no_afl && no_honggfuzz {
        return Err(anyhow!("⚠️  Pick at least one fuzzer"));
    }

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    println!("📋  Starting build command");

    if !no_afl {
        println!("    {} afl", style("Building").red().bold());

        // Second fuzzer we build: AFL++
        let run = process::Command::new(cargo.clone())
            .args([
                "afl",
                "build",
                "--features=ziggy/afl",
                "--target-dir=target/afl",
            ])
            .env("AFL_QUIET", "1")
            .spawn()?
            .wait()
            .context("⚠️  error spawning afl build command")?;

        if !run.success() {
            return Err(anyhow!(
                "error building afl fuzzer: Exited with {:?}",
                run.code()
            ));
        }

        println!("    {} afl", style("Finished").cyan().bold());
    }

    if !no_honggfuzz {
        println!("    {} honggfuzz", style("Building").red().bold());

        // Third fuzzer we build: Honggfuzz
        let run = process::Command::new(cargo)
            .args(["hfuzz", "build"])
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .stdout(process::Stdio::piped())
            .spawn()?
            .wait()
            .context("⚠️  error spawning hfuzz build command")?;

        if !run.success() {
            return Err(anyhow!(
                "error building honggfuzz fuzzer: Exited with {:?}",
                run.code()
            ));
        }

        println!("    {} honggfuzz", style("Finished").cyan().bold());
    }
    Ok(())
}
