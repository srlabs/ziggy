use crate::{find_target, Run};
use anyhow::{anyhow, Result, Context};
use console::style;
use std::{env, process};

impl Run {
    // Run inputs
    pub fn run(&self) -> Result<(), anyhow::Error> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let target = find_target(&self.target)?;

        // We build the runner
        eprintln!("    {} runner", style("Building").red().bold());

        // We run the compilation command
        let run = process::Command::new(cargo)
            .args(["rustc", "--target-dir=target/runner"])
            .env("RUSTFLAGS", "")
            .spawn().context(format!("⚠️  couldn't spawn runner compilation"))?
            .wait().context("⚠️  couldn't wait for the runner compilation process")?;

        if !run.success() {
            return Err(anyhow!(
                "Error building runner: Exited with {:?}",
                run.code()
            ));
        }

        eprintln!("    {} runner", style("Finished").cyan().bold());
        info!("Running inputs");
        let run_args: Vec<String> = self
            .inputs
            .iter()
            .map(|x| x.display().to_string().replace("{target_name}", &target))
            .collect();

        process::Command::new(format!("./target/runner/debug/{}", target))
            .args(run_args)
            .env("RUST_BACKTRACE", "full")
            .spawn().context("⚠️  couldn't spawn the runner process")?
            .wait().context("⚠️  couldn't wait for the runner process")?;

        Ok(())
    }
}
