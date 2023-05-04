use crate::*;
use anyhow::{anyhow, Result};
use console::style;
use std::{env, process};

pub fn run_inputs(args: &Run) -> Result<(), anyhow::Error> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    // We build the runner
    println!("    {} runner", style("Building").red().bold());

    // We run the compilation command
    let run = process::Command::new(cargo)
        .args(["rustc", "--target-dir=target/runner"])
        .env("RUSTFLAGS", "")
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(anyhow!(
            "error building runner: Exited with {:?}",
            run.code()
        ));
    }

    println!("    {} runner", style("Finished").cyan().bold());
    println!("📋  Running inputs");
    let run_args: Vec<String> = args
        .inputs
        .iter()
        .map(|x| {
            x.display()
                .to_string()
                .replace("{target_name}", &args.target)
        })
        .collect();
    //run_args.push("--".to_string());
    //run_args.push("-runs=1 ".to_string());
    //run_args.push(format!("-max_len={}", args.max_length));

    process::Command::new(format!("./target/runner/debug/{}", args.target))
        .args(run_args)
        .env("RUST_BACKTRACE", "full")
        .spawn()?
        .wait()?;

    Ok(())
}
