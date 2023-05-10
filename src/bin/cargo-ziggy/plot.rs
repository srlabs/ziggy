use anyhow::Result;
use std::{env, path::Path, process};

pub fn generate_plot(target: &str, input: &String, output: &Path) -> Result<(), anyhow::Error> {
    eprintln!("Generating plot");

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let fuzzer_data_dir = format!("./output/{target}/afl/{input}/");
    let fuzzer_output_dir = output
        .display()
        .to_string()
        .replace("{target_name}", target);

    // We run the afl-plot command
    process::Command::new(cargo)
        .args(["afl", "plot", &fuzzer_data_dir, &fuzzer_output_dir])
        .spawn()?
        .wait()?;

    Ok(())
}
