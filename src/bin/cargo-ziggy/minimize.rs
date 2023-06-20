use anyhow::Result;
use std::{env, fs::File, path::Path, process};

pub fn minimize_corpus(
    target: &str,
    input_corpus: &Path,
    output_corpus: &Path,
    jobs: u32,
) -> Result<(), anyhow::Error> {
    info!("Minimizing corpus");

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let jobs = match jobs {
        0 | 1 => String::from("all"),
        t => format!("{t}"),
    };

    // AFL++ minimization
    process::Command::new(cargo)
        .args([
            "afl",
            "cmin",
            "-i",
            &input_corpus
                .display()
                .to_string()
                .replace("{target_name}", target),
            "-o",
            &output_corpus
                .display()
                .to_string()
                .replace("{target_name}", target),
            "-T",
            &jobs,
            "--",
            &format!("./target/afl/debug/{target}"),
        ])
        .env("AFL_MAP_SIZE", "10000000")
        .stderr(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .stdout(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .spawn()?
        .wait()?;

    /*
    // HONGGFUZZ minimization
    process::Command::new(cargo)
        .args(["hfuzz", "run", target])
        .env("CARGO_TARGET_DIR", "./target/honggfuzz")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_WORKSPACE", format!("./output/{}/honggfuzz", target))
        .env(
            "HFUZZ_RUN_ARGS",
            format!(
                "-i{} -M -o{}",
                input_corpus
                    .display()
                    .to_string()
                    .replace("{target_name}", target),
                output_corpus
                    .display()
                    .to_string()
                    .replace("{target_name}", target),
            ),
        )
        .stderr(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .stdout(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .spawn()?
        .wait()?;
    */

    Ok(())
}
