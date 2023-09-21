use crate::{find_target, FuzzingEngines, Minimize};
use anyhow::{Context, Result};
use std::{env, fs::File, process};

impl Minimize {
    pub fn minimize(&mut self) -> Result<(), anyhow::Error> {
        self.target =
            find_target(&self.target).context("⚠️  couldn't find target when minimizing")?;

        info!("Minimizing corpus");

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        match self.engine {
            FuzzingEngines::AFLPlusPlus => {
                let jobs_option = match self.jobs {
                    0 | 1 => String::from("all"),
                    t => format!("{t}"),
                };

                // AFL++ minimization
                process::Command::new(cargo)
                    .args([
                        "afl",
                        "cmin",
                        "-i",
                        &self
                            .input_corpus
                            .display()
                            .to_string()
                            .replace("{target_name}", &self.target),
                        "-o",
                        &self
                            .output_corpus
                            .display()
                            .to_string()
                            .replace("{target_name}", &self.target),
                        "-T",
                        &jobs_option,
                        "--",
                        &format!("./target/afl/debug/{}", &self.target),
                    ])
                    .env("AFL_MAP_SIZE", "10000000")
                    .stderr(File::create(format!(
                        "./output/{}/logs/minimization.log",
                        &self.target
                    ))?)
                    .stdout(File::create(format!(
                        "./output/{}/logs/minimization.log",
                        &self.target
                    ))?)
                    .spawn()?
                    .wait()?;
            }
            FuzzingEngines::Honggfuzz => {
                // HONGGFUZZ minimization
                process::Command::new(cargo)
                    .args(["hfuzz", "run", &self.target])
                    .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                    .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                    .env(
                        "HFUZZ_WORKSPACE",
                        format!("./output/{}/honggfuzz", &self.target),
                    )
                    .env(
                        "HFUZZ_RUN_ARGS",
                        format!(
                            "-i{} -M -o{}",
                            self.input_corpus
                                .display()
                                .to_string()
                                .replace("{target_name}", &self.target),
                            self.output_corpus
                                .display()
                                .to_string()
                                .replace("{target_name}", &self.target),
                        ),
                    )
                    .stderr(File::create(format!(
                        "./output/{}/logs/minimization.log",
                        self.target
                    ))?)
                    .stdout(File::create(format!(
                        "./output/{}/logs/minimization.log",
                        &self.target
                    ))?)
                    .spawn()?
                    .wait()?;
            }
        }
        Ok(())
    }
}
