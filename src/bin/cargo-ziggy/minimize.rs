use crate::{find_target, Build, FuzzingEngines, Minimize};
use anyhow::{Context, Result};
use std::{env, fs::File, process, thread, time::Duration};

impl Minimize {
    pub fn minimize(&mut self) -> Result<(), anyhow::Error> {
        let build = Build {
            no_afl: self.engine == FuzzingEngines::Honggfuzz,
            no_honggfuzz: self.engine == FuzzingEngines::AFLPlusPlus,
            release: false,
            asan: false,
        };
        build.build().context("Failed to build the fuzzers")?;

        self.target =
            find_target(&self.target).context("⚠️  couldn't find target when minimizing")?;

        info!("Minimizing corpus");

        match self.engine {
            FuzzingEngines::All => {
                let min_afl = self.clone();
                let handle_afl = thread::spawn(move || {
                    min_afl.minimize_afl().unwrap();
                });
                thread::sleep(Duration::from_millis(1000));

                let min_honggfuzz = self.clone();
                let handle_honggfuzz = thread::spawn(move || {
                    min_honggfuzz.minimize_honggfuzz().unwrap();
                });

                handle_afl.join().unwrap();
                handle_honggfuzz.join().unwrap();
            }
            FuzzingEngines::AFLPlusPlus => {
                self.minimize_afl()?;
            }
            FuzzingEngines::Honggfuzz => {
                self.minimize_honggfuzz()?;
            }
        }
        Ok(())
    }

    // AFL++ minimization
    fn minimize_afl(&self) -> Result<(), anyhow::Error> {
        info!("Minimizing with AFL++");
        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

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
                    .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                    .replace("{target_name}", &self.target),
                "-o",
                &self
                    .output_corpus
                    .display()
                    .to_string()
                    .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                    .replace("{target_name}", &self.target),
                "-T",
                &jobs_option,
                "--",
                &format!("./target/afl/debug/{}", &self.target),
            ])
            .stderr(File::create(format!(
                "{}/{}/logs/minimization_afl.log",
                &self.ziggy_output.display(),
                &self.target,
            ))?)
            .stdout(File::create(format!(
                "{}/{}/logs/minimization_afl.log",
                &self.ziggy_output.display(),
                &self.target,
            ))?)
            .spawn()?
            .wait()?;
        Ok(())
    }

    // HONGGFUZZ minimization
    fn minimize_honggfuzz(&self) -> Result<(), anyhow::Error> {
        info!("Minimizing with honggfuzz");
        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        process::Command::new(cargo)
            .args(["hfuzz", "run", &self.target])
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .env(
                "HFUZZ_WORKSPACE",
                format!(
                    "{}/{}/honggfuzz",
                    &self.ziggy_output.display(),
                    &self.target
                ),
            )
            .env(
                "HFUZZ_RUN_ARGS",
                format!(
                    "-i{} -M -o{}",
                    self.input_corpus
                        .display()
                        .to_string()
                        .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                        .replace("{target_name}", &self.target),
                    self.output_corpus
                        .display()
                        .to_string()
                        .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                        .replace("{target_name}", &self.target),
                ),
            )
            .stderr(File::create(format!(
                "{}/{}/logs/minimization_honggfuzz.log",
                &self.ziggy_output.display(),
                &self.target,
            ))?)
            .stdout(File::create(format!(
                "{}/{}/logs/minimization_honggfuzz.log",
                &self.ziggy_output.display(),
                &self.target,
            ))?)
            .spawn()?
            .wait()?;
        Ok(())
    }
}
