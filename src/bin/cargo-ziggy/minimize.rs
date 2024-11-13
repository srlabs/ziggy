use crate::{find_target, Build, FuzzingEngines, Minimize};
use anyhow::{Context, Result};
use std::{
    env,
    fs::{self, File},
    process,
};

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

        let entries = fs::read_dir(self.input_corpus())?;
        let original_count = entries.filter_map(|entry| entry.ok()).count();
        println!("Running minimization on a corpus of {original_count} files");

        match self.engine {
            FuzzingEngines::AFLPlusPlus => {
                self.minimize_afl()?;
            }
            FuzzingEngines::Honggfuzz => {
                self.minimize_honggfuzz()?;
            }
        }

        let min_entries = fs::read_dir(self.output_corpus())?;
        let minimized_count = min_entries.filter_map(|entry| entry.ok()).count();
        println!("Minimized corpus contains {minimized_count} files");

        Ok(())
    }

    fn input_corpus(&self) -> String {
        self.input_corpus
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target)
    }

    fn output_corpus(&self) -> String {
        self.output_corpus
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target)
    }

    // AFL++ minimization
    fn minimize_afl(&self) -> Result<(), anyhow::Error> {
        println!("Minimizing with AFL++");
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
                &self.input_corpus(),
                "-o",
                &self.output_corpus(),
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
        println!("Minimizing with honggfuzz");
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
                format!("-i{} -M -o{}", &self.input_corpus(), &self.output_corpus(),),
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
