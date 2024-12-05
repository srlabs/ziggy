use crate::{find_target, Build, FuzzingEngines, Minimize};
use anyhow::{anyhow, Context, Result};
use std::{
    env,
    fs::{self, File},
    process, thread,
    time::Duration,
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

        if fs::read_dir(self.output_corpus()).is_ok() {
            return Err(anyhow!("Directory {} exists, please move it before running minimization", self.output_corpus()));
        }

        let entries = fs::read_dir(self.input_corpus())?;
        let original_count = entries.filter_map(|entry| entry.ok()).count();
        println!("Running minimization on a corpus of {original_count} files");

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

        // We rename every file to its md5 hash
        let min_entries = fs::read_dir(self.output_corpus())?;
        for file in min_entries.flatten() {
            let hasher = process::Command::new("md5sum")
                .arg(file.path())
                .output()
                .unwrap();
            let hash_vec = hasher.stdout.split(|&b| b == b' ').next().unwrap_or(&[]);
            let hash = std::str::from_utf8(hash_vec).unwrap_or_default();
            let _ = fs::rename(file.path(), format!("{}/{hash}", self.output_corpus()));
        }

        let min_entries_hashed = fs::read_dir(self.output_corpus())?;
        let minimized_count = min_entries_hashed.filter_map(|entry| entry.ok()).count();
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
