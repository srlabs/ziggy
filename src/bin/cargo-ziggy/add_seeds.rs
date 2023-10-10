use crate::*;
use rand::Rng;
use std::{env, process};

impl AddSeeds {
    pub fn add_seeds(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Adding seeds to AFL");

        self.target = find_target(&self.target)?;

        let input = self
            .input
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target);

        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let mut rng = rand::thread_rng();
        process::Command::new(cargo.clone())
            .args(
                [
                    "afl",
                    "fuzz",
                    "-i",
                    &input,
                    &format!("-o{}/{}/afl", self.ziggy_output.display(), self.target),
                    "-V1",
                    "-c-",
                    &format!("-Sadd{:x}", rng.gen::<u64>()),
                    &format!("./target/afl/debug/{}", self.target),
                ]
                .iter()
                .filter(|a| a != &&""),
            )
            .env("AFL_NO_STARTUP_CALIBRATION", "1")
            .env("AFL_IGNORE_SEED_PROBLEMS", "1")
            .env("AFL_NO_UI", "1")
            .env("AFL_BENCH_JUST_ONE", "1")
            .env("AFL_SYNC_TIME", "100")
            .spawn()?
            .wait()?;
        Ok(())
    }
}
