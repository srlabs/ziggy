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
            .replace("{target_name}", &self.target);

        // AFL timeout is in ms so we convert the value
        let timeout_option = match self.timeout {
            Some(t) => format!("-t{}", t * 1000),
            None => String::new(),
        };

        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let mut rng = rand::thread_rng();
        process::Command::new(cargo.clone())
            .args(
                [
                    "afl",
                    "fuzz",
                    "-i",
                    &input,
                    &format!("-ooutput/{}/afl", self.target),
                    "-V1",
                    "-c-",
                    &format!("-Saddseeds{}", rng.gen::<u64>()),
                    &timeout_option,
                    &format!("./target/afl/debug/{}", self.target),
                ]
                .iter()
                .filter(|a| a != &&""),
            )
            .spawn()?
            .wait()?;
        Ok(())
    }
}
