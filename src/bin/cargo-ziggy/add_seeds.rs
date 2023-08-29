use crate::*;
use std::{env, process};

impl AddSeeds {
    pub fn add_seeds(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Adding seeds to AFL");

        self.target = find_target(&self.target)?;

        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        process::Command::new(cargo.clone())
            .args([
                "afl",
                "fuzz",
                "-i",
                self.input
                    .to_str()
                    .ok_or(anyhow!("⚠️  couldn't convert target path to &str"))?,
                &format!("-ooutput/{}/afl", self.target),
                "-V1",
                "-c-",
                &format!("./target/afl/debug/{}", self.target),
            ])
            .spawn()?;
        Ok(())
    }
}
