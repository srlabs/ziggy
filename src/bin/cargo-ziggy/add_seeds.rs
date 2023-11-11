use crate::*;
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
        process::Command::new(cargo.clone())
            .args(
                [
                    "afl",
                    "addseeds",
                    &format!("-o{}/{}/afl", self.ziggy_output.display(), self.target),
                    "-i",
                    &input,
                ]
                .iter()
                .filter(|a| a != &&""),
            )
            .spawn()?
            .wait()?;
        Ok(())
    }
}
