use crate::*;
use std::{env, process};

impl AddSeeds {
    pub fn add_seeds(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Adding seeds to AFL");

        let req = semver::VersionReq::parse(">=0.14.5").unwrap();
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let afl_version = process::Command::new(cargo)
            .args(["afl", "--version"])
            .output()
            .context("could not run `cargo afl --version`")?;

        if !std::str::from_utf8(afl_version.stdout.as_slice())
            .unwrap_or_default()
            .split_whitespace()
            .nth(1)
            .context("could not get afl version from stdout")
            .map(semver::Version::parse)
            .context("could not parse cargo-afl version")?
            .map(|v| req.matches(&v))?
        {
            return Err(anyhow!("Outdated version of cargo-afl, ziggy needs >=0.14.5, please run `cargo install cargo-afl`"));
        }

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
                    "-o",
                    &format!("{}/{}/afl", self.ziggy_output.display(), self.target),
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
