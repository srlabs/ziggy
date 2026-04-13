use crate::{AddSeeds, Common};
use anyhow::{Context, bail};
use std::{env, process};

impl AddSeeds {
    pub fn add_seeds(&self, common: &Common) -> Result<(), anyhow::Error> {
        eprintln!("Adding seeds to AFL");

        let req = semver::VersionReq::parse(">=0.14.5").unwrap();
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let afl_version = process::Command::new(&cargo)
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
            bail!(
                "Outdated version of cargo-afl, ziggy needs >=0.14.5, please run `cargo install cargo-afl`"
            );
        }

        let target = common.resolve_bin(self.target.clone())?;
        let input = self.input.display().to_string();

        common
            .cargo()
            .args([
                "afl",
                "addseeds",
                "-o",
                &format!("{}/{target}/afl", self.ziggy_output.display()),
                "-i",
                &input,
            ])
            .spawn()?
            .wait()?;
        Ok(())
    }
}
