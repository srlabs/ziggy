use crate::Clean;
use anyhow::{bail, Error};
use std::{env, process::Command};

impl Clean {
    pub fn clean(&self) -> Result<(), Error> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let clean = |sub_target: &str, target_triple: Option<&str>| -> Result<(), Error> {
            let status = Command::new(&cargo)
                .arg("clean")
                .arg("-q")
                .args(&self.args)
                .args(target_triple.map(|triple| format!("--target={triple}")))
                .env("CARGO_TARGET_DIR", super::target_dir().join(sub_target))
                .status()
                .expect("Error running cargo clean command");
            if !status.success() {
                bail!("Error cleaning up: Exited with {:?}", status.code());
            }
            Ok(())
        };

        clean("afl", None)?;
        // ASan uses --target=host
        clean("afl", Some(target_triple::TARGET))?;
        // honggfuzz uses --target=host
        clean("honggfuzz", Some(target_triple::TARGET))?;
        // coverage (from ziggy cover)
        clean("coverage", None)?;
        // runner (from ziggy run)
        clean("runner", None)?;
        Ok(())
    }
}
