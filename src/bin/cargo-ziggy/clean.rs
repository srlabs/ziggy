use crate::{Clean, Common};
use anyhow::{Error, bail};

impl Clean {
    pub fn clean(&self, common: &Common) -> Result<(), Error> {
        let Ok(target_dir) = common.target_dir() else {
            return Ok(());
        };
        let clean = |target, target_triple: Option<&str>, try_release| -> Result<(), Error> {
            let mut command = common.cargo();
            command
                .args(["clean", "-q"])
                .env("CARGO_TARGET_DIR", target_dir.join(target));
            if !self.args.is_empty() {
                command.args(&self.args);
                if let Some(triple) = target_triple {
                    command.arg(format!("--target={triple}"));
                }
                let already_profile = self.args.iter().any(|arg| {
                    arg.as_encoded_bytes().starts_with(b"--profile") || arg == "--release"
                });
                if try_release && !already_profile {
                    command.arg("--release");
                }
            }
            let status = command.status().expect("Error running cargo clean command");
            if !status.success() {
                bail!("Error cleaning up: Exited with {:?}", status.code());
            }
            Ok(())
        };

        clean("afl", None, false)?;
        // ASan uses --target=host
        clean("afl", Some(target_triple::TARGET), false)?;
        // honggfuzz uses --target=host
        clean("honggfuzz", Some(target_triple::TARGET), true)?;
        // coverage (from ziggy cover)
        clean("coverage", None, false)?;
        // runner (from ziggy run)
        clean("runner", None, false)?;
        Ok(())
    }
}
