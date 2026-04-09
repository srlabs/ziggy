use crate::{Clean, Common};
use anyhow::{Error, bail};

impl Clean {
    pub fn clean(&self, common: &Common) -> Result<(), Error> {
        let Ok(target_dir) = common.target_dir() else {
            return Ok(());
        };
        let clean = |target, target_triple: Option<&str>, try_release| -> Result<(), Error> {
            let already_profile = self
                .args
                .iter()
                .any(|arg| arg.as_encoded_bytes().starts_with(b"--profile") || arg == "--release");
            let status = common
                .cargo()
                .arg("clean")
                .arg("-q")
                .args(&self.args)
                .args(target_triple.map(|triple| format!("--target={triple}")))
                .args((!already_profile && try_release).then_some("--release"))
                .env("CARGO_TARGET_DIR", target_dir.join(target))
                .status()
                .expect("Error running cargo clean command");
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
