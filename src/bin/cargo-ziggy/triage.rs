use crate::{Common, Triage, util::Context};
use anyhow::{Context as _, bail};
use std::{fs, process};

impl Triage {
    pub fn triage(&self, common: &Common) -> Result<(), anyhow::Error> {
        eprintln!("Running CASR triage on crashes");

        let cx = Context::new(common, self.target.clone())?;
        let input_dir = cx.target_dir.join("afl");

        let triage_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target);
        fs::remove_dir_all(&triage_dir).ok();

        if !fs::metadata(&input_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            bail!("This option requires that at least one AFL++ instance was run!");
        }

        if fs::metadata(&triage_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            bail!("Please remove {triage_dir:?} first");
        }

        process::Command::new("casr-afl")
            .args([
                "-i",
                input_dir.as_ref(),
                "-o",
                &triage_dir,
                &format!("-j{}", self.jobs),
                &format!("-t{}", self.timeout.unwrap_or(0)), // future: add option for crashes directory and use runner
            ])
            .spawn()
            .context("Running casr failed, try `cargo install casr`")?
            .wait()?;

        Ok(())
    }
}
