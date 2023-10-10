use crate::*;
use std::process;

impl Triage {
    pub fn triage(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Running CASR triage on crashes");

        self.target = find_target(&self.target)?;
        let input_dir = format!("{}/{}/afl", self.ziggy_output.display(), self.target);

        let triage_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target);
        fs::remove_dir_all(&triage_dir).unwrap_or_default();

        if !fs::metadata(&input_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            eprintln!("This option requires that at least one AFL++ instance was run!");
            return Ok(());
        }

        if fs::metadata(&triage_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            eprintln!("Please remove {:?} first", triage_dir);
            return Ok(());
        }

        let tool = String::from("casr-afl");
        process::Command::new(tool.clone())
            .args(
                [
                    "-i",
                    &input_dir,
                    "-o",
                    &triage_dir,
                    &format!("-j{}", self.jobs),
                    // future: add option for crashes directory and use runner
                ]
                .iter()
                .filter(|a| a != &&""),
            )
            .spawn()?
            .wait()?;

        Ok(())
    }
}
