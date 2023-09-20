use crate::*;
use std::process;

impl Triage {
    pub fn triage(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Running CASR triage on crashes");

        self.target = find_target(&self.target)?;
        let input_dir = format!("output/{}/afl", self.target);
        let output_dir = if self.output != DEFAULT_TRIAGE_DIR {
            self.output.clone()
        } else {
            let tmp = format!("output/{}/triage", &self.target);
            fs::remove_dir_all(&tmp).unwrap_or_default();
            tmp
        };

        if !fs::metadata(&input_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            eprintln!("This option requires that at least one AFL++ instance was run!");
            return Ok(());
        }

        if fs::metadata(&output_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            eprintln!("Please remove {:?} first", output_dir);
            return Ok(());
        }

        let tool = String::from("casr-afl");
        process::Command::new(tool.clone())
            .args(
                [
                    "-i",
                    &input_dir,
                    "-o",
                    &output_dir,
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
