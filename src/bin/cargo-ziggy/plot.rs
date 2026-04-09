use crate::{Common, Plot, util::Context};
use anyhow::{Context as _, Result};

impl Plot {
    pub fn generate_plot(&self, common: &Common) -> Result<(), anyhow::Error> {
        eprintln!("Generating plot");

        let cx = Context::new(common, self.target.clone())?;

        let fuzzer_data_dir = format!(
            "{}/{}/afl/{}/",
            self.ziggy_output.display(),
            cx.bin_target,
            &self.input
        );

        let plot_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target);
        println!("{plot_dir}");
        println!("{}", cx.bin_target);

        // We run the afl-plot command
        common
            .cargo()
            .args(["afl", "plot", &fuzzer_data_dir, &plot_dir])
            .spawn()
            .context("⚠️  couldn't spawn afl plot")?
            .wait()
            .context("⚠️  couldn't wait for the afl plot")?;

        Ok(())
    }
}
