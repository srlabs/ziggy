use crate::{find_target, Run};
use anyhow::{anyhow, Context, Result};
use console::style;
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    process,
};

impl Run {
    // Run inputs
    pub fn run(&mut self) -> Result<(), anyhow::Error> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let target = find_target(&self.target)?;

        // We build the runner
        eprintln!("    {} runner", style("Building").red().bold());

        // We run the compilation command
        let run = process::Command::new(cargo)
            .args(["rustc", "--target-dir=target/runner"])
            .env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default())
            .spawn()
            .context("⚠️  couldn't spawn runner compilation")?
            .wait()
            .context("⚠️  couldn't wait for the runner compilation process")?;

        if !run.success() {
            return Err(anyhow!(
                "Error building runner: Exited with {:?}",
                run.code()
            ));
        }

        eprintln!("    {} runner", style("Finished").cyan().bold());

        if self.recursive {
            info!("Finding nested input directories recursively...");
            let mut all_dirs = HashSet::new();
            for input in &self.inputs {
                all_dirs.insert(input.clone());
                collect_dirs_recursively(input, &mut all_dirs)?;
            }
            for dir in all_dirs {
                if !self.inputs.contains(&dir) {
                    self.inputs.push(dir);
                }
            }
        }

        info!("Running inputs");
        let run_args: Vec<String> = self
            .inputs
            .iter()
            .map(|x| {
                x.display()
                    .to_string()
                    .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                    .replace("{target_name}", &target)
            })
            .collect();

        process::Command::new(format!("./target/runner/debug/{}", target))
            .args(run_args)
            .env("RUST_BACKTRACE", "full")
            .spawn()
            .context("⚠️  couldn't spawn the runner process")?
            .wait()
            .context("⚠️  couldn't wait for the runner process")?;

        Ok(())
    }
}

fn collect_dirs_recursively(
    dir: &Path,
    dir_list: &mut HashSet<PathBuf>,
) -> Result<(), anyhow::Error> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && !dir_list.contains(&path) {
                dir_list.insert(path.clone());
                collect_dirs_recursively(&path, dir_list)?;
            }
        }
    }
    Ok(())
}
