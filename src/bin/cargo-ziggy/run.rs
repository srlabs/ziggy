use crate::{build::ASAN_TARGET, find_target, Run};
use anyhow::{anyhow, Context, Result};
use console::style;
use std::{
    collections::HashSet,
    env, fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process,
};

impl Run {
    // Run inputs
    pub fn run(&mut self) -> Result<(), anyhow::Error> {
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
        let target = find_target(&self.target)?;

        let mut args = vec!["rustc", "--target-dir=target/runner"];
        let asan_target_str = format!("--target={ASAN_TARGET}");
        let mut rust_flags = env::var("RUSTFLAGS").unwrap_or_default();
        let mut rust_doc_flags = env::var("RUSTDOCFLAGS").unwrap_or_default();

        for feature in &self.features {
            args.extend(["-F", feature.as_str()]);
        }

        if self.asan {
            args.push(&asan_target_str);
            args.extend(["-Z", "build-std"]);
            rust_flags.push_str(" -Zsanitizer=address ");
            rust_flags.push_str(" -Copt-level=0 ");
            rust_doc_flags.push_str(" -Zsanitizer=address ");
        };

        // We build the runner
        eprintln!("    {} runner", style("Building").red().bold());

        // We run the compilation command
        let run = process::Command::new(cargo)
            .args(args)
            .env("RUSTFLAGS", rust_flags)
            .env("RUSTDOCFLAGS", rust_doc_flags)
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

        let runner_path = match self.asan {
            true => format!("./target/runner/{ASAN_TARGET}/debug/{}", target),
            false => format!("./target/runner/debug/{}", target),
        };

        let res = process::Command::new(runner_path)
            .args(run_args)
            .env("RUST_BACKTRACE", "full")
            .spawn()
            .context("⚠️  couldn't spawn the runner process")?
            .wait()
            .context("⚠️  couldn't wait for the runner process")?;

        if !res.success() {
            if let Some(signal) = res.signal() {
                println!("⚠️  input terminated with signal {:?}!", signal);
            } else if let Some(exit_code) = res.code() {
                println!("⚠️  input terminated with code {:?}!", exit_code);
            } else {
                println!("⚠️  input terminated but we do not know why!");
            }
        }

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
