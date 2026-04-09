use crate::{Common, Run, util::Context};
use anyhow::{Context as _, Result, bail};
use console::style;
use std::{
    collections::HashSet,
    env, fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
};

impl Run {
    // Run inputs
    pub fn run(&mut self, common: &Common) -> Result<(), anyhow::Error> {
        let cx = Context::new(common, self.target.clone())?;
        let target_arg = format!("--target-dir={}", cx.target_dir.join("runner"));

        let mut args = vec!["rustc", &target_arg];
        let asan_target_str = format!("--target={}", target_triple::TARGET);
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
        }

        // We build the runner
        eprintln!("    {} runner", style("Building").red().bold());

        // We run the compilation command
        let run = common
            .cargo()
            .args(args)
            .env("RUSTFLAGS", rust_flags)
            .env("RUSTDOCFLAGS", rust_doc_flags)
            .spawn()
            .context("⚠️  couldn't spawn runner compilation")?
            .wait()
            .context("⚠️  couldn't wait for the runner compilation process")?;

        if !run.success() {
            bail!("Error building runner: Exited with {:?}", run.code());
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

        let input_files: Vec<PathBuf> = self
            .inputs
            .iter()
            .flat_map(|x| {
                let canonical_name = x
                    .display()
                    .to_string()
                    .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                    .replace("{target_name}", &cx.bin_target);
                // For each directory we read, we get all files in that directory
                let path = PathBuf::from(canonical_name);
                if path.is_dir() {
                    fs::read_dir(path)
                        .expect("could not read directory")
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|path| path.is_file())
                        .collect::<Vec<_>>()
                } else {
                    vec![path]
                }
            })
            .collect();

        let runner_path = if self.asan {
            cx.target_dir.join(format!(
                "runner/{}/debug/{}",
                target_triple::TARGET,
                cx.bin_target
            ))
        } else {
            cx.target_dir
                .join(format!("runner/debug/{}", cx.bin_target))
        };

        let runner = Runner::new(
            common.async_runtime(),
            runner_path.as_std_path(),
            self.timeout
                .map(|s| tokio::time::Duration::from_secs(u64::from(s))),
        );

        for file in input_files {
            match runner.run(&file) {
                Status::Ok(status) => {
                    if !status.success() {
                        if let Some(signal) = status.signal() {
                            println!("⚠️  input terminated with signal {signal:?}!");
                        } else if let Some(exit_code) = status.code() {
                            println!("⚠️  input terminated with code {exit_code:?}!");
                        } else {
                            println!("⚠️  input terminated but we do not know why!");
                        }
                        if self.stop_on_crash {
                            return Ok(());
                        }
                    }
                }
                Status::Err(e) => return Err(e),
                Status::Timeout => {
                    println!("⚠️  input timed out!");
                    if self.stop_on_crash {
                        return Ok(());
                    }
                }
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

struct Runner<'a> {
    rt: &'a tokio::runtime::Runtime,
    path: &'a Path,
    timeout: Option<tokio::time::Duration>,
}

impl<'a> Runner<'a> {
    fn new(
        rt: &'a tokio::runtime::Runtime,
        path: &'a Path,
        timeout: Option<tokio::time::Duration>,
    ) -> Self {
        Self { rt, path, timeout }
    }

    fn run(&self, seed: &Path) -> Status {
        self.rt.block_on(async {
            let mut child = match tokio::process::Command::new(self.path)
                .arg(seed)
                .env("RUST_BACKTRACE", "full")
                .spawn()
                .context("⚠️  couldn't spawn the runner process")
            {
                Ok(child) => child,
                Err(e) => return e.into(),
            };
            let res = if let Some(duration) = self.timeout {
                if let Ok(res) = tokio::time::timeout(duration, child.wait()).await {
                    res
                } else {
                    let _ = child.start_kill();
                    return Status::Timeout;
                }
            } else {
                child.wait().await
            }
            .context("⚠️  couldn't wait for the runner process");
            match res {
                Ok(status) => Status::Ok(status),
                Err(e) => e.into(),
            }
        })
    }
}

enum Status {
    Timeout,
    Ok(std::process::ExitStatus),
    Err(anyhow::Error),
}

impl From<anyhow::Error> for Status {
    fn from(err: anyhow::Error) -> Self {
        Self::Err(err)
    }
}
