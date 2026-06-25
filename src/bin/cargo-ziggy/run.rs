use crate::{Common, Run, util::Context};
use anyhow::{Context as _, Result, bail};
use console::style;
use std::{
    collections::HashSet,
    env, fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
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
            runner_path.as_std_path(),
            self.timeout.map(|s| Duration::from_secs(u64::from(s))),
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
    path: &'a Path,
    timeout: Option<Duration>,
}

impl<'a> Runner<'a> {
    fn new(path: &'a Path, timeout: Option<Duration>) -> Self {
        Self { path, timeout }
    }

    fn run(&self, seed: &Path) -> Status {
        let mut child = match process::Command::new(self.path)
            .arg(seed)
            .env("RUST_BACKTRACE", "full")
            .spawn()
            .context("⚠️  couldn't spawn the runner process")
        {
            Ok(child) => child,
            Err(e) => return e.into(),
        };
        let res = match self.timeout {
            Some(duration) => {
                let start = Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break Ok(status),
                        Ok(None) if start.elapsed() >= duration => {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Status::Timeout;
                        }
                        Ok(None) => thread::sleep(Duration::from_millis(10)),
                        Err(e) => break Err(e),
                    }
                }
            }
            None => child.wait(),
        }
        .context("⚠️  couldn't wait for the runner process");
        match res {
            Ok(status) => Status::Ok(status),
            Err(e) => e.into(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::fs::PermissionsExt};

    /// Write a `/bin/sh` script with `body` into `dir`, mark it executable, and
    /// return its path. Used as a stand-in for the compiled runner binary.
    fn executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/sh\n{body}").unwrap();
        drop(file);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn dummy_seed(dir: &Path) -> PathBuf {
        let seed = dir.join("seed");
        fs::write(&seed, b"input").unwrap();
        seed
    }

    fn label(status: &Status) -> &'static str {
        match status {
            Status::Ok(_) => "Ok",
            Status::Timeout => "Timeout",
            Status::Err(_) => "Err",
        }
    }

    /// A run that finishes well within the timeout reports its real exit status
    /// instead of timing out.
    #[test]
    fn completes_within_timeout_reports_success() {
        let dir = tempfile::tempdir().unwrap();
        let runner_bin = executable_script(dir.path(), "fast-runner", "exit 0");
        let seed = dummy_seed(dir.path());

        let runner = Runner::new(&runner_bin, Some(Duration::from_secs(30)));
        match runner.run(&seed) {
            Status::Ok(status) => assert!(status.success()),
            other => panic!(
                "expected Status::Ok(success), got Status::{}",
                label(&other)
            ),
        }
    }

    /// A non-zero exit within the timeout is surfaced as a failing `Status::Ok`,
    /// not misreported as a timeout.
    #[test]
    fn nonzero_exit_is_reported_not_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let runner_bin = executable_script(dir.path(), "failing-runner", "exit 3");
        let seed = dummy_seed(dir.path());

        let runner = Runner::new(&runner_bin, Some(Duration::from_secs(30)));
        match runner.run(&seed) {
            Status::Ok(status) => {
                assert!(!status.success());
                assert_eq!(status.code(), Some(3));
            }
            other => panic!(
                "expected Status::Ok(failure), got Status::{}",
                label(&other)
            ),
        }
    }

    /// A run that outlasts the timeout is killed and reported as a timeout, and
    /// the call returns promptly rather than blocking for the full run.
    #[test]
    fn exceeding_timeout_is_killed_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        // `exec` so the shell is replaced by `sleep`, ensuring the process we
        // spawn is the one we kill on timeout.
        let runner_bin = executable_script(dir.path(), "slow-runner", "exec sleep 30");
        let seed = dummy_seed(dir.path());

        let runner = Runner::new(&runner_bin, Some(Duration::from_millis(100)));
        let start = Instant::now();
        let status = runner.run(&seed);
        let elapsed = start.elapsed();

        assert!(
            matches!(status, Status::Timeout),
            "expected Status::Timeout, got Status::{}",
            label(&status),
        );
        // If the child were waited on rather than killed, this would take ~30s.
        assert!(
            elapsed < Duration::from_secs(10),
            "timeout should return promptly after killing the child, took {elapsed:?}",
        );
    }

    /// Without a timeout the runner simply waits for the process to finish.
    #[test]
    fn no_timeout_waits_for_completion() {
        let dir = tempfile::tempdir().unwrap();
        let runner_bin = executable_script(dir.path(), "no-timeout-runner", "exit 0");
        let seed = dummy_seed(dir.path());

        let runner = Runner::new(&runner_bin, None);
        match runner.run(&seed) {
            Status::Ok(status) => assert!(status.success()),
            other => panic!(
                "expected Status::Ok(success), got Status::{}",
                label(&other)
            ),
        }
    }

    /// A runner binary that cannot be spawned yields an error rather than a
    /// timeout or a phantom success.
    #[test]
    fn spawn_failure_is_reported_as_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let seed = dummy_seed(dir.path());

        let runner = Runner::new(&missing, Some(Duration::from_secs(30)));
        match runner.run(&seed) {
            Status::Err(_) => {}
            other => panic!("expected Status::Err, got Status::{}", label(&other)),
        }
    }
}
