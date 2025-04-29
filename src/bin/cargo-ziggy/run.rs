use crate::build::append_env_var;
use crate::libfuzzer::TARGET_SUBDIR;
use crate::{build::ASAN_TARGET, find_target, Build, Run};
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

        if self.cpp {
            env::set_var("AFL_COMPILER_MODE", "runner");
            let builder = Build {
                no_afl: true,
                no_honggfuzz: true,
                release: false,
                asan: self.asan,
                cpp: true,
                lto: false,
                target_name: self.target_name.clone(),
                cmakelist_path: self.cmakelist_path.clone(),
                additional_libs: self.additional_libs.clone(),
            };
            builder.build_cpp()?;
        }

        if self.asan {
            // Crash if we detect an ASAN bug
            append_env_var("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1");
            args.push(&asan_target_str);
            args.extend(["-Z", "build-std"]);
            rust_flags.push_str(" -Zsanitizer=address ");
            rust_flags.push_str(" -Copt-level=0 ");
            rust_doc_flags.push_str(" -Zsanitizer=address ");
        };

        // We build the runner
        eprintln!("    {} runner", style("Building").red().bold());

        eprintln!(
            "    {} `AFL_COMPILER_MODE={} ASAN_OPTIONS={} RUSTDOCFLAGS={rust_doc_flags} RUSTFLAGS={rust_flags} cargo {}`",
            style("Compiling with").cyan().bold(),
            env::var("AFL_COMPILER_MODE").unwrap_or("??".parse()?),
            env::var("ASAN_OPTIONS").unwrap_or("??".parse()?), 
            args.join(" ")
        );

        // We run the compilation command
        let output = process::Command::new(cargo)
            // .current_dir(TARGET_SUBDIR)
            .args(args)
            .env("RUSTFLAGS", rust_flags)
            .env("RUSTDOCFLAGS", rust_doc_flags)
            .output()
            .context("⚠️  couldn't execute runner compilation")?;

        println!("\n{}", String::from_utf8_lossy(&output.stdout));
        println!("\n{}", String::from_utf8_lossy(&output.stderr));

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

        let runner_path = if self.cpp {
            if self.asan {
                format!("./{}/target/afl/debug/{target}", TARGET_SUBDIR) //TODO
            } else {
                format!("./{}/target/runner/debug/{target}", TARGET_SUBDIR)
            }
        } else if self.asan {
            format!("./target/runner/{ASAN_TARGET}/debug/{target}")
        } else {
            format!("./target/runner/debug/{target}")
        };

        //ENABLE_FUZZ_MAIN
        println!("Using runner {runner_path}");
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
