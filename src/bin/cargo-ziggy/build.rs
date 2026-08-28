use crate::{Build, Common, util::Context};
use anyhow::{Context as _, Result, bail};
use console::style;
use std::{env, process};

impl Build {
    /// Build the fuzzers
    pub fn build(&self, common: &Common) -> Result<(), anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            bail!("Pick at least one fuzzer");
        }

        let is_nightly = is_using_nightly_toolchain();

        if self.asan && !is_nightly {
            bail!("ASAN requires nightly toolchain");
        }

        if !is_nightly {
            eprintln!(
                "    {} the Rust toolchain is not nightly; AFL++ CMPLOG and ASAN instrumentation are unavailable",
                style("Warning:").yellow().bold()
            );
        }

        let cx = Context::new(common, self.target.clone())?;

        if is_nightly && !self.no_afl && !afl_plugins_installed(common) {
            eprintln!(
                "    {} the AFL++ LLVM plugins are not available; build them with `cargo afl config --update --plugins --verbose`",
                style("Warning:").yellow().bold()
            );
        }

        if !self.no_afl {
            eprintln!("    {} afl", style("Building").red().bold());
            let target_dir = format!("--target-dir={}", cx.target_dir.join("afl"));
            let mut afl_args = vec![
                "afl",
                "build",
                "--features=ziggy/afl",
                &target_dir,
                "--bin",
                &cx.bin_target,
            ];

            if self.release {
                afl_args.push("--release");
            }

            let mut rust_flags = env::var("RUSTFLAGS").unwrap_or_default();
            let mut rust_doc_flags = env::var("RUSTDOCFLAGS").unwrap_or_default();

            let mut cmd = common.cargo();
            cmd.args(&afl_args)
                .env("AFL_QUIET", "1")
                .env("AFL_LLVM_CMPLOG", "1") // for afl.rs feature "plugins"
                .env("RUSTFLAGS", &rust_flags)
                .env("RUSTDOCFLAGS", &rust_doc_flags);

            if is_nightly {
                // make afl.rs check that AFL++ plugins are installed and fail otherwise
                cmd.env("AFLRS_REQUIRE_PLUGINS", "1");
            }

            // First fuzzer we build: AFL++
            let run = cmd
                .spawn()?
                .wait()
                .context("Error spawning afl build command")?;

            if !run.success() {
                bail!("Error building afl fuzzer: Exited with {:?}", run.code());
            }

            let asan_target_str = format!("--target={}", target_triple::TARGET);

            // If ASAN is enabled, build both a sanitized binary and a non-sanitized binary.
            if self.asan {
                eprintln!("    {} afl (ASan)", style("Building").red().bold());
                afl_args.push(&asan_target_str);
                afl_args.extend(["-Z", "build-std"]);
                rust_flags.push_str(" -Zsanitizer=address ");
                rust_doc_flags.push_str(" -Zsanitizer=address ");

                let run = common
                    .cargo()
                    .args(afl_args)
                    .env("AFL_QUIET", "1")
                    .env("AFLRS_REQUIRE_PLUGINS", "1")
                    .env("RUSTFLAGS", rust_flags)
                    .env("RUSTDOCFLAGS", rust_doc_flags)
                    .spawn()?
                    .wait()
                    .context("Error spawning afl build command")?;

                if !run.success() {
                    bail!("Error building afl fuzzer: Exited with {:?}", run.code());
                }
            }

            eprintln!("    {} afl", style("Finished").cyan().bold());
        }

        if !self.no_honggfuzz {
            eprintln!("    {} honggfuzz", style("Building").red().bold());

            // Second fuzzer we build: Honggfuzz
            let run = common
                .cargo()
                .args(["hfuzz", "build", "--bin", &cx.bin_target])
                .env("CARGO_TARGET_DIR", cx.target_dir.join("honggfuzz"))
                .envs(honggfuzz_envs(self.asan))
                .stdout(process::Stdio::piped())
                .spawn()?
                .wait()
                .context("Error spawning hfuzz build command")?;

            if !run.success() {
                bail!(
                    "Error building honggfuzz fuzzer: Exited with {:?}",
                    run.code()
                );
            }

            eprintln!("    {} honggfuzz", style("Finished").cyan().bold());
        }

        Ok(())
    }
}

fn is_using_nightly_toolchain() -> bool {
    Common::rustc()
        .arg("--version")
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("nightly"))
}

pub fn afl_plugins_installed(common: &Common) -> bool {
    common
        .cargo()
        .args(["afl", "--version"])
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("with plugins"))
}

pub fn honggfuzz_envs(use_asan: bool) -> impl Iterator<Item = (&'static str, String)> {
    let mut rust_flags = String::new();
    let mut hfuzz_build_args = "--features=ziggy/honggfuzz ".to_owned();

    if use_asan {
        hfuzz_build_args.push_str("-Zbuild-std ");
        rust_flags.push_str("-Zsanitizer=address ");
    }
    let mut rust_doc_flags = rust_flags.clone();
    rust_flags.extend(env::var("RUSTFLAGS"));
    rust_doc_flags.extend(env::var("RUSTDOCFLAGS"));

    [
        ("RUSTFLAGS", rust_flags),
        ("RUSTDOCFLAGS", rust_doc_flags),
        ("HFUZZ_BUILD_ARGS", hfuzz_build_args),
    ]
    .into_iter()
}
