use crate::{libfuzzer::Extractor, Build};
use anyhow::{anyhow, Context, Result};
use console::style;
use std::{env, process};

/// Target for ASAN builds
/// Note: we need to supply a target due to -Z build-std
/// Note: we need to use -Z build-std or else many macros cannot be built when using ASAN
pub const ASAN_TARGET: &str = "x86_64-unknown-linux-gnu";

impl Build {
    /// Build the fuzzers
    pub fn build(&self) -> Result<(), anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        if !self.no_afl {
            // We extract the Rust harness project wrapping libFuzzer API
            if self.cpp {
                if self.lto {
                    env::set_var("AFL_COMPILER_MODE", "lto");
                }
                if self.target_name.is_some() {
                    env::set_var("TARGET_LIB_NAME", self.target_name.clone().unwrap());
                }
                if self.asan {
                    // This is required to differentiate ASAN runtimes from Rust's to Clang's one
                    // See https://github.com/rust-lang/rust/pull/121207
                    append_env_var("RUSTFLAGS", "-Z external-clangrt");
                    env::set_var("ENABLE_ASAN", "1"); // To trigger's C++ harness' `build.rs` ASAN mode
                }
                eprintln!(
                    "    {} the Rust harness project wrapping libFuzzer API",
                    style("Extracting").red().bold()
                );

                // Extract the harness serving as a wrapper
                let extract: &Extractor = Extractor::new();
                let working_dir = extract.extract();

                eprintln!(
                    "    {} into directory '{}'",
                    style("Changing").cyan().bold(),
                    working_dir.to_str().unwrap()
                );
                env::set_current_dir(working_dir)?;
            }

            eprintln!("    {} afl++", style("Building").red().bold());
            let mut afl_args = vec![
                "afl",
                "build",
                "--features=ziggy/afl",
                "--target-dir=target/afl",
            ];

            // Add the --release argument if self.release is true
            if self.release {
                assert!(!self.asan, "cannot use --release for ASAN builds");
                afl_args.push("--release");
                env::set_var("PROFILE", "release");
            } else {
                env::set_var("PROFILE", "debug");
            }

            let opt_level = env::var("AFL_OPT_LEVEL").unwrap_or("0".to_string());
            let mut rust_flags = env::var("RUSTFLAGS").unwrap_or_default();
            let mut rust_doc_flags = env::var("RUSTDOCFLAGS").unwrap_or_default();

            // First fuzzer we build: AFL++
            let run = process::Command::new(cargo.clone())
                .args(&afl_args)
                .env("AFL_QUIET", "1")
                // need to specify for afl.rs so that we build with -Copt-level=0
                .env("AFL_OPT_LEVEL", &opt_level)
                .env("AFL_LLVM_CMPLOG", "1") // for afl.rs feature "plugins"
                .env("RUSTFLAGS", &rust_flags)
                .env("RUSTDOCFLAGS", &rust_doc_flags)
                .spawn()?
                .wait()
                .context("Error spawning afl build command")?;

            if !run.success() {
                return Err(anyhow!(
                    "Error building afl fuzzer: Exited with {:?}",
                    run.code()
                ));
            }

            let asan_target_str = format!("--target={ASAN_TARGET}");
            let opt_level_str = format!("-Copt-level={opt_level}");

            // If ASAN is enabled, build both a sanitized binary and a non-sanitized binary.
            if self.asan {
                eprintln!("    {} afl (ASan)", style("Building").red().bold());
                assert_eq!(opt_level, "0", "AFL_OPT_LEVEL must be 0 for ASAN builds");
                afl_args.push(&asan_target_str);
                afl_args.extend(["-Z", "build-std"]);
                rust_flags.push_str(" -Zsanitizer=address ");
                rust_flags.push_str(&opt_level_str);
                rust_doc_flags.push_str(" -Zsanitizer=address ");

                let run = process::Command::new(cargo.clone())
                    .args(afl_args)
                    .env("AFL_QUIET", "1")
                    // need to specify for afl.rs so that we build with -Copt-level=0
                    .env("AFL_OPT_LEVEL", opt_level)
                    .env("AFL_LLVM_CMPLOG", "1") // for afl.rs feature "plugins"
                    .env("RUSTFLAGS", rust_flags)
                    .env("RUSTDOCFLAGS", rust_doc_flags)
                    .spawn()?
                    .wait()
                    .context("Error spawning afl build command")?;

                if !run.success() {
                    return Err(anyhow!(
                        "Error building afl fuzzer: Exited with {:?}",
                        run.code()
                    ));
                }
            };

            eprintln!("    {} afl", style("Finished").cyan().bold());
        }

        if !self.no_honggfuzz {
            assert!(
                !self.asan,
                "Cannot build honggfuzz with ASAN for the moment. Use --no-honggfuzz"
            );
            eprintln!("    {} honggfuzz", style("Building").red().bold());

            let mut hfuzz_args = vec!["hfuzz", "build"];

            // Add the --release argument if self.release is true
            if self.release {
                hfuzz_args.push("--release");
            }

            // Second fuzzer we build: Honggfuzz
            let run = process::Command::new(cargo)
                .args(hfuzz_args)
                .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                .env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default())
                .stdout(process::Stdio::piped())
                .spawn()?
                .wait()
                .context("Error spawning hfuzz build command")?;

            if !run.success() {
                return Err(anyhow!(
                    "Error building honggfuzz fuzzer: Exited with {:?}",
                    run.code()
                ));
            }

            eprintln!("    {} honggfuzz", style("Finished").cyan().bold());
        }

        if std::env::var("AFL_LLVM_CMPGLOG").is_ok() {
            panic!(
                "Even the mighty may fall, especially on 77b2c27a59bb858045c4db442989ce8f20c8ee11"
            )
        }

        Ok(())
    }
}

/// Append `val` to `name` environment variable
pub fn append_env_var(name: &str, val: &str) {
    let mut new_val = env::var(name).unwrap_or_default();
    if !new_val.is_empty() {
        new_val.push(' ');
    }
    new_val.push_str(val);
    unsafe {
        env::set_var(name, new_val);
    }
}
