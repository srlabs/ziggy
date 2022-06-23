#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use clap::Command;
#[cfg(feature = "cli")]
use console::style;
#[cfg(feature = "cli")]
use std::{process, thread, time};

#[cfg(feature = "cli")]
pub fn cli() -> Command<'static> {
    Command::new("cargo-ziggy").bin_name("cargo").subcommand(
        clap::command!("ziggy")
            .about("A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤")
            .arg_required_else_help(true)
            .subcommand_required(true)
            .allow_external_subcommands(true)
            .allow_invalid_utf8_for_external_subcommands(true)
            .subcommand(
                Command::new("cover")
                    .about("Generate code coverage information using the existing corpus"),
            )
            .subcommand(
                Command::new("fuzz").about("Fuzz targets using different fuzzers in parallel"),
            )
            .subcommand(Command::new("init").about("Create a new fuzzing target"))
            .subcommand(
                Command::new("run")
                    .about("Run a specific input or a directory of inputs to analyze backtrace"),
            )
            .subcommand(Command::new("build").about("Build the fuzzer and the runner binaries")),
    )
}

#[cfg(feature = "cli")]
fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("ziggy", subcommand)) => match subcommand.subcommand() {
            Some(("cover", _)) => {
                todo!();
            }
            Some(("fuzz", _)) => {
                build_command();
                fuzz_command();
            }
            Some(("init", _)) => {
                todo!();
            }
            Some(("run", _)) => {
                todo!();
            }
            Some(("build", _)) => {
                build_command();
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[cfg(feature = "cli")]
fn fuzz_command() {

    // TODO loop over fuzzer config objects
    // TODO make this process work on an arbitrary target

    let libfuzzer_process = process::Command::new("./libfuzzer_target/debug/ziggy-example")
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("error starting libfuzzer fuzzer");
    println!("{} libfuzzer", style("launched").green());

    let _ = process::Command::new("mkdir")
        .arg("./afl_workspace")
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("Error creating afl_workspace directory")
        .wait()
        .unwrap();

    let afl_process = process::Command::new("cargo")
        .args(&[
            "afl",
            "fuzz",
            "-iafl_workspace",
            "-oafl_workspace",
            "./afl_target/debug/ziggy-example",
        ])
        .env("AFL_BENCH_UNTIL_CRASH", "true")
        .stdout(process::Stdio::piped())
        .spawn()
        .expect("error starting libfuzzer fuzzer");
    println!("{} afl", style("launched").green());

    let hfuzz_process = process::Command::new("cargo")
        .args(&["hfuzz", "run", "ziggy-example"])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz --offline")
        .env("HFUZZ_RUN_ARGS", "--exit_upon_crash")
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("error starting libfuzzer fuzzer");
    println!("{} honggfuzz", style("launched").green());

    let mut processes = vec![libfuzzer_process, afl_process, hfuzz_process];

    println!(
        "{} for the fuzzers to find a crash",
        style("waiting").yellow()
    );

    loop {
        let thirty_fps = time::Duration::from_millis(33);
        thread::sleep(thirty_fps);

        // TODO do something with the stdio streams and display info

        if processes
            .iter_mut()
            .all(|process| process.try_wait().unwrap_or(None).is_some())
        {
            break;
        }
    }

    println!("{} all fuzzers are done", style("finished").cyan());
}

#[cfg(feature = "cli")]
fn build_command() {

    // TODO loop over fuzzer config objects
    // TODO make this process work on an arbitrary target

    let run = process::Command::new("cargo")
        .args(&["rustc", "--features=ziggy/libfuzzer-sys", "--target-dir=libfuzzer_target"])
        .env("RUSTFLAGS", " -Cpasses=sancov -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Zsanitizer=address -Znew-llvm-pass-manager=no")
        .spawn()
        .expect("error starting libfuzzer build")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building libfuzzer fuzzer: Exited with {:?}",
        run.code()
    );
    println!("{} libfuzzer and its target", style("built").blue());

    let run = process::Command::new("cargo")
        .args(&[
            "afl",
            "build",
            "--features=ziggy/afl",
            "--target-dir=afl_target",
        ])
        .spawn()
        .expect("error starting afl build")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building afl fuzzer: Exited with {:?}",
        run.code()
    );
    println!("{} afl and its target", style("built").blue());

    let run = process::Command::new("cargo")
        .args(&["hfuzz", "build"])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .spawn()
        .expect("error starting honggfuzz build")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building honggfuzz fuzzer: Exited with {:?}",
        run.code()
    );
    println!("{} honggfuzz and its target", style("built").blue());
}
