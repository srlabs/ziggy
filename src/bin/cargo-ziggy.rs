#[cfg(not(feature = "clap"))]
fn main() {}

#[cfg(feature = "clap")]
use clap::Command;
#[cfg(feature = "clap")]
use std::process;

#[cfg(feature = "clap")]
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

#[cfg(feature = "clap")]
fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("ziggy", subcommand)) => match subcommand.subcommand() {
            Some(("cover", _)) => {
                todo!();
            }
            Some(("fuzz", _)) => {
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

#[cfg(feature = "clap")]
fn fuzz_command() {

    println!("\n -- Running libfuzzer fuzzer");
    let _run = process::Command::new("./libfuzzer_target/debug/ziggy-example")
        .spawn()
        .expect("error starting libfuzzer fuzzer")
        .wait()
        .unwrap();

    let _ = process::Command::new("mkdir").arg("./tmp").spawn().expect("Error creating tmp directory").wait().unwrap();

    println!("\n -- Running afl fuzzer");
    let run = process::Command::new("cargo")
        .args(&["afl", "fuzz", "-itmp", "-otmp", "./afl_target/debug/ziggy-example"])
        .env("AFL_BENCH_UNTIL_CRASH", "true")
        .spawn()
        .expect("error starting libfuzzer fuzzer")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building libfuzzer fuzzer: Exited with {:?}",
        run.code()
    );

    println!("\n -- Running afl fuzzer");
    let run = process::Command::new("cargo")
        .args(&["hfuzz", "run", "ziggy-example"])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", "--exit_upon_crash")
        .spawn()
        .expect("error starting libfuzzer fuzzer")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building libfuzzer fuzzer: Exited with {:?}",
        run.code()
    );
}

#[cfg(feature = "clap")]
fn build_command() {
    println!("\n -- Compiling libfuzzer fuzzer");
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

    println!("\n -- Compiling afl fuzzer");
    let run = process::Command::new("cargo")
        .args(&["afl", "build", "--features=ziggy/afl", "--target-dir=afl_target"])
        .spawn()
        .expect("error starting afl build")
        .wait()
        .unwrap();

    assert!(
        run.success(),
        "error building afl fuzzer: Exited with {:?}",
        run.code()
    );

    println!("\n -- Compiling honggfuzz fuzzer");
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
}
