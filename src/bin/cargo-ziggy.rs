#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use clap::Command;
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::UdpSocket,
    process, thread, time,
};

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
                Command::new("fuzz")
                    .about("Fuzz targets using different fuzzers in parallel")
                    .arg(
                        clap::Arg::new("target")
                            .required(true)
                            .help("Target to fuzz"),
                    ),
            )
            .subcommand(Command::new("init").about("Create a new fuzzing target"))
            .subcommand(
                Command::new("run")
                    .about("Run a specific input or a directory of inputs to analyze backtrace"),
            )
            .subcommand(Command::new("build").about("Build the fuzzer and the runner binaries"))
            .subcommand(Command::new("clean").about("Clean the target directories")),
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
            Some(("fuzz", args)) => {
                build_command();
                fuzz_command(args);
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
            Some(("clean", _)) => {
                let _ = process::Command::new("rm")
                    .args(&[
                        "-rf",
                        "./libfuzzer_target",
                        "./afl_target",
                        "./hfuzz_target",
                        "./target",
                    ])
                    .spawn()
                    .expect("Error removing target directories")
                    .wait()
                    .unwrap();
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[cfg(feature = "cli")]
fn fuzz_command(args: &clap::ArgMatches) {
    // TODO loop over fuzzer config objects

    let target = args.value_of("target").expect("Could not parse target");

    let _ = process::Command::new("mkdir")
        .arg("./shared_corpus")
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("Error creating shared_corpus directory")
        .wait()
        .unwrap();

    let libfuzzer_handle = process::Command::new(format!("./libfuzzer_target/debug/{target}"))
        .args(&["shared_corpus", "--", "-artifact_prefix=./shared_corpus/"])
        .stdout(File::create("libfuzzer.log").unwrap())
        .stderr(File::create("libfuzzer.log").unwrap())
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

    let afl_handle = process::Command::new("cargo")
        .args(&[
            "afl",
            "fuzz",
            "-Mmainaflfuzzer",
            "-iafl_workspace",
            "-oafl_workspace",
            "-Fshared_corpus",
            &format!("./afl_target/debug/{target}"),
        ])
        .env("AFL_BENCH_UNTIL_CRASH", "true")
        .env("AFL_STATSD", "true")
        .stdout(File::create("afl.log").unwrap())
        .stderr(File::create("afl.log").unwrap())
        .spawn()
        .expect("error starting afl fuzzer");
    println!("{} afl", style("launched").green());

    let hfuzz_handle = process::Command::new("cargo")
        .args(&["hfuzz", "run", target])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz --offline")
        .env("HFUZZ_RUN_ARGS", "--exit_upon_crash -ishared_corpus")
        .stderr(File::create("hfuzz.log").unwrap())
        .stdout(File::create("hfuzz.log").unwrap())
        .spawn()
        .expect("error starting libfuzzer fuzzer");
    println!("{} honggfuzz", style("launched").green());

    let mut processes = vec![libfuzzer_handle, afl_handle, hfuzz_handle];

    let term = Term::stdout();
    term.write_line(&style("afl++ stats").yellow().to_string())
        .unwrap();
    term.write_line("...").unwrap();
    term.write_line("...").unwrap();

    // Variables for stats printing
    let mut corpus_count = String::new();
    let mut edges_found = String::new();
    let mut total_edges = String::new();

    // We connect to the afl statsd socket
    let socket = UdpSocket::bind(("127.0.0.1", 8125)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut buf = [0; 1024];

    loop {
        let thirty_fps = time::Duration::from_millis(33);
        thread::sleep(thirty_fps);

        // We retrieve the total_edged value from the fuzzer_stats file
        if total_edges == "" {
            if let Ok(file) = File::open("./afl_workspace/mainaflfuzzer/fuzzer_stats") {
                total_edges = String::from(
                    BufReader::new(file)
                        .lines()
                        .nth(31)
                        .unwrap_or(Ok(String::new()))
                        .unwrap_or_default()
                        .trim_start_matches("total_edges       : "),
                );
            }
        }

        // If we have new stats from afl's statsd socket, we update our values
        if let Ok((amt, _)) = socket.recv_from(&mut buf) {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&buf[0..amt]);

            for msg in String::from_utf8(v).unwrap().split_terminator("\n") {
                if msg.contains("corpus_count") {
                    corpus_count = String::from(msg[21..].trim_end_matches("|g"));
                } else if msg.contains("edges_found") {
                    edges_found = String::from(msg[20..].trim_end_matches("|g"));
                }
            }

            // We print the new values
            term.move_cursor_up(2).unwrap();
            term.write_line(&format!(
                "{} {}",
                style("corpus count :").dim(),
                &corpus_count
            ))
            .unwrap();
            let edges_percentage = 100f64 * edges_found.parse::<f64>().unwrap_or_default()
                / total_edges.parse::<f64>().unwrap_or(1f64);
            term.write_line(&format!(
                "{} {} ({:.2}%)",
                style(" edges found :").dim(),
                &edges_found,
                &edges_percentage
            ))
            .unwrap();
        }

        if processes
            .iter_mut()
            .all(|process| process.try_wait().unwrap_or(None).is_some())
        {
            break;
        }
    }

    term.write_line(&format!(
        "{} all fuzzers are done",
        style("finished").cyan()
    ))
    .unwrap();
}

#[cfg(feature = "cli")]
fn build_command() {
    // TODO loop over fuzzer config objects

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
