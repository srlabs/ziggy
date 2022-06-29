#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use clap::Command;
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    net::UdpSocket,
    process, thread,
    time::{Duration, Instant},
};

// Half an hour, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py#L54-L56
#[cfg(feature = "cli")]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[cfg(feature = "cli")]
const DEFAULT_CORPUS: &str = "./shared_corpus/";

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
                    )
                    .arg(
                        clap::Arg::new("corpus")
                            .short('c')
                            .long("corpus")
                            .takes_value(true)
                            .value_name("DIR")
                            .help("Shared corpus directory"),
                    )
                    .arg(
                        clap::Arg::new("min")
                            .short('m')
                            .long("minimization-timeout")
                            .takes_value(true)
                            .value_name("SECS")
                            .value_parser(clap::value_parser!(usize))
                            .help("Timeout before shared corpus minimization"),
                    )
                    .arg(
                        clap::Arg::new("threads")
                            .short('t')
                            .long("threads-multiplier")
                            .takes_value(true)
                            .value_name("NUM")
                            .value_parser(clap::value_parser!(usize))
                            // .default_value("1")
                            .help(
                                "Number of threads per fuzzer (total CPU usage will be 3xNUM CPUs)",
                            ),
                    ),
            )
            .subcommand(Command::new("init").about("Create a new fuzzing target"))
            .subcommand(
                Command::new("minimize")
                    .about("Minimize the input corpus using the given fuzzing target")
                    .arg(
                        clap::Arg::new("target")
                            .required(true)
                            .help("Target to use"),
                    )
                    .arg(clap::Arg::new("corpus").help("Corpus directory to minimize")),
            )
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
            Some(("minimize", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let corpus = args.value_of("corpus").unwrap_or(DEFAULT_CORPUS);
                minimize_corpus(target, corpus);
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
fn launch_fuzzers(
    target: &str,
    shared_corpus: &str,
    threads_mult: &str,
    minimization_timeout: Duration,
) -> Vec<process::Child> {
    // TODO loop over fuzzer config objects

    let _ = process::Command::new("mkdir")
        .arg("./shared_corpus")
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("Error creating shared_corpus directory")
        .wait()
        .unwrap();

    let libfuzzer_handle = process::Command::new(format!("./libfuzzer_target/debug/{target}"))
        .args(&[
            shared_corpus,
            "--",
            &format!("-artifact_prefix=./{shared_corpus}/"),
            &format!("-jobs={threads_mult}"),
        ])
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

    // TODO make it so that you don't have to `cargo install afl`
    // TODO launch threads_mult processes, one being main and the rest secondary
    let afl_handle = process::Command::new("cargo")
        .args(&[
            "afl",
            "fuzz",
            "-Mmainaflfuzzer",
            &format!("-i{shared_corpus}"),
            "-oafl_workspace",
            &format!("-F{shared_corpus}"),
            &format!("-V{}", minimization_timeout.as_secs()),
            &format!("./afl_target/debug/{target}"),
        ])
        .env("AFL_BENCH_UNTIL_CRASH", "true")
        .env("AFL_STATSD", "true")
        .env("AFL_AUTORESUME", "1")
        .stdout(File::create("afl.log").unwrap())
        .stderr(File::create("afl.log").unwrap())
        .spawn()
        .expect("error starting afl fuzzer");
    println!("{} afl", style("launched").green());

    // TODO make it so that you don't have to `cargo install honggfuzz`
    let hfuzz_handle = process::Command::new("cargo")
        .args(&["hfuzz", "run", target])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env(
            "HFUZZ_RUN_ARGS",
            format!("--exit_upon_crash -i{} -n{}", shared_corpus, threads_mult),
        )
        .stderr(File::create("hfuzz.log").unwrap())
        .stdout(File::create("hfuzz.log").unwrap())
        .spawn()
        .expect("error starting libfuzzer fuzzer");
    println!("{} honggfuzz", style("launched").green());

    vec![libfuzzer_handle, afl_handle, hfuzz_handle]
}

#[cfg(feature = "cli")]
fn fuzz_command(args: &clap::ArgMatches) {
    use std::os::unix::prelude::ExitStatusExt;

    let target = args.value_of("target").expect("Could not parse target");
    let corpus = args.value_of("corpus").unwrap_or(DEFAULT_CORPUS);
    let minimization_timeout = args
        .value_of("min")
        .map(|t| {
            Duration::from_secs(
                t.parse::<u64>()
                    .expect("could not parse minimization timeout"),
            )
        })
        .unwrap_or(DEFAULT_TIMEOUT);
    let threads_mult = args.value_of("threads").unwrap_or("1");

    let mut processes = launch_fuzzers(target, corpus, threads_mult, minimization_timeout);

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

    let mut last_merge = Instant::now();

    loop {
        let thirty_fps = Duration::from_millis(33);
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

        // Every DEFAULT_TIMEOUT, we kill the fuzzers and minimize the shared corpus, before launching the fuzzers again
        if last_merge.elapsed() > minimization_timeout {
            term.move_cursor_up(3).unwrap();

            for mut process in processes {
                process.kill().unwrap_or_default();
                process.wait().unwrap_or(process::ExitStatus::from_raw(0));
            }

            term.write_line("now running minimization            ")
                .unwrap();
            term.write_line("          ....                      ")
                .unwrap();
            term.write_line("     please hold on                 ")
                .unwrap();
            let old_corpus_size = fs::read_dir(corpus).unwrap().count();

            // TODO Can we run minimization + coverage report at the same time?
            minimize_corpus(target, corpus);

            let new_corpus_size = fs::read_dir(corpus).unwrap().count();
            term.move_cursor_up(3).unwrap();
            println!(
                "{} the corpus : {} -> {} files             ",
                style("minimized").red(),
                old_corpus_size,
                new_corpus_size
            );

            last_merge = Instant::now();
            processes = launch_fuzzers(target, corpus, threads_mult, minimization_timeout);

            term.write_line(&style("afl++ stats").yellow().to_string())
                .unwrap();
            term.write_line("...").unwrap();
            term.write_line("...").unwrap();
        }
    }

    term.write_line(&format!(
        "{} all fuzzers are done",
        style("finished").cyan()
    ))
    .unwrap();
}

#[cfg(feature = "cli")]
fn minimize_corpus(target: &str, corpus: &str) {
    process::Command::new("cargo")
        .args(&["hfuzz", "run", target])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", format!("-i{} -M", corpus))
        .stderr(File::create("minimization.log").unwrap())
        .stdout(File::create("minimization.log").unwrap())
        .spawn()
        .expect("error launching corpus minimization")
        .wait()
        .expect("error waiting for corpus minimization");
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
