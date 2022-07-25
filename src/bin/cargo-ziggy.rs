#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use clap::Command;
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader},
    net::UdpSocket,
    process, thread,
    time::{Duration, Instant},
};

// Half an hour, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py#L54-L56
#[cfg(feature = "cli")]
const DEFAULT_TIMEOUT: &str = "1800";

#[cfg(feature = "cli")]
const DEFAULT_CORPUS: &str = "./output/shared_corpus/";

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
                            .value_name("DIR")
                            .default_value(DEFAULT_CORPUS)
                            .help("Shared corpus directory"),
                    )
                    .arg(
                        clap::Arg::new("min")
                            .short('m')
                            .long("minimization-timeout")
                            .value_name("SECS")
                            .default_value(DEFAULT_TIMEOUT)
                            .help("Timeout before shared corpus minimization"),
                    )
                    .arg(
                        clap::Arg::new("threads")
                            .short('t')
                            .long("threads-multiplier")
                            .value_name("NUM")
                            .default_value("1")
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
                    .arg(clap::Arg::new("input-corpus").help("Corpus directory to minimize"))
                    .arg(clap::Arg::new("output-corpus").help("Output directory")),
            )
            .subcommand(
                Command::new("run")
                    .about("Run a specific input or a directory of inputs to analyze backtrace")
                    .arg(
                        clap::Arg::new("target")
                            .required(true)
                            .help("Target to use"),
                    )
                    .arg(clap::Arg::new("inputs").help("Input directory or file to run")),
            )
            .subcommand(Command::new("build").about("Build the fuzzer and the runner binaries"))
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
            Some(("run", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let inputs = args.value_of("inputs").unwrap_or(DEFAULT_CORPUS);
                run_inputs(target, inputs);
            }
            Some(("build", _)) => {
                build_command();
            }
            Some(("minimize", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let input_corpus = args.value_of("input-corpus").unwrap_or(DEFAULT_CORPUS);
                let output_corpus = args.value_of("output-corpus").unwrap_or("./output/minimized_corpus");
                minimize_corpus(target, input_corpus, output_corpus);
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
    threads_mult: usize,
    minimization_timeout: Duration,
) -> Vec<process::Child> {
    // TODO loop over fuzzer config objects

    let mut fuzzer_handles = vec![];

    let _ = process::Command::new("mkdir")
        .args(&["-p", &shared_corpus])
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("error creating shared corpus directory")
        .wait()
        .unwrap();

    let _ = process::Command::new("mkdir")
        .args(&["-p", "./output/libfuzzer"])
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("error creating shared corpus directory")
        .wait()
        .unwrap();

    fuzzer_handles.push(
        process::Command::new(fs::canonicalize(format!("./target/libfuzzer/debug/{target}")).unwrap())
            .args(&[
                fs::canonicalize(shared_corpus).unwrap().to_str().unwrap(),
                "--",
                &format!("-artifact_prefix={}/", fs::canonicalize(shared_corpus).unwrap().display()),
                &format!("-jobs={threads_mult}"),
            ])
            .current_dir("./output/libfuzzer")
            .stdout(File::create("./output/libfuzzer.log").unwrap())
            .stderr(File::create("./output/libfuzzer.log").unwrap())
            .spawn()
            .expect("error starting libfuzzer fuzzer"),
    );

    println!("{} libfuzzer          ", style("launched").green());

    let _ = process::Command::new("mkdir")
        .arg("./output/afl")
        .stderr(process::Stdio::piped())
        .spawn()
        .expect("error creating afl workspace directory")
        .wait()
        .unwrap();

    // https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores
    let afl_modes = vec!["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];
    // TODO install afl if it's not already present
    for thread_num in 0..threads_mult {
        // We set the fuzzer name, and if it's the main or a secondary fuzzer
        let fuzzer_name = match thread_num {
            0 => String::from("-Mmainaflfuzzer"),
            n => format!("-Ssecondaryfuzzer{}", n),
        };
        let use_shared_corpus = match thread_num {
            0 => format!("-F{shared_corpus}"),
            _ => String::new(),
        };
        // A quarter of secondary fuzzers have the MOpt mutator enabled
        let mopt_mutator = match thread_num % 4 {
            1 => "-L0",
            _ => "",
        };
        // Power schedule
        let power_schedule = afl_modes.get(thread_num % afl_modes.len()).unwrap();
        // Old queue cycling
        let old_queue_cycling = match thread_num % 10 {
            9 => "-Z",
            _ => "",
        };
        // Banner to differentiate the statsd output
        let banner = match thread_num {
            0 => "-Tmain_fuzzer",
            _ => "",
        };

        fuzzer_handles.push(
            process::Command::new("cargo")
                .args(
                    [
                        "afl",
                        "fuzz",
                        &fuzzer_name,
                        &format!("-i{shared_corpus}"),
                        &format!("-p{power_schedule}"),
                        "-ooutput/afl",
                        banner,
                        &use_shared_corpus,
                        &format!("-V{}", minimization_timeout.as_secs()),
                        old_queue_cycling,
                        mopt_mutator,
                        &format!("./target/afl/debug/{target}"),
                    ]
                    .iter()
                    .filter(|a| a != &&""),
                )
                .env("AFL_BENCH_UNTIL_CRASH", "1")
                .env("AFL_STATSD", "1")
                .env("AFL_STATSD_TAGS_FLAVOR", "dogstatsd")
                .env("AFL_AUTORESUME", "1")
                .env("AFL_TESTCACHE_SIZE", "100")
                .env("AFL_CMPLOG_ONLY_NEW", "1")
                .env("AFL_FAST_CAL", "1")
                .stdout(File::create(&format!("output/afl_{thread_num}.log")).unwrap())
                .stderr(File::create(&format!("output/afl_{thread_num}.log")).unwrap())
                .spawn()
                .expect("error starting afl fuzzer"),
        )
    }
    println!("{} afl           ", style("launched").green());

    // TODO install honggfuzz if it's not already present
    fuzzer_handles.push(
        process::Command::new("cargo")
            .args(&["hfuzz", "run", target])
            .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_WORKSPACE", "./output/honggfuzz")
            .env(
                "HFUZZ_RUN_ARGS",
                format!("--exit_upon_crash -i{shared_corpus} -n{threads_mult}"),
            )
            .stderr(File::create("./output/honggfuzz.log").unwrap())
            .stdout(File::create("./output/honggfuzz.log").unwrap())
            .spawn()
            .expect("error starting honggfuzz fuzzer"),
    );
    println!("{} honggfuzz              ", style("launched").green());

    fuzzer_handles
}

#[cfg(feature = "cli")]
fn fuzz_command(args: &clap::ArgMatches) {
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
        .expect("could not parse minimization timeout");
    let threads_mult = args
        .value_of("threads")
        .unwrap_or("1")
        .parse::<usize>()
        .expect("could not parse threads multipier");

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
    let mut buf = [0; 4096];

    let mut last_merge = Instant::now();

    loop {
        let thirty_fps = Duration::from_millis(33);
        thread::sleep(thirty_fps);

        // We retrieve the total_edged value from the fuzzer_stats file
        if total_edges.is_empty() {
            if let Ok(file) = File::open("./output/afl/mainaflfuzzer/fuzzer_stats") {
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

            for msg in String::from_utf8(v).unwrap().split_terminator('\n') {
                if !msg.contains("main_fuzzer") {
                    break;
                } else if msg.contains("corpus_count") {
                    corpus_count = String::from(msg[21..].split('|').next().unwrap_or_default());
                } else if msg.contains("edges_found") {
                    edges_found = String::from(msg[20..].split('|').next().unwrap_or_default());
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
                process.kill().unwrap();
            }

            term.write_line("now running minimization            ")
                .unwrap();
            term.write_line("          ....                      ")
                .unwrap();
            term.write_line("     please hold on                 ")
                .unwrap();

            process::Command::new("mv")
                .args(&[corpus, "./output/main_corpus"])
                .output()
                .expect("could not move shared_corpus to main_corpus directory");

            use glob::glob;

            for input in glob("./output/afl/**/queue/*").expect("failed to read glob pattern") {
                if let Ok(path) = input {
                    if path.is_file() {
                        fs::copy(
                            path.to_str().unwrap(),
                            format!(
                                "./output/main_corpus/{}",
                                path.file_name().unwrap().to_str().unwrap()
                            ),
                        )
                        .unwrap();
                    }
                }
            }

            let old_corpus_size = fs::read_dir("./output/main_corpus").unwrap().count();

            // TODO Can we run minimization + coverage report at the same time?
            minimize_corpus(target, "./output/main_corpus", corpus);

            let new_corpus_size = fs::read_dir(corpus).unwrap().count();

            process::Command::new("rm")
                .args(&["-r", "./output/main_corpus"])
                .output()
                .expect("could not remove main_corpus");

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
fn run_inputs(target: &str, inputs: &str) {
    process::Command::new(format!("./target/libfuzzer/debug/{target}"))
        .arg(inputs)
        .env("RUST_BACKTRACE", "full")
        .spawn()
        .expect("error starting libfuzzer runner")
        .wait()
        .expect("error during libfuzzer run");
}

#[cfg(feature = "cli")]
fn minimize_corpus(target: &str, input_corpus: &str, output_corpus: &str) {
    // AFL++ minimization
    process::Command::new("cargo")
        .args(&[
            "afl",
            "cmin",
            &format!("-i{input_corpus}"),
            &format!("-o{output_corpus}"),
            "--",
            &format!("./target/afl/debug/{target}"),
        ])
        .stderr(File::create("./output/minimization.log").unwrap())
        .stdout(File::create("./output/minimization.log").unwrap())
        .spawn()
        .expect("error launching corpus minimization")
        .wait()
        .expect("error waiting for corpus minimization");

    /*
    // HONGGFUZZ minimization
    process::Command::new("cargo")
        .args(&["hfuzz", "run", target])
        .env("RUSTFLAGS", "-Znew-llvm-pass-manager=no")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", format!("-i{} -M -Woutput/honggfuzz", corpus))
        .stderr(File::create("./output/minimization.log").unwrap())
        .stdout(File::create("./output/minimization.log").unwrap())
        .spawn()
        .expect("error launching corpus minimization")
        .wait()
        .expect("error waiting for corpus minimization");
    */
}

#[cfg(feature = "cli")]
fn build_command() {
    // TODO loop over fuzzer config objects

    let run = process::Command::new("cargo")
        .args(&["rustc", "--features=ziggy/libfuzzer-sys", "--target-dir=target/libfuzzer"])
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
            "--target-dir=target/afl",
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
        .env("CARGO_TARGET_DIR", "./target/honggfuzz")
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
