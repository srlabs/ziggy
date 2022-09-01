#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use clap::Command;
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader},
    net::UdpSocket,
    process, thread,
    time::{Duration, Instant},
};

// Half an hour, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py#L54-L56
#[cfg(feature = "cli")]
const DEFAULT_MINIMIZATION_TIMEOUT: &str = "1800";

// We want to make sure we don't mistake a minimization kill for a found crash
#[cfg(feature = "cli")]
const SECONDS_TO_WAIT_AFTER_KILL: u64 = 5;

#[cfg(feature = "cli")]
const DEFAULT_CORPUS: &str = "./output/shared_corpus/";

#[cfg(feature = "cli")]
const DEFAULT_COVERAGE_DIR: &str = "./output/coverage";

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
                    .about("Generate code coverage information using the existing corpus")
                    .arg(
                        clap::Arg::new("target")
                            .required(true)
                            .help("Target to generate coverage for"),
                    )
                    .arg(
                        clap::Arg::new("corpus")
                            .short('c')
                            .long("corpus")
                            .value_name("DIR")
                            .default_value(DEFAULT_CORPUS)
                            .help("Corpus directory to run target on"),
                    )
                    .arg(
                        clap::Arg::new("output")
                            .short('o')
                            .long("output")
                            .value_name("DIR")
                            .default_value(DEFAULT_COVERAGE_DIR)
                            .help("Output directory for code coverage report"),
                    ),
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
                            .default_value(DEFAULT_MINIMIZATION_TIMEOUT)
                            .help("Timeout before shared corpus minimization"),
                    )
                    .arg(
                        clap::Arg::new("jobs")
                            .short('j')
                            .long("jobs")
                            .value_name("NUM")
                            .default_value("1")
                            .help(
                                "Number of jobs per fuzzer (total CPU usage will be 3xNUM CPUs)",
                            ),
                    )
                    .arg(
                        clap::Arg::new("timeout")
                            .short('t')
                            .long("timeout")
                            .value_name("SECS")
                            .help("Timeout for a single run"),
                    )
                    .arg(
                        clap::Arg::new("dictionary")
                            .short('x')
                            .long("dict")
                            .value_name("FILE")
                            .help("Dictionary file (format:http://llvm.org/docs/LibFuzzer.html#dictionaries)"),
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
            .subcommand(Command::new("build").about("Build the fuzzer and the runner binaries")),
    )
}

#[cfg(feature = "cli")]
fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("ziggy", subcommand)) => match subcommand.subcommand() {
            Some(("cover", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let corpus = args.value_of("corpus").unwrap_or(DEFAULT_CORPUS);
                let output = args.value_of("output").unwrap_or(DEFAULT_COVERAGE_DIR);
                generate_coverage(target, corpus, output)
                    .expect("failure while running coverage generation");
            }
            Some(("fuzz", args)) => {
                build_command().expect("failure while building");
                fuzz_command(args).expect("failure while fuzzing");
            }
            Some(("init", _)) => {
                todo!();
            }
            Some(("run", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let inputs = args.value_of("inputs").unwrap_or(DEFAULT_CORPUS);
                run_inputs(target, inputs).expect("failure while running input");
            }
            Some(("build", _)) => {
                build_command().expect("failure while building");
            }
            Some(("minimize", args)) => {
                let target = args.value_of("target").expect("Could not parse target");
                let input_corpus = args.value_of("input-corpus").unwrap_or(DEFAULT_CORPUS);
                let output_corpus = args
                    .value_of("output-corpus")
                    .unwrap_or("./output/minimized_corpus");
                minimize_corpus(target, input_corpus, output_corpus)
                    .expect("failure while running minimizer");
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
    jobs_mult: usize,
    minimization_timeout: Duration,
    timeout: Option<u64>,
    dictionary: Option<&str>,
) -> Result<(Vec<process::Child>, u16), Box<dyn Error>> {
    // TODO loop over fuzzer config objects

    let mut fuzzer_handles = vec![];

    let _ = process::Command::new("mkdir")
        .args(&["-p", shared_corpus])
        .stderr(process::Stdio::piped())
        .spawn()?
        .wait()?;

    let _ = process::Command::new("mkdir")
        .args(&["-p", "./output/libfuzzer"])
        .stderr(process::Stdio::piped())
        .spawn()?
        .wait()?;

    let timeout_option = match timeout {
        Some(t) => format!("-timeout={t}"),
        None => String::new(),
    };

    let dictionary_option = match dictionary {
        Some(d) => format!("-dict{}", d),
        None => String::new(),
    };

    fuzzer_handles.push(
        process::Command::new(fs::canonicalize(format!(
            "./target/libfuzzer/debug/{target}"
        ))?)
        .args(
            [
                fs::canonicalize(shared_corpus)?
                    .to_str()
                    .ok_or("could not parse shared corpus path")?,
                "--",
                &format!(
                    "-artifact_prefix={}/",
                    fs::canonicalize(shared_corpus)?.display()
                ),
                &format!("-jobs={jobs_mult}"),
                &format!(
                    "-max_total_time={}",
                    minimization_timeout.as_secs() + SECONDS_TO_WAIT_AFTER_KILL
                ),
                &timeout_option,
                &dictionary_option,
            ]
            .iter()
            .filter(|a| a != &&""),
        )
        .current_dir("./output/libfuzzer")
        .stdout(File::create("./output/libfuzzer.log")?)
        .stderr(File::create("./output/libfuzzer.log")?)
        .spawn()?,
    );

    println!("{} libfuzzer          ", style("launched").green());

    let _ = process::Command::new("mkdir")
        .arg("./output/afl")
        .stderr(process::Stdio::piped())
        .spawn()?
        .wait()?;

    // https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores
    let afl_modes = vec!["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];

    let mut statsd_port = 8125;
    while UdpSocket::bind(("127.0.0.1", statsd_port)).is_err() {
        statsd_port += 1;
    }

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    // TODO install afl if it's not already present
    for job_num in 0..jobs_mult {
        // We set the fuzzer name, and if it's the main or a secondary fuzzer
        let fuzzer_name = match job_num {
            0 => String::from("-Mmainaflfuzzer"),
            n => format!("-Ssecondaryfuzzer{}", n),
        };
        let use_shared_corpus = match job_num {
            0 => format!("-F{shared_corpus}"),
            _ => String::new(),
        };
        // A quarter of secondary fuzzers have the MOpt mutator enabled
        let mopt_mutator = match job_num % 4 {
            1 => "-L0",
            _ => "",
        };
        // Power schedule
        let power_schedule = afl_modes.get(job_num % afl_modes.len()).unwrap_or(&"fast");
        // Old queue cycling
        let old_queue_cycling = match job_num % 10 {
            9 => "-Z",
            _ => "",
        };
        // Banner to differentiate the statsd output
        let banner = match job_num {
            0 => "-Tmain_fuzzer",
            _ => "",
        };

        // AFL timeout is in ms so we convert the value
        let timeout_option = match timeout {
            Some(t) => format!("-t{}", t * 1000),
            None => String::new(),
        };

        let dictionary_option = match dictionary {
            Some(d) => format!("-x{}", d),
            None => String::new(),
        };

        fuzzer_handles.push(
            process::Command::new(cargo.clone())
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
                        &format!(
                            "-V{}",
                            minimization_timeout.as_secs() + SECONDS_TO_WAIT_AFTER_KILL
                        ),
                        old_queue_cycling,
                        mopt_mutator,
                        &timeout_option,
                        &dictionary_option,
                        &format!("./target/afl/debug/{target}"),
                    ]
                    .iter()
                    .filter(|a| a != &&""),
                )
                .env("AFL_BENCH_UNTIL_CRASH", "1")
                .env("AFL_STATSD", "1")
                .env("AFL_STATSD_TAGS_FLAVOR", "dogstatsd")
                .env("AFL_STATSD_PORT", format!("{statsd_port}"))
                .env("AFL_AUTORESUME", "1")
                .env("AFL_TESTCACHE_SIZE", "100")
                .env("AFL_CMPLOG_ONLY_NEW", "1")
                .env("AFL_FAST_CAL", "1")
                .env("AFL_MAP_SIZE", "10000000")
                .stdout(File::create(&format!("output/afl_{job_num}.log"))?)
                .stderr(File::create(&format!("output/afl_{job_num}.log"))?)
                .spawn()?,
        )
    }
    println!("{} afl           ", style("launched").green());

    let dictionary_option = match dictionary {
        Some(d) => format!("-w{}", d),
        None => String::new(),
    };

    // TODO install honggfuzz if it's not already present
    fuzzer_handles.push(
        process::Command::new(cargo)
            .args(&["hfuzz", "run", target])
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_WORKSPACE", "./output/honggfuzz")
            .env(
                "HFUZZ_RUN_ARGS",
                format!("--run_time={} --exit_upon_crash -i{shared_corpus} -n{jobs_mult} {timeout_option} {dictionary_option}", minimization_timeout.as_secs() + SECONDS_TO_WAIT_AFTER_KILL),
            )
            .stderr(File::create("./output/honggfuzz.log")?)
            .stdout(File::create("./output/honggfuzz.log")?)
            .spawn()?,
    );
    println!("{} honggfuzz              ", style("launched").green());

    Ok((fuzzer_handles, statsd_port))
}

#[cfg(feature = "cli")]
fn fuzz_command(args: &clap::ArgMatches) -> Result<(), Box<dyn Error>> {
    let target = args.value_of("target").ok_or("could not parse target")?;
    let corpus = args.value_of("corpus").unwrap_or(DEFAULT_CORPUS);
    let minimization_timeout_str = args
        .value_of("min")
        .ok_or("could not parse minimization timeout")?;

    let minimization_timeout = Duration::from_secs(
        minimization_timeout_str
            .parse::<u64>()
            .map_err(|_| "could not parse minimization timeout")?,
    );

    let jobs_mult = args
        .value_of("jobs")
        .unwrap_or("1")
        .parse::<usize>()
        .map_err(|_| "could not parse jobs multipier")?;

    // Timeout can be undefined, so we keep an Option here
    let timeout = args
        .value_of("timeout")
        .map(|t| t.parse::<u64>())
        .transpose()?;

    // Dictionary can be undefined, so we keep an Option here
    let dictionary = args.value_of("dictionary");

    let (mut processes, statsd_port) = launch_fuzzers(
        target,
        corpus,
        jobs_mult,
        minimization_timeout,
        timeout,
        dictionary,
    )?;

    let term = Term::stdout();
    term.write_line(&style("afl++ stats").yellow().to_string())?;
    term.write_line("...")?;
    term.write_line("...")?;

    // Variables for stats printing
    let mut corpus_count = String::new();
    let mut edges_found = String::new();
    let mut total_edges = String::new();

    // We connect to the afl statsd socket
    let socket = UdpSocket::bind(("127.0.0.1", statsd_port))?;
    socket.set_nonblocking(true)?;
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

            for msg in String::from_utf8(v)?.split_terminator('\n') {
                if !msg.contains("main_fuzzer") {
                    break;
                } else if msg.contains("corpus_count") {
                    corpus_count = String::from(msg[21..].split('|').next().unwrap_or_default());
                } else if msg.contains("edges_found") {
                    edges_found = String::from(msg[20..].split('|').next().unwrap_or_default());
                }
            }

            // We print the new values
            term.move_cursor_up(2)?;
            term.write_line(&format!(
                "{} {}",
                style("corpus count :").dim(),
                &corpus_count
            ))?;
            let edges_percentage = 100f64 * edges_found.parse::<f64>().unwrap_or_default()
                / total_edges.parse::<f64>().unwrap_or(1f64);
            term.write_line(&format!(
                "{} {} ({:.2}%)",
                style(" edges found :").dim(),
                &edges_found,
                &edges_percentage
            ))?;
        }

        if processes
            .iter_mut()
            .all(|process| process.try_wait().unwrap_or(None).is_some())
        {
            break;
        }

        // Every DEFAULT_MINIMIZATION_TIMEOUT, we kill the fuzzers and minimize the shared corpus, before launching the fuzzers again
        if last_merge.elapsed() > minimization_timeout {
            for mut process in processes {
                process.kill().ok();
                process.wait().ok();
            }

            term.write_line("running minimization            ")?;

            process::Command::new("mv")
                .args(&[corpus, "./output/main_corpus"])
                .output()
                .map_err(|_| "could not move shared_corpus to main_corpus directory")?;

            use glob::glob;

            for path in glob("./output/afl/**/queue/*")
                .map_err(|_| "failed to read glob pattern")?
                .flatten()
            {
                if path.is_file() {
                    fs::copy(
                        path.to_str().ok_or("could not parse input path")?,
                        format!(
                            "./output/main_corpus/{}",
                            path.file_name()
                                .ok_or("could not parse input file name")?
                                .to_str()
                                .ok_or("could not parse input file name path")?
                        ),
                    )?;
                }
            }

            let old_corpus_size = fs::read_dir("./output/main_corpus")
                .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

            // TODO Can we run minimization + coverage report at the same time?
            match minimize_corpus(target, "./output/main_corpus", corpus) {
                Ok(_) => {
                    let new_corpus_size = fs::read_dir(corpus)
                        .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

                    process::Command::new("rm")
                        .args(&[
                            "-r",
                            "./output/main_corpus/",
                            "./output/afl/*/.synced/",
                            "./output/afl/*/_resume/",
                            "./output/afl/*/queue/",
                            "./output/afl/*/fuzzer_stats",
                            "./output/afl/*/.cur_input",
                        ])
                        .output()
                        .map_err(|_| "could not remove main_corpus")?;

                    term.move_cursor_up(1)?;
                    term.write_line(&format!(
                        "{} the corpus : {} -> {} files             ",
                        style("minimized").red(),
                        old_corpus_size,
                        new_corpus_size
                    ))?;
                }
                Err(_) => {
                    term.write_line("error running minimization... probably a memory error")?;

                    process::Command::new("mv")
                        .args(&["./output/main_corpus", corpus])
                        .output()
                        .map_err(|_| "could not move main_corpus to shared_corpus directory")?;
                }
            }

            last_merge = Instant::now();
            (processes, _) = launch_fuzzers(
                target,
                corpus,
                jobs_mult,
                minimization_timeout,
                timeout,
                dictionary,
            )?;

            term.write_line(&style("afl++ stats").yellow().to_string())?;
            term.write_line("...")?;
            term.write_line("...")?;
        }
    }

    term.write_line(&format!(
        "{} all fuzzers are done",
        style("finished").cyan()
    ))?;

    Ok(())
}

#[cfg(feature = "cli")]
fn run_inputs(target: &str, inputs: &str) -> Result<(), Box<dyn Error>> {
    process::Command::new(format!("./target/libfuzzer/debug/{target}"))
        .arg(inputs)
        .env("RUST_BACKTRACE", "full")
        .spawn()?
        .wait()?;

    Ok(())
}

#[cfg(feature = "cli")]
fn minimize_corpus(
    target: &str,
    input_corpus: &str,
    output_corpus: &str,
) -> Result<(), Box<dyn Error>> {
    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    // AFL++ minimization
    process::Command::new(cargo)
        .args(&[
            "afl",
            "cmin",
            &format!("-i{input_corpus}"),
            &format!("-o{output_corpus}"),
            "--",
            &format!("./target/afl/debug/{target}"),
        ])
        .env("AFL_MAP_SIZE", "10000000")
        .stderr(File::create("./output/minimization.log")?)
        .stdout(File::create("./output/minimization.log")?)
        .spawn()?
        .wait()?;

    /*
    // HONGGFUZZ minimization
    process::Command::new(cargo)
        .args(&["hfuzz", "run", target])
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", format!("-i{} -M -Woutput/honggfuzz", corpus))
        .stderr(File::create("./output/minimization.log")?)
        .stdout(File::create("./output/minimization.log")?)
        .spawn()?
        .wait()?;
    */

    Ok(())
}

#[cfg(feature = "cli")]
fn generate_coverage(target: &str, corpus: &str, output: &str) -> Result<(), Box<dyn Error>> {
    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let libfuzzer_rustflags = env::var("LIBFUZZER_RUSTFLAGS").unwrap_or_else(|_| String::from("-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));

    // We build the libfuzzer runner with the appropriate flags for coverage
    process::Command::new(cargo)
        .args(&[
            "rustc",
            "--features=ziggy/libfuzzer-sys",
            "--target-dir=target/coverage",
        ])
        .env("RUSTFLAGS", libfuzzer_rustflags)
        .env("RUSTDOCFLAGS", "-Cpanic=abort")
        .env("CARGO_INCREMENTAL", "0")
        .spawn()?
        .wait()?;

    // We run the target against the corpus
    process::Command::new(format!("./target/coverage/debug/{target}"))
        .arg(corpus)
        .spawn()?
        .wait()?;

    // We generate the code coverage report
    process::Command::new("grcov")
        .args(&[
            ".",
            &format!("-b=./target/coverage/debug/{target}"),
            &format!(
                "-s={}",
                env::var("HOME").unwrap_or_else(|_| String::from("."))
            ),
            "-t=html",
            "--llvm",
            "--branch",
            "--ignore-not-existing",
            &format!("-o={output}"),
        ])
        .spawn()?
        .wait()?;

    Ok(())
}

#[cfg(feature = "cli")]
fn build_command() -> Result<(), Box<dyn Error>> {
    // TODO loop over fuzzer config objects

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let libfuzzer_rustflags = env::var("LIBFUZZER_RUSTFLAGS").unwrap_or_else(|_| String::from("-Cpasses=sancov-module -Zsanitizer=address -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table"));

    let run = process::Command::new(cargo.clone())
        .args(&[
            "rustc",
            "--features=ziggy/libfuzzer-sys",
            "--target-dir=target/libfuzzer",
        ])
        .env("RUSTFLAGS", libfuzzer_rustflags)
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(Box::from(format!(
            "error building libfuzzer fuzzer: Exited with {:?}",
            run.code()
        )));
    }

    println!("{} libfuzzer and its target", style("built").blue());

    let run = process::Command::new(cargo.clone())
        .args(&[
            "afl",
            "build",
            "--features=ziggy/afl",
            "--target-dir=target/afl",
        ])
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(Box::from(format!(
            "error building afl fuzzer: Exited with {:?}",
            run.code()
        )));
    }

    println!("{} afl and its target", style("built").blue());

    let run = process::Command::new(cargo)
        .args(&["hfuzz", "build"])
        .env("CARGO_TARGET_DIR", "./target/honggfuzz")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(Box::from(format!(
            "error building honggfuzz fuzzer: Exited with {:?}",
            run.code()
        )));
    }

    println!("{} honggfuzz and its target", style("built").blue());

    Ok(())
}
