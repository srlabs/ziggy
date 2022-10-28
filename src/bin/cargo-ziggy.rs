#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use anyhow::{anyhow, Result};
#[cfg(feature = "cli")]
use clap::{Args, Parser, Subcommand};
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::UdpSocket,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

// Half an hour, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py#L54-L56
#[cfg(feature = "cli")]
pub const DEFAULT_MINIMIZATION_TIMEOUT: u32 = 30 * 60;

#[cfg(feature = "cli")]
pub const DEFAULT_CORPUS: &str = "./output/{target_name}/shared_corpus/";

#[cfg(feature = "cli")]
pub const DEFAULT_COVERAGE_DIR: &str = "./output/{target_name}/coverage/";

#[cfg(feature = "cli")]
pub const DEFAULT_MINIMIZATION_CORPUS: &str = "./output/{target_name}/minimized_corpus/";

// We want to make sure we don't mistake a minimization kill for a found crash
#[cfg(feature = "cli")]
const SECONDS_TO_WAIT_AFTER_KILL: u32 = 5;

#[cfg(feature = "cli")]
#[derive(Parser)]
#[clap(name = "cargo")]
#[clap(bin_name = "cargo")]
pub enum Cargo {
    #[clap(subcommand)]
    Ziggy(Ziggy),
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
#[clap(
    author,
    version,
    about = "A multi-fuzzer management utility for all of your Rust fuzzing needs 🧑‍🎤"
)]
pub enum Ziggy {
    /// Create a new fuzzing target
    Init(Init),

    /// Build the fuzzer and the runner binaries
    Build(Build),

    /// Fuzz targets using different fuzzers in parallel
    // #[clap(arg_required_else_help = true)]
    Fuzz(Fuzz),

    /// Run a specific input or a directory of inputs to analyze backtrace
    // #[clap(arg_required_else_help = true)]
    Run(Run),

    /// Minimize the input corpus using the given fuzzing target
    // #[clap(arg_required_else_help = true)]
    Minimize(Minimize),

    /// Generate code coverage information using the existing corpus
    // #[clap(arg_required_else_help = true)]
    Cover(Cover),
}

#[derive(Args)]
pub struct Init {}

#[derive(Args)]
pub struct Build {
    /// Skip building libfuzzer
    #[clap(long)]
    no_libfuzzer: bool,
}

#[derive(Args)]
pub struct Fuzz {
    /// Target to fuzz
    #[clap(value_name = "TARGET", default_value = "")]
    target: String,

    /// Shared corpus directory
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    corpus: PathBuf,

    /// Timeout before shared corpus minimization
    #[clap(short, long, value_name = "SECS", default_value_t = DEFAULT_MINIMIZATION_TIMEOUT)]
    minimization_timeout: u32,

    /// Number of jobs per fuzzer (total CPU usage will be 3xNUM CPUs)
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,

    /// Timeout for a single run
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,

    /// Dictionary file (format:http://llvm.org/docs/LibFuzzer.html#dictionaries)
    #[clap(short = 'x', long = "dict", value_name = "FILE")]
    dictionary: Option<PathBuf>,

    /// Skip running libfuzzer
    #[clap(long)]
    no_libfuzzer: bool,
}

#[derive(Args)]
pub struct Run {
    /// Target to use
    #[clap(value_name = "TARGET", default_value = "")]
    target: String,

    /// Input directories and/or files to run
    #[clap(value_name = "DIR", default_value = DEFAULT_CORPUS)]
    inputs: Vec<PathBuf>,
}

#[derive(Args)]
pub struct Minimize {
    /// Target to use
    #[clap(value_name = "TARGET", default_value = "")]
    target: String,

    /// Corpus directory to minimize
    #[clap(short, long, default_value = DEFAULT_CORPUS)]
    input_corpus: PathBuf,

    /// Output directory
    #[clap(short, long, default_value = DEFAULT_MINIMIZATION_CORPUS)]
    output_corpus: PathBuf,
}

#[derive(Args)]
pub struct Cover {
    /// Target to generate coverage for
    #[clap(value_name = "TARGET", default_value = "")]
    target: String,
    /// Corpus directory to run target on
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    corpus: PathBuf,
    /// Output directory for code coverage report
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_COVERAGE_DIR)]
    output: PathBuf,
}

#[cfg(feature = "cli")]
fn main() {
    let Cargo::Ziggy(command) = Cargo::parse();
    match command {
        Ziggy::Init(_) => {
            todo!("Please see the examples directory");
        }
        Ziggy::Build(args) => {
            build_fuzzers(args.no_libfuzzer).expect("failure while building fuzzers");
        }
        Ziggy::Fuzz(mut args) => {
            args.target = get_target(args.target);
            build_fuzzers(args.no_libfuzzer).expect("failure while building fuzzers");
            run_fuzzers(&args).expect("failure while fuzzing");
        }
        Ziggy::Run(mut args) => {
            args.target = get_target(args.target);
            run_inputs(&args.target, &args.inputs).expect("failure while running input")
        }
        Ziggy::Minimize(mut args) => {
            args.target = get_target(args.target);
            minimize_corpus(&args.target, &args.input_corpus, &args.output_corpus)
                .expect("failure while running minimizer")
        }
        Ziggy::Cover(mut args) => {
            args.target = get_target(args.target);
            generate_coverage(&args.target, &args.corpus, &args.output)
                .expect("failure while running coverage generation")
        }
    }
}

#[cfg(feature = "cli")]
fn get_target(target: String) -> String {
    // If the target is already set, we're done here
    if !target.is_empty() {
        println!("    Using given target {target}\n");
        return target;
    }

    fn get_new_target() -> Result<String> {
        let cargo_toml_string = fs::read_to_string("Cargo.toml")?;
        let cargo_toml = cargo_toml_string.parse::<toml::Value>()?;
        if let Some(bin_section) = cargo_toml.get("bin") {
            let bin_array = bin_section
                .as_array()
                .ok_or_else(|| anyhow!("bin section should be an array in Cargo.toml"))?;
            // If one of the bin targets uses main, we use this target
            for bin_target in bin_array {
                if bin_target["path"]
                    .as_str()
                    .expect("path should be a string in Cargo.toml")
                    == "src/main.rs"
                {
                    return Ok(bin_target["name"]
                        .as_str()
                        .ok_or_else(|| anyhow!("bin name should be a string in Cargo.toml"))?
                        .to_string());
                }
            }
        }
        // src/main.rs exists, and either the bin array was empty, or it did not specify the main.rs bin target,
        // so we use the name of the project as target.
        if std::path::Path::new("src/main.rs").exists() {
            return Ok(cargo_toml["package"]["name"]
                .as_str()
                .ok_or_else(|| anyhow!("package name should be a string in Cargo.toml"))?
                .to_string());
        }
        Err(anyhow!("please specify a target"))
    }

    let new_target_result = get_new_target();

    match new_target_result {
        Ok(new_target) => {
            println!("    Using target {new_target}\n");
            new_target
        }
        Err(err) => {
            println!("    Target is not obvious, {err}\n");
            std::process::exit(0);
        }
    }
}

// This method will build our fuzzers
#[cfg(feature = "cli")]
fn build_fuzzers(no_libfuzzer: bool) -> Result<()> {
    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    // First fuzzer we build: LibFuzzer
    // We do not build it if asked not to
    if !no_libfuzzer {
        println!("    {} libfuzzer", style("Building").red().bold());

        // User-provided flags can replace the default libfuzzer rustflags
        let rustflags = match env::var("LIBFUZZER_RUSTFLAGS") {
            Ok(flags) => flags,
            Err(_) => "\
                -Cpasses=sancov-module \
                -Zsanitizer=address \
                -Cllvm-args=-sanitizer-coverage-level=4 \
                -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
                -Cllvm-args=-sanitizer-coverage-pc-table \
                --cfg=fuzzing \
                "
            .to_string(),
        };

        let rustup_command = process::Command::new("rustup")
            .args(["show", "active-toolchain"])
            .output()?;
        let rust_target = std::str::from_utf8(&rustup_command.stdout)?
            .split(' ')
            .next()
            .ok_or("Could not get rustup active toolchain")
            .unwrap_or("nightly-x86_64-unknown-linux-gnu")
            .strip_prefix("nightly-")
            .ok_or_else(|| {
                anyhow!("You should be using rust nightly if you want to use libfuzzer")
            })?;

        // We run the compilation command
        let run = process::Command::new(cargo.clone())
            .args([
                "rustc",
                "--features=ziggy/libfuzzer-sys",
                "--target-dir=target/libfuzzer",
                &format!("--target={rust_target}"),
            ])
            .env("RUSTFLAGS", rustflags)
            .spawn()?
            .wait()?;

        if !run.success() {
            return Err(anyhow!(
                "error building libfuzzer fuzzer: Exited with {:?}",
                run.code()
            ));
        }

        println!("    {} libfuzzer", style("Finished").cyan().bold());
    }

    println!("    {} afl", style("Building").red().bold());

    // Second fuzzer we build: AFL++
    let run = process::Command::new(cargo.clone())
        .args([
            "afl",
            "build",
            "--features=ziggy/afl",
            "--target-dir=target/afl",
        ])
        .env("AFL_QUIET", "1")
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(anyhow!(
            "error building afl fuzzer: Exited with {:?}",
            run.code()
        ));
    }

    println!("    {} afl", style("Finished").cyan().bold());

    println!("    {} honggfuzz", style("Building").red().bold());

    // Third fuzzer we build: Honggfuzz
    let run = process::Command::new(cargo)
        .args(["hfuzz", "build"])
        .env("CARGO_TARGET_DIR", "./target/honggfuzz")
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .stdout(process::Stdio::piped())
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(anyhow!(
            "error building honggfuzz fuzzer: Exited with {:?}",
            run.code()
        ));
    }

    println!("    {} honggfuzz", style("Finished").cyan().bold());

    Ok(())
}

// Manages the continuous running of fuzzers
#[cfg(feature = "cli")]
fn run_fuzzers(args: &Fuzz) -> Result<()> {
    let (mut processes, mut statsd_port) = spawn_new_fuzzers(args)?;

    let parsed_corpus = args
        .corpus
        .display()
        .to_string()
        .replace("{target_name}", &args.target);

    let term = Term::stdout();

    // Variables for stats printing
    let mut execs_per_sec = String::new();
    let mut execs_done = String::new();
    let mut corpus_count = String::new();
    let mut edges_found = String::new();
    let mut total_edges = String::new();
    let mut cycles_wo_finds = String::new();
    let mut cycle_done = String::new();
    let mut saved_crashes = String::new();
    let mut total_crashes = String::new();

    // We connect to the afl statsd socket
    let mut socket = UdpSocket::bind(("127.0.0.1", statsd_port))?;
    socket.set_nonblocking(true)?;
    let mut buf = [0; 4096];

    let mut last_merge = Instant::now();

    loop {
        let sleep_duration = Duration::from_millis(100);
        thread::sleep(sleep_duration);

        // We retrieve the total_edges value from the fuzzer_stats file
        if let Ok(file) = File::open(format!(
            "./output/{}/afl/mainaflfuzzer/fuzzer_stats",
            args.target
        )) {
            total_edges = String::from(
                BufReader::new(file)
                    .lines()
                    .nth(31)
                    .unwrap_or(Ok(String::new()))
                    .unwrap_or_default()
                    .trim_start_matches("total_edges       : "),
            );
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
                } else if msg.contains("saved_crashes") {
                    saved_crashes = String::from(msg[22..].split('|').next().unwrap_or_default());
                } else if msg.contains("total_crashes") {
                    total_crashes = String::from(msg[22..].split('|').next().unwrap_or_default());
                } else if msg.contains("execs_per_sec") {
                    execs_per_sec = String::from(msg[22..].split('|').next().unwrap_or_default());
                } else if msg.contains("execs_done") {
                    execs_done = String::from(msg[19..].split('|').next().unwrap_or_default());
                } else if msg.contains("cycles_wo_finds") {
                    cycles_wo_finds = String::from(msg[24..].split('|').next().unwrap_or_default());
                } else if msg.contains("cycle_done") {
                    cycle_done = String::from(msg[19..].split('|').next().unwrap_or_default());
                }
            }

            // We print the new values
            term.move_cursor_up(9)?;
            term.write_line(&format!(
                "{} {}",
                style("       execs per sec :").dim(),
                &execs_per_sec
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("          execs done :").dim(),
                &execs_done
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("        corpus count :").dim(),
                &corpus_count
            ))?;
            let edges_percentage = 100f64 * edges_found.parse::<f64>().unwrap_or_default()
                / total_edges.parse::<f64>().unwrap_or(1f64);
            term.write_line(&format!(
                "{} {} ({:.2}%)",
                style("         edges found :").dim(),
                &edges_found,
                &edges_percentage
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("          cycle done :").dim(),
                &cycle_done
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("cycles without finds :").dim(),
                &cycles_wo_finds
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("       saved crashes :").dim(),
                &saved_crashes
            ))?;
            term.write_line(&format!(
                "{} {}",
                style("       total crashes :").dim(),
                &total_crashes
            ))?;
            term.write_line("")?;
        }

        // Every DEFAULT_MINIMIZATION_TIMEOUT, we kill the fuzzers and minimize the shared corpus, before launching the fuzzers again
        if last_merge.elapsed() > Duration::from_secs(args.minimization_timeout.into()) {
            for mut process in processes {
                process.kill().ok();
                process.wait().ok();
            }

            term.write_line(&format!(
                "    {}",
                &style("Running minimization").magenta().bold()
            ))?;

            process::Command::new("mv")
                .args([
                    &parsed_corpus,
                    &format!("./output/{}/main_corpus", args.target),
                ])
                .output()
                .map_err(|_| anyhow!("could not move shared_corpus to main_corpus directory"))?;

            use glob::glob;

            for path in glob(&format!("./output/{}/afl/**/queue/*", args.target))
                .map_err(|_| anyhow!("failed to read glob pattern"))?
                .flatten()
            {
                if path.is_file() {
                    fs::copy(
                        path.to_str()
                            .ok_or_else(|| anyhow!("could not parse input path"))?,
                        format!(
                            "./output/{}/main_corpus/{}",
                            args.target,
                            path.file_name()
                                .ok_or_else(|| anyhow!("could not parse input file name"))?
                                .to_str()
                                .ok_or_else(|| anyhow!("could not parse input file name path"))?
                        ),
                    )?;
                }
            }

            let old_corpus_size = fs::read_dir(format!("./output/{}/main_corpus", args.target))
                .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

            match minimize_corpus(
                &args.target,
                &PathBuf::from(format!("./output/{}/main_corpus", args.target)),
                &args.corpus,
            ) {
                Ok(_) => {
                    let new_corpus_size = fs::read_dir(&parsed_corpus)
                        .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

                    process::Command::new("rm")
                        .args([
                            "-r",
                            &format!("./output/{}/main_corpus/", args.target),
                            &format!("./output/{}/afl/*/.synced/", args.target),
                            &format!("./output/{}/afl/*/_resume/", args.target),
                            &format!("./output/{}/afl/*/queue/", args.target),
                            &format!("./output/{}/afl/*/fuzzer_stats", args.target),
                            &format!("./output/{}/afl/*/.cur_input", args.target),
                        ])
                        .output()
                        .map_err(|_| anyhow!("could not remove main_corpus"))?;

                    term.move_cursor_up(1)?;
                    term.write_line(&format!(
                        "{} the corpus ({} -> {} files)             ",
                        style("    Minimized").magenta().bold(),
                        old_corpus_size,
                        new_corpus_size
                    ))?;
                }
                Err(_) => {
                    term.write_line("error running minimization... probably a memory error")?;

                    process::Command::new("mv")
                        .args([
                            &format!("./output/{}/main_corpus", args.target),
                            &parsed_corpus,
                        ])
                        .output()
                        .map_err(|_| {
                            anyhow!("could not move main_corpus to shared_corpus directory")
                        })?;
                }
            }

            // TODO Run coverage report here

            last_merge = Instant::now();

            (processes, statsd_port) = spawn_new_fuzzers(args)?;

            socket = UdpSocket::bind(("127.0.0.1", statsd_port))?;
            socket.set_nonblocking(true)?;
        }
    }
}

// Spawns new fuzzers
#[cfg(feature = "cli")]
fn spawn_new_fuzzers(args: &Fuzz) -> Result<(Vec<process::Child>, u16)> {
    let mut fuzzer_handles = vec![];

    let timeout_option = match args.timeout {
        Some(t) => format!("-timeout={t}"),
        None => String::new(),
    };

    let parsed_corpus = args
        .corpus
        .display()
        .to_string()
        .replace("{target_name}", &args.target);

    let _ = process::Command::new("mkdir")
        .args([
            "-p",
            &parsed_corpus,
            &format!("./output/{}/logs/", args.target),
        ])
        .stderr(process::Stdio::piped())
        .spawn()?
        .wait()?;

    // We create an initial corpus file, so that AFL++ starts-up properly
    let mut initial_corpus = File::create(parsed_corpus.clone() + "/init")?;
    writeln!(&mut initial_corpus, "00000000")?;
    drop(initial_corpus);

    if !args.no_libfuzzer {
        let _ = process::Command::new("mkdir")
            .args(["-p", &format!("./output/{}/libfuzzer", args.target)])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        let dictionary_option = match &args.dictionary {
            Some(d) => format!("-dict{}", &d.display().to_string()),
            None => String::new(),
        };

        let rustup_command = process::Command::new("rustup")
            .args(["show", "active-toolchain"])
            .output()?;
        let rust_target = std::str::from_utf8(&rustup_command.stdout)?
            .split(' ')
            .next()
            .ok_or("Could not get rustup active toolchain")
            .unwrap_or("nightly-x86_64-unknown-linux-gnu")
            .strip_prefix("nightly-")
            .ok_or_else(|| {
                anyhow!("You should be using rust nightly if you want to use libfuzzer")
            })?;

        fuzzer_handles.push(
            process::Command::new(fs::canonicalize(format!(
                "./target/libfuzzer/{}/debug/{}",
                rust_target, args.target,
            ))?)
            .args(
                [
                    fs::canonicalize(&parsed_corpus)?
                        .to_str()
                        .ok_or_else(|| anyhow!("could not parse shared corpus path"))?,
                    "--",
                    &format!(
                        "-artifact_prefix={}/",
                        fs::canonicalize(&parsed_corpus)?.display()
                    ),
                    &format!("-jobs={}", args.jobs),
                    "-ignore_crashes=1",
                    &format!(
                        "-max_total_time={}",
                        args.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL
                    ),
                    &timeout_option,
                    &dictionary_option,
                ]
                .iter()
                .filter(|a| a != &&""),
            )
            .current_dir(format!("./output/{}/libfuzzer", args.target))
            .stdout(File::create(format!(
                "./output/{}/logs/libfuzzer.log",
                args.target
            ))?)
            .stderr(File::create(format!(
                "./output/{}/logs/libfuzzer.log",
                args.target
            ))?)
            .spawn()?,
        );

        println!(
            "{} libfuzzer          ",
            style("    Launched").green().bold()
        );
    }

    let _ = process::Command::new("mkdir")
        .args(["-p", &format!("./output/{}/afl", args.target)])
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
    for job_num in 0..args.jobs {
        // We set the fuzzer name, and if it's the main or a secondary fuzzer
        let fuzzer_name = match job_num {
            0 => String::from("-Mmainaflfuzzer"),
            n => format!("-Ssecondaryfuzzer{}", n),
        };
        let use_shared_corpus = match job_num {
            0 => format!("-F{}", &parsed_corpus),
            _ => String::new(),
        };
        // A quarter of secondary fuzzers have the MOpt mutator enabled
        let mopt_mutator = match job_num % 4 {
            1 => "-L0",
            _ => "",
        };
        // Power schedule
        let power_schedule = afl_modes
            .get(job_num as usize % afl_modes.len())
            .unwrap_or(&"fast");
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
        let timeout_option_afl = match args.timeout {
            Some(t) => format!("-t{}", t * 1000),
            None => String::new(),
        };

        let dictionary_option = match &args.dictionary {
            Some(d) => format!("-x{}", &d.display().to_string()),
            None => String::new(),
        };

        fuzzer_handles.push(
            process::Command::new(cargo.clone())
                .args(
                    [
                        "afl",
                        "fuzz",
                        &fuzzer_name,
                        &format!("-i{}", &parsed_corpus,),
                        &format!("-p{power_schedule}"),
                        &format!("-ooutput/{}/afl", args.target),
                        banner,
                        &use_shared_corpus,
                        &format!(
                            "-V{}",
                            args.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL
                        ),
                        old_queue_cycling,
                        mopt_mutator,
                        &timeout_option_afl,
                        &dictionary_option,
                        &format!("./target/afl/debug/{}", args.target),
                    ]
                    .iter()
                    .filter(|a| a != &&""),
                )
                .env("AFL_STATSD", "1")
                .env("AFL_STATSD_TAGS_FLAVOR", "dogstatsd")
                .env("AFL_STATSD_PORT", format!("{statsd_port}"))
                .env("AFL_AUTORESUME", "1")
                .env("AFL_TESTCACHE_SIZE", "100")
                .env("AFL_CMPLOG_ONLY_NEW", "1")
                .env("AFL_FAST_CAL", "1")
                .env("AFL_MAP_SIZE", "10000000")
                .env("AFL_FORCE_UI", "1")
                .stdout(File::create(&format!(
                    "output/{}/logs/afl_{job_num}.log",
                    args.target
                ))?)
                .stderr(File::create(&format!(
                    "output/{}/logs/afl_{job_num}.log",
                    args.target
                ))?)
                .spawn()?,
        )
    }
    println!("{} afl           ", style("    Launched").green().bold());

    let dictionary_option = match &args.dictionary {
        Some(d) => format!("-w{}", &d.display().to_string()),
        None => String::new(),
    };

    // TODO install honggfuzz if it's not already present
    fuzzer_handles.push(
        process::Command::new(cargo)
            .args(["hfuzz", "run", &args.target])
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env(
                "HFUZZ_WORKSPACE",
                format!("./output/{}/honggfuzz", args.target),
            )
            .env(
                "HFUZZ_RUN_ARGS",
                format!(
                    "--run_time={} -i{} -n{} {timeout_option} {dictionary_option}",
                    args.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL,
                    &parsed_corpus,
                    args.jobs
                ),
            )
            .stderr(File::create(format!(
                "./output/{}/logs/honggfuzz.log",
                args.target
            ))?)
            .stdout(File::create(format!(
                "./output/{}/logs/honggfuzz.log",
                args.target
            ))?)
            .spawn()?,
    );
    println!(
        "{} honggfuzz              ",
        style("    Launched").green().bold()
    );

    println!(
        "\nSee more live info by running {}\n",
        style(format!("tail -f ./output/{}/logs/afl_0.log", args.target)).bold()
    );
    println!(
        "{}",
        &style("    AFL++ main process stats")
            .yellow()
            .bold()
            .to_string()
    );
    println!("\n");
    println!("    Waiting for afl++ to");
    println!("    finish executing the");
    println!("    existing corpus once");
    println!("\n\n\n");

    Ok((fuzzer_handles, statsd_port))
}

#[cfg(feature = "cli")]
fn run_inputs(target: &str, inputs: &[PathBuf]) -> Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    // We build the runner
    println!("    {} runner", style("Building").red().bold());

    // We run the compilation command
    let run = process::Command::new(cargo)
        .args([
            "rustc",
            "--features=ziggy/libfuzzer-sys",
            "--target-dir=target/runner",
        ])
        .env("RUSTFLAGS", "")
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(anyhow!(
            "error building libfuzzer runner: Exited with {:?}",
            run.code()
        ));
    }

    println!("    {} runner", style("Finished").cyan().bold());

    let mut args: Vec<String> = inputs
        .iter()
        .map(|x| x.display().to_string().replace("{target_name}", target))
        .collect();
    args.push("--".to_string());
    args.push("-runs=1".to_string());

    process::Command::new(format!("./target/runner/debug/{target}"))
        .args(args)
        .env("RUST_BACKTRACE", "full")
        .spawn()?
        .wait()?;

    Ok(())
}

#[cfg(feature = "cli")]
fn minimize_corpus(target: &str, input_corpus: &Path, output_corpus: &Path) -> Result<()> {
    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    // AFL++ minimization
    process::Command::new(cargo)
        .args([
            "afl",
            "cmin",
            &format!(
                "-i{}",
                input_corpus
                    .display()
                    .to_string()
                    .replace("{target_name}", target)
            ),
            &format!(
                "-o{}",
                output_corpus
                    .display()
                    .to_string()
                    .replace("{target_name}", target)
            ),
            "--",
            &format!("./target/afl/debug/{target}"),
        ])
        .env("AFL_MAP_SIZE", "10000000")
        .stderr(File::create(format!("./output/{target}/minimization.log"))?)
        .stdout(File::create(format!("./output/{target}/minimization.log"))?)
        .spawn()?
        .wait()?;

    /*
    // HONGGFUZZ minimization
    process::Command::new(cargo)
        .args(&["hfuzz", "run", target])
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", format!("-i{corpus} -M -Woutput/{target}/honggfuzz"))
        .stderr(File::create(format!("./output/{target}/minimization.log"))?)
        .stdout(File::create(format!("./output/{target}/minimization.log"))?)
        .spawn()?
        .wait()?;
    */

    Ok(())
}

#[cfg(feature = "cli")]
fn generate_coverage(target: &str, corpus: &Path, output: &Path) -> Result<()> {
    // We remove the previous coverage files
    process::Command::new("rm")
        .args(["-rf", "target/coverage/"])
        .spawn()?
        .wait()?;

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let libfuzzer_rustflags = env::var("LIBFUZZER_RUSTFLAGS").unwrap_or_else(|_| String::from("-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));

    // We build the libfuzzer runner with the appropriate flags for coverage
    process::Command::new(cargo)
        .args([
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
        .args([
            corpus
                .display()
                .to_string()
                .replace("{target_name}", target),
            "--".into(),
            "-runs=1".into(),
        ])
        .spawn()?
        .wait()?;

    // We generate the code coverage report
    process::Command::new("grcov")
        .args([
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
            &format!(
                "-o={}",
                output
                    .display()
                    .to_string()
                    .replace("{target_name}", target)
            ),
        ])
        .spawn()?
        .wait()?;

    Ok(())
}
