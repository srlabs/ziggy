#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
use anyhow::{anyhow, Context, Result};
#[cfg(feature = "cli")]
use clap::{Args, Parser, Subcommand};
#[cfg(feature = "cli")]
use console::{style, Term};
#[cfg(feature = "cli")]
use glob::glob;
#[cfg(feature = "cli")]
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::UdpSocket,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "cli")]
pub const DEFAULT_UNMODIFIED_TARGET: &str = "automatically guessed";

// Default time after which we share the corpora between the fuzzer instances and re-launch the fuzzers
// This is work in progress
// Set to 2 hour and 20 minutes, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/local/butler/scripts/setup.py#L52
#[cfg(feature = "cli")]
pub const _DEFAULT_FUZZ_TIMEOUT: u32 = 8400;

// Default time after which we minimize the corpus and re-launch the fuzzers
// Set to 22 hours, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/tasks/corpus_pruning_task.py#L61
#[cfg(feature = "cli")]
pub const DEFAULT_MINIMIZATION_TIMEOUT: u32 = 22 * 60 * 60;

#[cfg(feature = "cli")]
pub const DEFAULT_CORPUS: &str = "./output/{target_name}/shared_corpus/";

#[cfg(feature = "cli")]
pub const DEFAULT_COVERAGE_DIR: &str = "./output/{target_name}/coverage/";

#[cfg(feature = "cli")]
pub const DEFAULT_MINIMIZATION_CORPUS: &str = "./output/{target_name}/minimized_corpus/";

#[cfg(feature = "cli")]
pub const DEFAULT_PLOT_DIR: &str = "./output/{target_name}/plot/";

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
    /// Build the fuzzer and the runner binaries
    Build(Build),

    /// Fuzz targets using different fuzzers in parallel
    Fuzz(Fuzz),

    /// Run a specific input or a directory of inputs to analyze backtrace
    Run(Run),

    /// Minimize the input corpus using the given fuzzing target
    Minimize(Minimize),

    /// Generate code coverage information using the existing corpus
    Cover(Cover),

    /// Plot AFL++ data using afl-plot
    Plot(Plot),
}

#[derive(Args)]
pub struct Build {
    /// No honggfuzz (Fuzz only with AFL++)
    #[clap(long = "no-afl", action)]
    no_afl: bool,

    /// No AFL++ (Fuzz only with honggfuzz)
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,
}

#[derive(Args)]
pub struct Fuzz {
    /// Target to fuzz
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
    target: String,

    /// Shared corpus directory
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    corpus: PathBuf,

    /// Initial corpus directory (will only be read)
    #[clap(short, long, value_parser, value_name = "DIR")]
    initial_corpus: Option<PathBuf>,

    /// Timeout before shared corpus minimization
    #[clap(short, long, value_name = "SECS", default_value_t = DEFAULT_MINIMIZATION_TIMEOUT)]
    minimization_timeout: u32,

    /// Number of concurent fuzzing jobs
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,

    /// Timeout for a single run
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,

    /// Dictionary file (format:http://llvm.org/docs/LibFuzzer.html#dictionaries)
    #[clap(short = 'x', long = "dict", value_name = "FILE")]
    dictionary: Option<PathBuf>,

    /// Maximum length of input
    #[clap(short = 'G', long = "maxlength", default_value_t = 1048576)]
    max_length: u64,

    /// Minimum length of input (AFL++ only)
    #[clap(short = 'g', long = "minlength", default_value_t = 1)]
    min_length: u64,

    /// No honggfuzz (Fuzz only with AFL++)
    #[clap(long = "no-afl", action)]
    no_afl: bool,

    /// No AFL++ (Fuzz only with honggfuzz)
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,
}

#[derive(Args)]
pub struct Run {
    /// Target to use
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
    target: String,

    /// Maximum length of input
    #[clap(short = 'G', long = "maxlength", default_value_t = 1048576)]
    max_length: u64,

    /// Input directories and/or files to run
    #[clap(short, long, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    inputs: Vec<PathBuf>,
}

#[derive(Args)]
pub struct Minimize {
    /// Target to use
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
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
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
    target: String,
    /// Corpus directory to run target on
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    corpus: PathBuf,
    /// Output directory for code coverage report
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_COVERAGE_DIR)]
    output: PathBuf,
    /// Source directory of covered code
    #[clap(short, long, value_parser, value_name = "DIR", default_value = "$HOME")]
    source: PathBuf,
}

#[derive(Args)]
pub struct Plot {
    /// Target to generate plot for
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
    target: String,
    /// Name of AFL++ fuzzer to use as data source
    #[clap(short, long, value_name = "NAME", default_value = "mainaflfuzzer")]
    input: String,
    /// Output directory for plot
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_PLOT_DIR)]
    output: PathBuf,
}

#[cfg(feature = "cli")]
fn main() -> Result<(), anyhow::Error> {
    let Cargo::Ziggy(command) = Cargo::parse();
    match command {
        Ziggy::Build(args) => {
            build_fuzzers(args.no_afl, args.no_honggfuzz)
                .context("⚠️  failure while building fuzzers")?;
            Ok(())
        }
        Ziggy::Fuzz(mut args) => {
            args.target = get_target(args.target)?;
            build_fuzzers(args.no_afl, args.no_honggfuzz)
                .context("⚠️  failure while building fuzzers")?;
            run_fuzzers(&args).context("⚠️  failure running fuzzers: run_fuzzers")?;
            Ok(())
        }
        Ziggy::Run(mut args) => {
            args.target = get_target(args.target)?;
            run_inputs(&args).context("⚠️  failure running inputs: run_inputs")?;
            Ok(())
        }
        Ziggy::Minimize(mut args) => {
            args.target = get_target(args.target)?;
            minimize_corpus(&args.target, &args.input_corpus, &args.output_corpus)
                .context("⚠️  failure minimizing: minimize_corpus")?;
            Ok(())
        }
        Ziggy::Cover(mut args) => {
            args.target = get_target(args.target)?;
            generate_coverage(&args.target, &args.corpus, &args.output, &args.source)
                .context("⚠️  failure generating coverage: generate_coverage")?;
            Ok(())
        }
        Ziggy::Plot(mut args) => {
            args.target = get_target(args.target)?;
            generate_plot(&args.target, &args.input, &args.output)
                .context("⚠️  failure generating plot: generate_plot")?;
            Ok(())
        }
    }
}

#[cfg(feature = "cli")]
fn get_target(target: String) -> Result<String> {
    println!("📋  Guessing target");

    // If the target is already set, we're done here
    if target != DEFAULT_UNMODIFIED_TARGET {
        println!("    Using given target {target}\n");
        return Ok(target);
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
                    .context("path should be a string in Cargo.toml")?
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
            Ok(new_target)
        }
        Err(err) => Err(anyhow!("    Target is not obvious, {err}\n")),
    }
}

// This method will build our fuzzers
#[cfg(feature = "cli")]
fn build_fuzzers(no_afl: bool, no_honggfuzz: bool) -> Result<(), anyhow::Error> {
    // No fuzzers for you
    if no_afl && no_honggfuzz {
        return Err(anyhow!("⚠️  Pick at least one fuzzer"));
    }

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    println!("📋  Starting build command");

    if !no_afl {
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
            .wait()
            .context("⚠️  error spawning afl build command")?;

        if !run.success() {
            return Err(anyhow!(
                "error building afl fuzzer: Exited with {:?}",
                run.code()
            ));
        }

        println!("    {} afl", style("Finished").cyan().bold());
    }

    if !no_honggfuzz {
        println!("    {} honggfuzz", style("Building").red().bold());

        // Third fuzzer we build: Honggfuzz
        let run = process::Command::new(cargo)
            .args(["hfuzz", "build"])
            .env("CARGO_TARGET_DIR", "./target/honggfuzz")
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .stdout(process::Stdio::piped())
            .spawn()?
            .wait()
            .context("⚠️  error spawning hfuzz build command")?;

        if !run.success() {
            return Err(anyhow!(
                "error building honggfuzz fuzzer: Exited with {:?}",
                run.code()
            ));
        }

        println!("    {} honggfuzz", style("Finished").cyan().bold());
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn kill_subprocesses_recursively(pid: &str) -> Result<(), anyhow::Error> {
    println!("📋  Killing pid {pid}");

    let subprocesses = process::Command::new("pgrep")
        .arg(&format!("-P{pid}"))
        .output()?;

    for subprocess in std::str::from_utf8(&subprocesses.stdout)?.split('\n') {
        if subprocess.is_empty() {
            continue;
        }

        kill_subprocesses_recursively(subprocess)
            .context("⚠️  error in kill_subprocesses_recursively for pid {pid}")?;

        process::Command::new("kill")
            .arg(subprocess)
            .output()
            .context("⚠️  error killing subprocess: {subprocess}")?;
    }
    Ok(())
}

// Stop all fuzzer processes
#[cfg(feature = "cli")]
fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), anyhow::Error> {
    println!("📋  Stopping fuzzer processes");

    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
        process.kill()?;
        process.wait()?;
    }
    Ok(())
}

// Share AFL++ corpora in the shared_corpus directory
fn share_all_corpora(args: &Fuzz, parsed_corpus: &String) -> Result<()> {
    for path in glob(&format!("./output/{}/afl/**/queue/*", args.target))
        .map_err(|_| anyhow!("failed to read glob pattern"))?
        .flatten()
    {
        if path.is_file() {
            fs::copy(
                path.to_str()
                    .ok_or_else(|| anyhow!("could not parse input path"))?,
                format!(
                    "{}/{}",
                    &parsed_corpus,
                    path.file_name()
                        .ok_or_else(|| anyhow!("could not parse input file name"))?
                        .to_str()
                        .ok_or_else(|| anyhow!("could not parse input file name path"))?
                ),
            )?;
        }
    }
    Ok(())
}

// Manages the continuous running of fuzzers
#[cfg(feature = "cli")]
fn run_fuzzers(args: &Fuzz) -> Result<(), anyhow::Error> {
    println!("📋  Running fuzzer");

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
    println!("📋  Binding to afl statsd socket");
    let mut socket = UdpSocket::bind(("127.0.0.1", statsd_port))
        .context("⚠️  cannot bind to afl statsd socket")?;
    socket.set_nonblocking(true)?;
    let mut buf = [0; 4096];

    let mut last_merge = Instant::now();

    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    let ziggy_crash_dir = format!("./output/{}/crashes/{}/", args.target, time);
    let ziggy_crash_path = Path::new(&ziggy_crash_dir);

    fs::create_dir_all(ziggy_crash_path)?;

    let mut crash_has_been_found = false;

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

        if execs_per_sec.is_empty() {
            if let Ok(afl_log) =
                fs::read_to_string(format!("./output/{}/logs/afl.log", args.target))
            {
                if afl_log.contains("echo core >/proc/sys/kernel/core_pattern") {
                    stop_fuzzers(&mut processes)?;
                    println!("AFL++ needs you to run the following command before it can start fuzzing:\n");
                    println!("    echo core >/proc/sys/kernel/core_pattern");
                    println!();
                    return Ok(());
                }
                if afl_log.contains("cd /sys/devices/system/cpu") {
                    stop_fuzzers(&mut processes)?;
                    println!("AFL++ needs you to run the following commands before it can start fuzzing:\n");
                    println!("    cd /sys/devices/system/cpu");
                    println!("    echo performance | tee cpu*/cpufreq/scaling_governor");
                    println!();
                    return Ok(());
                }
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
            if saved_crashes.trim() != "0" && !saved_crashes.trim().is_empty() {
                crash_has_been_found = true;
            }

            // We print the new values
            term.move_cursor_up(11)?;
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
            if crash_has_been_found {
                term.write_line("\nCrashes have been found       ")?;
            } else {
                term.write_line("\nNo crash has been found so far")?;
            }
            term.write_line("")?;
        }

        // We only start checking for crashes after AFL++ has started responding to us
        if !execs_per_sec.is_empty() {
            // We check AFL++ and Honggfuzz's outputs for crash files
            let afl_crash_dir = format!("./output/{}/afl/mainaflfuzzer/crashes/", args.target);
            let honggfuzz_crash_dir =
                format!("./output/{}/honggfuzz/{}/", args.target, args.target);

            if let (Ok(afl_crashes), Ok(honggfuzz_crashes)) = (
                fs::read_dir(afl_crash_dir),
                fs::read_dir(honggfuzz_crash_dir),
            ) {
                for crash_input in afl_crashes.chain(honggfuzz_crashes).flatten() {
                    let file_name = crash_input.file_name();
                    let to_path = ziggy_crash_path.join(&file_name);
                    if to_path.exists()
                        || ["", "README.txt", "HONGGFUZZ.REPORT.TXT", "input"]
                            .contains(&file_name.to_str().unwrap_or_default())
                    {
                        continue;
                    }
                    fs::copy(crash_input.path(), to_path)?;
                }
            }
        }

        // Every DEFAULT_MINIMIZATION_TIMEOUT, we kill the fuzzers and minimize the shared corpus, before launching the fuzzers again
        if last_merge.elapsed() > Duration::from_secs(args.minimization_timeout.into()) {
            stop_fuzzers(&mut processes)?;

            term.write_line(&format!(
                "    {}",
                &style("Running minimization").magenta().bold()
            ))?;

            share_all_corpora(args, &parsed_corpus)?;

            let old_corpus_size = fs::read_dir(&parsed_corpus)
                .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

            let minimized_corpus =
                DEFAULT_MINIMIZATION_CORPUS.replace("{target_name}", &args.target);

            match minimize_corpus(
                &args.target,
                &PathBuf::from(&parsed_corpus),
                &PathBuf::from(&minimized_corpus),
            ) {
                Ok(_) => {
                    let new_corpus_size = fs::read_dir(&minimized_corpus)
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

                    fs::remove_dir_all(&parsed_corpus)?;
                    fs::rename(minimized_corpus, &parsed_corpus)?;
                }
                Err(_) => {
                    term.write_line("error running minimization... probably a memory error")?;
                }
            }

            last_merge = Instant::now();

            (processes, statsd_port) = spawn_new_fuzzers(args)?;

            socket = UdpSocket::bind(("127.0.0.1", statsd_port))?;
            socket.set_nonblocking(true)?;
        }
    }
}

// Spawns new fuzzers
#[cfg(feature = "cli")]
fn spawn_new_fuzzers(args: &Fuzz) -> Result<(Vec<process::Child>, u16), anyhow::Error> {
    // No fuzzers for you
    if args.no_afl && args.no_honggfuzz {
        return Err(anyhow!("⚠️  Pick at least one fuzzer"));
    }

    println!("📋  Spawning new fuzzers");

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

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let mut statsd_port = 8125;
    while UdpSocket::bind(("127.0.0.1", statsd_port)).is_err() {
        statsd_port += 1;
    }

    let (afl_jobs, honggfuzz_jobs) = {
        if args.no_afl {
            (0, args.jobs)
        } else if args.no_honggfuzz {
            (args.jobs, 0)
        } else if args.jobs > 6 {
            // If there are more than 6 jobs, we assign 3 to honggfuzz and the rest to AFL++
            (args.jobs - 3, 3)
        } else {
            // Otherwise, we assign half/half with priority to AFL++
            (args.jobs / 2 + args.jobs % 2, args.jobs / 2)
        }
    };

    if !args.no_afl {
        // We create an initial corpus file, so that AFL++ starts-up properly
        let mut initial_corpus = File::create(parsed_corpus.clone() + "/init")?;
        writeln!(&mut initial_corpus, "00000000")?;
        drop(initial_corpus);

        let _ = process::Command::new("mkdir")
            .args(["-p", &format!("./output/{}/afl", args.target)])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        // https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores
        let afl_modes = vec!["fast", "explore", "coe", "lin", "quad", "exploit", "rare"];

        for job_num in 0..afl_jobs {
            // We set the fuzzer name, and if it's the main or a secondary fuzzer
            let fuzzer_name = match job_num {
                0 => String::from("-Mmainaflfuzzer"),
                n => format!("-Ssecondaryfuzzer{n}"),
            };
            let use_shared_corpus = match job_num {
                0 => format!("-F{}", &parsed_corpus),
                _ => String::new(),
            };
            let use_initial_corpus_dir = match (&args.initial_corpus, job_num) {
                (Some(initial_corpus), 0) => format!("-F{}", &initial_corpus.display().to_string()),
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
            // Deterministic fuzzing
            let deterministic_fuzzing = match job_num % 7 {
                0 => "-D",
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

            // statsd is only enabled for the main instance
            let statsd_enabled = match job_num {
                0 => "1",
                _ => "0",
            };

            let log_destination = || match job_num {
                0 => File::create(format!("output/{}/logs/afl.log", args.target))
                    .unwrap()
                    .into(),
                _ => process::Stdio::null(),
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
                            &format!("-g{}", args.min_length),
                            &format!("-G{}", args.max_length),
                            banner,
                            &use_shared_corpus,
                            &use_initial_corpus_dir,
                            &format!(
                                "-V{}",
                                args.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL
                            ),
                            old_queue_cycling,
                            deterministic_fuzzing,
                            mopt_mutator,
                            &timeout_option_afl,
                            &dictionary_option,
                            &format!("./target/afl/debug/{}", args.target),
                        ]
                        .iter()
                        .filter(|a| a != &&""),
                    )
                    .env("AFL_STATSD", statsd_enabled)
                    .env("AFL_STATSD_TAGS_FLAVOR", "dogstatsd")
                    .env("AFL_STATSD_PORT", format!("{statsd_port}"))
                    .env("AFL_AUTORESUME", "1")
                    .env("AFL_TESTCACHE_SIZE", "100")
                    .env("AFL_CMPLOG_ONLY_NEW", "1")
                    .env("AFL_FAST_CAL", "1")
                    .env("AFL_MAP_SIZE", "10000000")
                    .env("AFL_FORCE_UI", "1")
                    .stdout(log_destination())
                    .stderr(log_destination())
                    .spawn()?,
            )
        }
        println!("{} afl           ", style("    Launched").green().bold());
    }

    if !args.no_honggfuzz {
        let dictionary_option = match &args.dictionary {
            Some(d) => format!("-w{}", &d.display().to_string()),
            None => String::new(),
        };

        // The `script` invocation is a trick to get the correct TTY output for honggfuzz
        fuzzer_handles.push(
            process::Command::new("script")
                .args([
                    "--flush",
                    "--quiet",
                    "-c",
                    &format!("{} hfuzz run {}", cargo, &args.target),
                    "/dev/null",
                ])
                .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                .env(
                    "HFUZZ_WORKSPACE",
                    format!("./output/{}/honggfuzz", args.target),
                )
                .env(
                    "HFUZZ_RUN_ARGS",
                    format!(
                        "--run_time={} -i{} -n{} -F{} {timeout_option} {dictionary_option}",
                        args.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL,
                        &parsed_corpus,
                        honggfuzz_jobs,
                        args.max_length,
                    ),
                )
                .stdin(std::process::Stdio::null())
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
    }

    println!(
        "\nSee more live info by running\n  {}\nor\n  {}\n",
        style(format!("tail -f ./output/{}/logs/afl.log", args.target)).bold(),
        style(format!(
            "tail -f ./output/{}/logs/honggfuzz.log",
            args.target
        ))
        .bold(),
    );
    println!(
        "{}",
        &style("    AFL++ main process stats")
            .yellow()
            .bold()
            .to_string()
    );
    println!("\n");
    println!("📋  Waiting for afl++ to");
    println!("📋  finish executing the");
    println!("📋  existing corpus once");
    println!("\n\n\n\n\n");

    Ok((fuzzer_handles, statsd_port))
}

#[cfg(feature = "cli")]
fn run_inputs(args: &Run) -> Result<(), anyhow::Error> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    // We build the runner
    println!("    {} runner", style("Building").red().bold());

    // We run the compilation command
    let run = process::Command::new(cargo)
        .args(["rustc", "--target-dir=target/runner"])
        .env("RUSTFLAGS", "")
        .spawn()?
        .wait()?;

    if !run.success() {
        return Err(anyhow!(
            "error building runner: Exited with {:?}",
            run.code()
        ));
    }

    println!("    {} runner", style("Finished").cyan().bold());
    println!("📋  Running inputs");
    let run_args: Vec<String> = args
        .inputs
        .iter()
        .map(|x| {
            x.display()
                .to_string()
                .replace("{target_name}", &args.target)
        })
        .collect();
    //run_args.push("--".to_string());
    //run_args.push("-runs=1 ".to_string());
    //run_args.push(format!("-max_len={}", args.max_length));

    process::Command::new(format!("./target/runner/debug/{}", args.target))
        .args(run_args)
        .env("RUST_BACKTRACE", "full")
        .spawn()?
        .wait()?;

    Ok(())
}

#[cfg(feature = "cli")]
fn minimize_corpus(
    target: &str,
    input_corpus: &Path,
    output_corpus: &Path,
) -> Result<(), anyhow::Error> {
    println!("📋  Minimizing corpus");

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
        .stderr(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .stdout(File::create(format!(
            "./output/{target}/logs/minimization.log"
        ))?)
        .spawn()?
        .wait()?;

    /*
    // HONGGFUZZ minimization
    process::Command::new(cargo)
        .args(&["hfuzz", "run", target])
        .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
        .env("HFUZZ_RUN_ARGS", format!("-i{corpus} -M -Woutput/{target}/honggfuzz"))
        .stderr(File::create(format!("./output/{target}/logs/minimization.log"))?)
        .stdout(File::create(format!("./output/{target}/logs/minimization.log"))?)
        .spawn()?
        .wait()?;
    */

    Ok(())
}

#[cfg(feature = "cli")]
fn generate_coverage(
    target: &str,
    corpus: &Path,
    output: &Path,
    source: &Path,
) -> Result<(), anyhow::Error> {
    println!("📋  Generating coverage");

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let coverage_rustflags = env::var("COVERAGE_RUSTFLAGS").unwrap_or_else(|_| String::from("-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));

    // We build the runner with the appropriate flags for coverage
    process::Command::new(cargo)
        .args(["rustc", "--target-dir=target/coverage"])
        .env("RUSTFLAGS", coverage_rustflags)
        .env("RUSTDOCFLAGS", "-Cpanic=abort")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTC_BOOTSTRAP", "1") // Trick to avoid forcing user to use rust nightly
        .spawn()?
        .wait()?;

    // We remove the previous coverage files
    if let Ok(gcda_files) = glob("target/coverage/debug/deps/*.gcda") {
        for file in gcda_files.flatten() {
            fs::remove_file(file)?;
        }
    }

    // We run the target against the corpus
    process::Command::new(format!("./target/coverage/debug/{target}"))
        .args([corpus
            .display()
            .to_string()
            .replace("{target_name}", target)])
        .spawn()?
        .wait()?;

    let source_str = match source.display().to_string().as_str() {
        "$HOME" => env::var("HOME").unwrap_or_else(|_| String::from(".")),
        s => s.to_string(),
    };

    let output_dir = output
        .display()
        .to_string()
        .replace("{target_name}", target);

    // We remove the previous coverage
    if let Err(error) = fs::remove_dir_all(&output_dir) {
        match error.kind() {
            std::io::ErrorKind::NotFound => {}
            e => return Err(anyhow!(e)),
        }
    };

    // We generate the code coverage report
    process::Command::new("grcov")
        .args([
            ".",
            &format!("-b=./target/coverage/debug/{target}"),
            &format!("-s={source_str}"),
            "-t=html",
            "--llvm",
            "--branch",
            "--ignore-not-existing",
            &format!("-o={output_dir}"),
        ])
        .spawn()?
        .wait()?;

    Ok(())
}

#[cfg(feature = "cli")]
fn generate_plot(target: &str, input: &String, output: &Path) -> Result<(), anyhow::Error> {
    println!("📋  Generating plot");

    // The cargo executable
    let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

    let fuzzer_data_dir = format!("./output/{target}/afl/{input}/");
    let fuzzer_output_dir = output
        .display()
        .to_string()
        .replace("{target_name}", target);

    // We run the afl-plot command
    process::Command::new(cargo)
        .args(["afl", "plot", &fuzzer_data_dir, &fuzzer_output_dir])
        .spawn()?
        .wait()?;

    Ok(())
}
