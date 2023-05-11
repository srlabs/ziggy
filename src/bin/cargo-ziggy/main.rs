#[cfg(not(feature = "cli"))]
fn main() {}

#[cfg(feature = "cli")]
mod build;
#[cfg(feature = "cli")]
mod coverage;
#[cfg(feature = "cli")]
mod fuzz;
#[cfg(feature = "cli")]
mod minimize;
#[cfg(feature = "cli")]
mod plot;
#[cfg(feature = "cli")]
mod run;
#[cfg(feature = "cli")]
mod utils;

#[cfg(feature = "cli")]
use anyhow::{anyhow, Context, Result};
#[cfg(feature = "cli")]
use clap::{Args, Parser, Subcommand};
#[cfg(feature = "cli")]
use std::{fs, path::PathBuf};

#[cfg(feature = "cli")]
#[macro_use]
extern crate log;

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
    #[clap(short, long, value_parser, value_name = "DIR")]
    source: Option<PathBuf>,
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
    env_logger::init();
    let Cargo::Ziggy(command) = Cargo::parse();
    match command {
        Ziggy::Build(args) => {
            build::build_fuzzers(args.no_afl, args.no_honggfuzz)
                .context("Failure building fuzzers")?;
            Ok(())
        }
        Ziggy::Fuzz(mut args) => {
            args.target = get_target(args.target)?;
            build::build_fuzzers(args.no_afl, args.no_honggfuzz)
                .context("Failure while building fuzzers")?;
            fuzz::run_fuzzers(&args).context("Failure running fuzzers")?;
            Ok(())
        }
        Ziggy::Run(mut args) => {
            args.target = get_target(args.target)?;
            run::run_inputs(&args).context("Failure running inputs")?;
            Ok(())
        }
        Ziggy::Minimize(mut args) => {
            args.target = get_target(args.target)?;
            minimize::minimize_corpus(&args.target, &args.input_corpus, &args.output_corpus)
                .context("Failure minimizing")?;
            Ok(())
        }
        Ziggy::Cover(mut args) => {
            args.target = get_target(args.target)?;
            coverage::generate_coverage(&args.target, &args.corpus, &args.output, args.source)
                .context("Failure generating coverage")?;
            Ok(())
        }
        Ziggy::Plot(mut args) => {
            args.target = get_target(args.target)?;
            plot::generate_plot(&args.target, &args.input, &args.output)
                .context("Failure generating plot")?;
            Ok(())
        }
    }
}

#[cfg(feature = "cli")]
fn get_target(target: String) -> Result<String> {
    info!("Guessing target");

    // If the target is already set, we're done here
    if target != DEFAULT_UNMODIFIED_TARGET {
        eprintln!("    Using given target {target}\n");
        return Ok(target);
    }

    fn get_new_target() -> Result<String> {
        let cargo_toml_string = fs::read_to_string("Cargo.toml")?;
        let cargo_toml = cargo_toml_string.parse::<toml::Value>()?;
        if let Some(bin_section) = cargo_toml.get("bin") {
            let bin_array = bin_section
                .as_array()
                .ok_or_else(|| anyhow!("Bin section should be an array in Cargo.toml"))?;
            // If one of the bin targets uses main, we use this target
            for bin_target in bin_array {
                if bin_target["path"]
                    .as_str()
                    .context("Path should be a string in Cargo.toml")?
                    == "src/main.rs"
                {
                    return Ok(bin_target["name"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Bin name should be a string in Cargo.toml"))?
                        .to_string());
                }
            }
        }
        // src/main.rs exists, and either the bin array was empty, or it did not specify the main.rs bin target,
        // so we use the name of the project as target.
        if std::path::Path::new("src/main.rs").exists() {
            return Ok(cargo_toml["package"]["name"]
                .as_str()
                .ok_or_else(|| anyhow!("Package name should be a string in Cargo.toml"))?
                .to_string());
        }
        Err(anyhow!("Please specify a target"))
    }

    let new_target_result = get_new_target();

    match new_target_result {
        Ok(new_target) => {
            eprintln!("    Using target {new_target}\n");
            Ok(new_target)
        }
        Err(err) => Err(anyhow!("    Target is not obvious, {err}\n")),
    }
}
