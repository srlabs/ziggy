#[cfg(not(feature = "cli"))]
fn main() {}

mod addseeds;
mod build;
mod coverage;
mod fuzz;
mod minimize;
mod plot;
mod run;
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

pub const DEFAULT_UNMODIFIED_TARGET: &str = "automatically guessed";

// Default time after which we share the corpora between the fuzzer instances and re-launch the fuzzers
// This is work in progress
// Set to 2 hour and 20 minutes, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/local/butler/scripts/setup.py#L52
// marc: this makes only sense for honggfuzz. AFL++ can learn honggfuzz's
// findings on the fly with the right command line parameter which is more
// effective
pub const _DEFAULT_FUZZ_TIMEOUT: u32 = 8400;

// Default time after which we minimize the corpus and re-launch the fuzzers
// Set to 22 hours, like in clusterfuzz
// See https://github.com/google/clusterfuzz/blob/52f28f83a0422e9a7026a215732876859e4b267b/src/clusterfuzz/_internal/bot/tasks/corpus_pruning_task.py#L61
// marc: another thing that is not a good idea IMHO. has anyone tested if this
// actually improving the fuzzing?
pub const DEFAULT_MINIMIZATION_TIMEOUT: u32 = 22 * 60 * 60;

pub const DEFAULT_CORPUS: &str = "./output/{target_name}/shared_corpus/";

pub const DEFAULT_COVERAGE_DIR: &str = "./output/{target_name}/coverage/";

pub const DEFAULT_MINIMIZATION_CORPUS: &str = "./output/{target_name}/minimized_corpus/";

pub const DEFAULT_PLOT_DIR: &str = "./output/{target_name}/plot/";

// We want to make sure we don't mistake a minimization kill for a found crash
const SECONDS_TO_WAIT_AFTER_KILL: u32 = 5;

#[derive(Parser)]
#[clap(name = "cargo")]
#[clap(bin_name = "cargo")]
pub enum Cargo {
    #[clap(subcommand)]
    Ziggy(Ziggy),
}

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

    /// Add seeds to the running AFL fuzzers
    AddSeeds(AddSeeds),
}

#[derive(Args)]
pub struct Build {
    /// No AFL++ (Fuzz only with honggfuzz)
    #[clap(long = "no-afl", action)]
    no_afl: bool,

    /// No honggfuzz (Fuzz only with AFL++)
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

    /// No AFL++ (Fuzz only with honggfuzz)
    #[clap(long = "no-afl", action)]
    no_afl: bool,

    /// No honggfuzz (Fuzz only with AFL++)
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,

    /// Skip initial minimization
    #[clap(long = "skip-initial-minimization", action)]
    skip_initial_minimization: bool,
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

    /// Number of concurent minimizing jobs
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,
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

#[derive(Args)]
pub struct AddSeeds {
    /// Target to use
    #[clap(value_name = "TARGET", default_value = DEFAULT_UNMODIFIED_TARGET)]
    target: String,
    /// Seeds directory to be added
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS)]
    input: PathBuf,
}

#[cfg(feature = "cli")]
fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let Cargo::Ziggy(command) = Cargo::parse();

    match command {
        Ziggy::Build(args) => args.build().context("Failed to build the fuzzers"),
        Ziggy::Fuzz(mut args) => args.fuzz().context("Failure running fuzzers"),
        Ziggy::Run(args) => args.run().context("Failure running inputs"),
        Ziggy::Minimize(mut args) => args.minimize().context("Failure running minimization"),
        Ziggy::Cover(mut args) => args
            .generate_coverage()
            .context("Failure generating coverage"),
        Ziggy::Plot(mut args) => args.generate_plot().context("Failure generating plot"),
        Ziggy::AddSeeds(mut args) => args.add_seeds().context("Add seeds to running fuzzer"),
    }
}

pub fn find_target(target: &String) -> Result<String> {
    // If the target is already set, we're done here
    if target != DEFAULT_UNMODIFIED_TARGET {
        eprintln!("    Using given target {target}");
        return Ok(target.into());
    }

    info!("Guessing target");

    let new_target_result = guess_target();

    if let Ok(ref new_target) = new_target_result {
        eprintln!("    Using target {new_target}");
    }

    new_target_result.context("Target is not obvious")
}

fn guess_target() -> Result<String> {
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
