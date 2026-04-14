mod add_seeds;
mod build;
mod clean;
mod coverage;
mod fuzz;
mod minimize;
mod plot;
mod run;
mod triage;
mod util;

use crate::fuzz::FuzzingConfig;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    path::PathBuf,
    sync::OnceLock,
    sync::{Arc, atomic::AtomicBool},
};

pub const DEFAULT_UNMODIFIED_TARGET: &str = "automatically guessed";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum FuzzingEngines {
    All,
    AFLPlusPlus,
    Honggfuzz,
}

pub const DEFAULT_OUTPUT_DIR: &str = "./output";

pub const DEFAULT_CORPUS_DIR: &str = "{ziggy_output}/{target_name}/corpus/";

pub const DEFAULT_COVERAGE_DIR: &str = "{ziggy_output}/{target_name}/coverage/";

pub const DEFAULT_MINIMIZATION_DIR: &str = "{ziggy_output}/{target_name}/corpus_minimized/";

pub const DEFAULT_PLOT_DIR: &str = "{ziggy_output}/{target_name}/plot/";

pub const DEFAULT_CRASHES_DIR: &str = "{ziggy_output}/{target_name}/crashes/";

pub const DEFAULT_TRIAGE_DIR: &str = "{ziggy_output}/{target_name}/triage/";

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

    /// Add seeds to the running AFL++ fuzzers
    AddSeeds(AddSeeds),

    /// Triage crashes found with CASR - currently only works for AFL++
    Triage(Triage),

    /// Remove generated artifacts from the target directory
    Clean(Clean),
}

#[derive(Args)]
pub struct Build {
    /// Target to build
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// No AFL++ (Fuzz only with honggfuzz)
    #[clap(long = "no-afl", action)]
    no_afl: bool,

    /// No honggfuzz (Fuzz only with AFL++)
    #[clap(long = "no-honggfuzz", action)]
    no_honggfuzz: bool,

    /// Compile in release mode (--release)
    #[clap(long = "release", action)]
    release: bool,

    /// Build with ASAN (nightly only)
    #[clap(long = "asan", action)]
    asan: bool,
}

#[derive(Args)]
pub struct Fuzz {
    /// Target to fuzz
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Shared corpus directory
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS_DIR)]
    corpus: PathBuf,

    /// Initial corpus directory (will only be read)
    #[clap(short, long, value_parser, value_name = "DIR")]
    initial_corpus: Option<PathBuf>,

    /// Compile in release mode (--release)
    #[clap(long = "release", action)]
    release: bool,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,

    /// Number of concurrent fuzzing jobs
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,

    /// Timeout for a single run
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,

    /// Memory limit for the fuzz target. (If fuzzing with honggfuzz, a numeric value in MiB must be specified)
    #[clap(short, long, value_name = "STRING")]
    memory_limit: Option<String>,

    /// Perform initial minimization
    #[clap(short = 'M', long, action, default_value_t = false)]
    minimize: bool,

    /// Dictionary file (format:<http://llvm.org/docs/LibFuzzer.html#dictionaries>)
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

    // This value helps us create a global timer for our display
    #[clap(skip = std::time::Instant::now())]
    start_time: std::time::Instant,

    /// Pass flags to AFL++ directly
    #[clap(short, long)]
    afl_flags: Vec<String>,

    /// AFL++ configuration
    #[clap(short = 'C', long, default_value = "generic")]
    config: FuzzingConfig,

    /// With a coverage worker
    #[clap(long)]
    coverage_worker: bool,

    /// Coverage generation interval in minutes
    #[clap(long, default_value = "15")]
    coverage_interval: u64,

    /// Corpus sync interval in minutes
    #[clap(long, default_value = "10")]
    corpus_sync_interval: u64,

    /// Fuzz an already AFL++ instrumented binary; the ziggy way
    #[clap(short, long)]
    binary: Option<PathBuf>,

    /// Build with ASAN (nightly only)
    #[clap(long = "asan", action)]
    asan: bool,

    /// Foreign fuzzer directories to sync with (AFL++ -F option)
    #[clap(long = "foreign-sync", short = 'F', action)]
    foreign_sync_dirs: Vec<PathBuf>,
}

#[derive(Args)]
pub struct Run {
    /// Target to use
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Input directories and/or files to run
    #[clap(short, long, value_name = "DIR", default_value = DEFAULT_CORPUS_DIR)]
    inputs: Vec<PathBuf>,

    /// Recursively run nested directories for all input directories
    #[clap(short, long)]
    recursive: bool,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,

    /// Build with ASAN (nightly only)
    #[clap(long = "asan", action)]
    asan: bool,

    /// Activate these features on the target
    #[clap(short = 'F', long, num_args = 0..)]
    features: Vec<String>,

    /// Timeout for a single run
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,

    /// Stop the run after the first crash is encountered
    #[clap(short = 'x', long)]
    stop_on_crash: bool,
}

#[derive(Args, Clone)]
pub struct Minimize {
    /// Target to use
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Corpus directory to minimize
    #[clap(short, long, default_value = DEFAULT_CORPUS_DIR)]
    input_corpus: PathBuf,

    /// Minimized corpus output directory
    #[clap(short, long, default_value = DEFAULT_MINIMIZATION_DIR)]
    output_corpus: PathBuf,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,

    /// Number of concurrent minimizing jobs (AFL++ only)
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,

    /// Timeout for a single run
    #[clap(short, long, value_name = "MILLI_SECS", default_value_t = 5000)]
    timeout: u32,

    #[clap(short, long, value_enum, default_value_t = FuzzingEngines::All)]
    engine: FuzzingEngines,
}

#[derive(Args)]
pub struct Cover {
    /// Target to generate coverage for
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Output directory for code coverage report
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_COVERAGE_DIR)]
    output: PathBuf,

    /// Input corpus directory to run target on
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CORPUS_DIR)]
    input: PathBuf,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,

    /// Source directory of covered code
    #[clap(short, long, value_parser, value_name = "DIR")]
    source: Option<PathBuf>,

    /// Keep coverage data files (WARNING: Do not use if source code has changed)
    #[clap(short, long, default_value_t = false)]
    keep: bool,

    /// Comma separated list of output types. See grcov --help to see supported output types. Default: html
    #[clap(short = 't', long)]
    output_types: Option<String>,

    /// Number of concurrent jobs
    #[clap(short, long, value_name = "NUM")]
    jobs: Option<usize>,
}

#[derive(Args)]
pub struct Plot {
    /// Target to generate plot for
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Name of AFL++ fuzzer to use as data source
    #[clap(short, long, value_name = "NAME", default_value = "mainaflfuzzer")]
    input: String,

    /// Output directory for plot
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_PLOT_DIR)]
    output: PathBuf,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,
}

#[derive(Args)]
pub struct Triage {
    /// Target to use
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Triage output directory to be written to (will be overwritten)
    #[clap(short, long, value_name = "DIR", default_value = DEFAULT_TRIAGE_DIR)]
    output: PathBuf,

    /// Number of concurrent fuzzing jobs
    #[clap(short, long, value_name = "NUM", default_value_t = 1)]
    jobs: u32,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,

    /// Terminate runner after x seconds
    #[clap(short, long, value_name = "SECS")]
    timeout: Option<u32>,
    /* future feature, wait for casr
    /// Crash directory to be sourced from
    #[clap(short, long, value_parser, value_name = "DIR", default_value = DEFAULT_CRASHES_DIR)]
    input: PathBuf,
    */
}

#[derive(Args)]
pub struct AddSeeds {
    /// Target to use
    #[clap(value_name = "TARGET")]
    target: Option<String>,

    /// Seeds directory to be added
    #[clap(short, long, value_parser, value_name = "DIR")]
    input: PathBuf,

    /// Fuzzers output directory
    #[clap(
        short, long, env = "ZIGGY_OUTPUT", value_parser, value_name = "DIR", default_value = DEFAULT_OUTPUT_DIR
    )]
    ziggy_output: PathBuf,
}

#[derive(Args)]
pub struct Clean {
    /// Arguments passed through to cargo clean, see cargo clean --help
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<std::ffi::OsString>,
}

#[derive(Debug)]
pub struct Common {
    terminate: Arc<AtomicBool>,
    sigs_done: Option<()>,
    pub cargo_path: PathBuf,
    runtime: OnceLock<tokio::runtime::Runtime>,
    metadata: OnceLock<Option<cargo_metadata::Metadata>>,
}

impl Common {
    fn new() -> Self {
        Self {
            terminate: Arc::new(AtomicBool::new(false)),
            sigs_done: Some(()),
            cargo_path: std::env::var("CARGO")
                .unwrap_or_else(|_| String::from("cargo"))
                .into(),
            runtime: OnceLock::new(),
            metadata: OnceLock::new(),
        }
    }
    fn is_terminated(&self) -> bool {
        self.terminate.load(std::sync::atomic::Ordering::Acquire)
    }

    fn shutdown_deferred(&self) {
        self.terminate
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn shutdown_immediate(&self) {
        self.terminate
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn setup_signal_handling(&mut self) -> Result<(), anyhow::Error> {
        if self.sigs_done.take().is_some() {
            for signal in signal_hook::consts::TERM_SIGNALS {
                signal_hook::flag::register_conditional_shutdown(
                    *signal,
                    1,
                    Arc::clone(&self.terminate),
                )
                .context("Setting up signal handler")?;
                signal_hook::flag::register(*signal, Arc::clone(&self.terminate))
                    .context("Setting up signal handler")?;
            }
        }
        Ok(())
    }

    fn cargo(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.cargo_path);
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn async_runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed building tokio runtime")
        })
    }

    /// Cached `cargo metadata`
    fn metadata(&self) -> Option<&cargo_metadata::Metadata> {
        self.metadata
            .get_or_init(|| cargo_metadata::MetadataCommand::new().exec().ok())
            .as_ref()
    }

    fn target_dir(&self) -> Result<&util::Utf8PathBuf> {
        self.metadata()
            .map(|metadata| &metadata.target_directory)
            .ok_or_else(|| anyhow!("not in a Cargo workspace"))
    }

    fn guess_bin(&self) -> Result<String> {
        let meta = self
            .metadata()
            .ok_or_else(|| anyhow!("failed running cargo metadata"))?;

        if meta.workspace_default_members.is_missing() {
            bail!("please specify a target")
        }
        let bins: Vec<(&str, &str)> = meta
            .workspace_default_packages()
            .into_iter()
            .flat_map(|p| p.targets.iter().filter(|t| t.is_bin()))
            .map(|t| (t.name.as_str(), t.src_path.as_str()))
            .collect();
        // if there is only one bin, we use it
        if let [(name, _)] = bins.as_slice() {
            return Ok((*name).to_owned());
        }
        // otherwise fallback to `main.rs`
        let main_bins: Vec<&str> = bins
            .iter()
            .filter_map(|(name, path)| path.ends_with("main.rs").then_some(*name))
            .collect();
        if let [name] = main_bins.as_slice() {
            return Ok((*name).to_owned());
        }
        // otherwise we ask the user to choose
        let mut targets = String::new();
        for (name, _) in bins {
            targets.push_str("\n\t");
            targets.push_str(name);
        }
        bail!("please specify a target\nhelp: available targets:{targets}");
    }

    fn resolve_bin(&self, target: Option<String>) -> Result<String> {
        target.ok_or(()).or_else(|()| self.guess_bin())
    }
}

fn main() -> Result<(), anyhow::Error> {
    let mut common = Common::new();
    common.shutdown_immediate();
    common.setup_signal_handling()?;

    let Cargo::Ziggy(command) = Cargo::parse();
    match command {
        Ziggy::Build(args) => args.build(&common).context("Failed to build the fuzzers"),
        Ziggy::Fuzz(mut args) => args.fuzz(&common).context("Failure running fuzzers"),
        Ziggy::Run(mut args) => args.run(&common).context("Failure running inputs"),
        Ziggy::Minimize(args) => args
            .minimize(&common)
            .context("Failure running minimization"),
        Ziggy::Cover(args) => args
            .generate_coverage(&common)
            .context("Failure generating coverage"),
        Ziggy::Plot(args) => args
            .generate_plot(&common)
            .context("Failure generating plot"),
        Ziggy::AddSeeds(args) => args
            .add_seeds(&common)
            .context("Failure adding seeds to AFL"),
        Ziggy::Triage(args) => args.triage(&common).context("Failure triaging with casr"),
        Ziggy::Clean(args) => args
            .clean(&common)
            .context("Failure cleaning build artifacts"),
    }
}
