use crate::{find_target, Bench, Build};
use anyhow::{Context, Error, Result};
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
    process,
    time::SystemTime,
};

const STATS_LEN: usize = 4;
const STATS: [&str; STATS_LEN] = ["run_time", "execs_per_sec", "edges_found", "total_edges"];
type Stats = [f64; STATS_LEN];

impl Bench {
    // Build the AFL++ fuzzer
    fn build(&self) -> Result<(), Error> {
        let build = Build {
            no_afl: false,
            no_honggfuzz: true,
        };
        build.build().context("Failed to build the fuzzer")
    }

    // Prepare the input and output directories
    fn prepare_directories(&mut self) -> Result<(String, String), Error> {
        self.target =
            find_target(&self.target).context("⚠️  couldn't find target when running benchmark")?;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis();

        let output_target_dir = format!(
            "{}/{}",
            &self.ziggy_output.display().to_string(),
            &self.target,
        );

        let bench_dir = format!("{output_target_dir}/bench",);
        let input_dir = format!("{output_target_dir}/bench/corpus",);
        let logs_dir = format!("{output_target_dir}/logs",);

        let _ = process::Command::new("mkdir")
            .args(["-p", &input_dir, &logs_dir])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        let output_dir = format!("{bench_dir}/{timestamp}");

        let output_file = format!("{input_dir}/bench_input");

        if self
            .copy_benchmark_file(&output_file, &output_target_dir)
            .is_err()
        {
            self.create_empty_benchmark_file(&output_file)?;
        }

        Ok((input_dir, output_dir))
    }

    fn copy_benchmark_file(&self, output_file: &str, output_target_dir: &str) -> Result<(), Error> {
        let afl_corpus_dir = format!("{output_target_dir}/afl/mainaflfuzzer/queue/",);
        let afl_corpus_path = Path::new(&afl_corpus_dir);
        let mut corpus_files: Vec<_> = fs::read_dir(afl_corpus_path)
            .context("Could not find corpus directory")?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .collect();

        corpus_files.sort_by_key(|entry| entry.path());

        let last_input = corpus_files
            .last()
            .context("Could not get last file from corpus")?;

        fs::copy(last_input.path(), output_file)
            .context("Could not copy file to new corpus directory")?;

        println!("Chosen benchmark input: {}", last_input.path().display());
        Ok(())
    }

    fn create_empty_benchmark_file(&self, output_file: &str) -> Result<(), Error> {
        let mut output = File::create(output_file)?;
        writeln!(&mut output, "00000000")?;
        Ok(())
    }

    fn extract_stats(&self, output_dir: &str) -> Result<Stats, Error> {
        let fuzzer_stats = File::open(format!("{output_dir}/default/fuzzer_stats"))
            .context("Could not open fuzzer_stats")?;
        let mut stats = Stats::default();
        for line in BufReader::new(fuzzer_stats).lines().map_while(Result::ok) {
            if let Some((i, _)) = STATS.iter().enumerate().find(|s| line.contains(s.1)) {
                stats[i] = line.split(' ').last().unwrap().parse()?;
            }
        }
        Ok(stats)
    }

    fn compute_averages(&self, values: &[Stats]) -> Stats {
        let mut sum = Stats::default();
        for v in values {
            sum = sum
                .iter()
                .zip(v.iter())
                .map(|(i, j)| i + j)
                .collect::<Vec<f64>>()
                .try_into()
                .unwrap();
        }
        sum
    }

    // Benchmark a harness
    // > # we want to benchmark the performance of a specific harness.
    // > AFL_BENCH_JUST_ONE=1 \# will focus on only 1 input
    // > AFL_DISABLE_TRIM=1 \
    // > afl-fuzz \
    // > -i dir \# dir should have only 1 large seed
    // > -D \# deterministic fuzzing
    // > -s 123 # hardcodes the rng seed
    // > # run this a couple of times (~3) for each input, and note the total runtime for each (in fuzz_stats)
    // > # knowledge source: @vanhauser-thc
    pub fn bench(&mut self) -> Result<(), Error> {
        // Build the AFL++ fuzzer
        self.build()?;
        // Prepare the input and output directories
        let (input_dir, output_dir) = self.prepare_directories()?;
        let mut stats = Vec::<Stats>::new();
        // TODO Allow for a custom amount of repetitions
        for i in 1..4 {
            println!("Run {i}");
            // Get the Cargo excecutable
            let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
            // Execute the benchmarking command
            process::Command::new(cargo)
                .args([
                    "afl",
                    "fuzz",
                    "-i",
                    &input_dir,
                    "-o",
                    &output_dir,
                    "-D",
                    "-s",
                    &format!("{}", 1337 + i), // TODO Allow passing custom RNG seed as input
                    "--",
                    &format!("./target/afl/debug/{}", &self.target),
                ])
                .env("AFL_BENCH_JUST_ONE", "1")
                .env("AFL_DISABLE_TRIM", "1")
                .stderr(File::create(format!(
                    "{}/{}/logs/bench.log",
                    &self.ziggy_output.display(),
                    &self.target,
                ))?)
                .stdout(File::create(format!(
                    "{}/{}/logs/bench.log",
                    &self.ziggy_output.display(),
                    &self.target,
                ))?)
                .spawn()?
                .wait()?;
            // Extract the stats from the AFL++ output
            stats.push(self.extract_stats(&output_dir)?);
        }
        let averages = self.compute_averages(&stats);
        for i in 0..STATS_LEN {
            println!("average {}: {}", STATS[i], averages[i].round());
        }
        Ok(())
    }
}
