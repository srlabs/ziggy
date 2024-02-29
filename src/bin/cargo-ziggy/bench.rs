use crate::{find_target, Bench, Build};
use anyhow::{Context, Error, Result};
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
    process,
    time::SystemTime,
};

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

        let bench_dir = format!("{output_target_dir}/bench");
        let input_dir = format!("{output_target_dir}/bench/corpus",);
        let afl_corpus_dir = format!("{output_target_dir}/afl/mainaflfuzzer/queue/",);

        let _ = process::Command::new("mkdir")
            .args(["-p", &bench_dir, &input_dir])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        let output_dir = format!("{bench_dir}/{timestamp}");

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

        println!("Chosen benchmark input: {}", last_input.path().display());

        fs::copy(last_input.path(), format!("{input_dir}/bench_input"))
            .context("Could not copy file to new corpus directory")?;

        Ok((input_dir, output_dir))
    }

    fn extract_stats(&self, output_dir: &str) -> Result<(), Error> {
        let fuzzer_stats = File::open(format!("{output_dir}/default/fuzzer_stats"))
            .context("Could not open fuzzer_stats")?;
        for line in BufReader::new(fuzzer_stats).lines().map_while(Result::ok) {
            if ["run_time", "execs_per_sec", "edges_found", "total_edges"]
                .iter()
                .any(|s| line.contains(s))
            {
                println!("{}", line);
            }
        }
        Ok(())
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
        // TODO Allow for a custom amount of repetitions
        for i in 1..4 {
            println!("\nRun {i}");
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
            self.extract_stats(&output_dir)?;
        }
        Ok(())
    }
}
