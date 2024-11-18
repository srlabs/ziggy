use crate::build::ASAN_TARGET;
use crate::*;
use anyhow::{anyhow, Error};
use console::{style, Term};
use glob::glob;
use std::{
    env,
    fs::File,
    io::Write,
    path::Path,
    process::{self, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use strip_ansi_escapes::strip_str;

/// Main logic for managing fuzzers and the fuzzing process in ziggy.

/// ## Initial minimization logic

/// When launching fuzzers, if initial corpora exist, they are merged together and we minimize it
/// with both AFL++ and Honggfuzz.
/// ```text
/// # bash pseudocode
/// cp all_afl_corpora/* corpus/* corpus_tmp/
/// # run afl++ minimization
/// afl++_minimization -i corpus_tmp -o corpus_minimized
/// # in parallel, run honggfuzz minimization
/// honggfuzz_minimization -i corpus_tmp -o corpus_minimized
/// rm -rf corpus corpus_tmp
/// mv corpus_minimized corpus
/// afl++ -i corpus -o all_afl_corpora &
///   honggfuzz -i corpus -o corpus
/// ```
/// The `all_afl_corpora` directory corresponds to the `output/target_name/afl/**/queue/` directories.

struct FuzzerWeights {
    afl: u32,
    libafl: u32,
    honggfuzz: u32,
}

const FUZZER_WEIGHTS: FuzzerWeights = FuzzerWeights {
    afl: 3,
    libafl: 2,
    honggfuzz: 1,
};

impl Fuzz {
    pub fn corpus(&self) -> String {
        self.corpus
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target)
    }

    pub fn corpus_tmp(&self) -> String {
        format!("{}/corpus_tmp/", self.output_target())
    }

    pub fn corpus_minimized(&self) -> String {
        format!("{}/corpus_minimized/", self.output_target(),)
    }

    pub fn output_target(&self) -> String {
        format!("{}/{}", self.ziggy_output.display(), self.target)
    }

    /// Returns true if AFL++ is enabled
    pub fn afl(&self) -> bool {
        !self.no_afl
    }

    /// Returns true if LibAFL is enabled
    pub fn libafl(&self) -> bool {
        !self.no_libafl && (self.no_afl || self.jobs > 1)
    }

    /// Returns true if Honggfuzz is enabled
    // This definition could be a one-liner but it was expanded for clarity
    pub fn honggfuzz(&self) -> bool {
        if self.fuzz_binary() {
            // We cannot use honggfuzz in binary mode
            false
        } else if self.no_afl && self.no_libafl {
            // If we have "no_afl" and "no_libafl" set then honggfuzz is always enabled
            true
        } else if self.no_afl || self.no_libafl {
            return !self.no_honggfuzz && self.jobs > 1
        } else {
            return !self.no_honggfuzz && self.jobs > 2
        }
    }

    fn fuzz_binary(&self) -> bool {
        self.binary.is_some()
    }

    // Manages the continuous running of fuzzers
    pub fn fuzz(&mut self) -> Result<(), anyhow::Error> {
       if !self.fuzz_binary() {
            let build = Build {
                no_afl: !self.afl(),
                no_libafl: !self.libafl(),
                no_honggfuzz: !self.honggfuzz(),
                release: self.release,
                asan: self.asan,
            };
            build.build().context("Failed to build the fuzzers")?;
        }

        self.target = if self.fuzz_binary() {
            self.binary
                .as_ref()
                .expect("invariant; should never occur")
                .display()
                .to_string()
        } else {
            find_target(&self.target).context("⚠️  couldn't find target when fuzzing")?
        };

        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        let crash_dir = format!("{}/crashes/{}/", self.output_target(), time);
        let crash_path = Path::new(&crash_dir);
        fs::create_dir_all(crash_path)?;

        let _ = process::Command::new("mkdir")
            .args([
                "-p",
                &format!("{}/logs/", self.output_target()),
                &format!("{}/queue/", self.output_target()),
            ])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        if Path::new(&self.corpus()).exists() {
            if self.minimize {
                fs::create_dir_all(self.corpus_tmp())
                    .context("Could not create temporary corpus")?;
                self.copy_corpora()
                    .context("Could not move all seeds to temporary corpus")?;
                let _ = fs::remove_dir_all(self.corpus_minimized());
                self.run_minimization()
                    .context("Failure while minimizing")?;
                fs::remove_dir_all(self.corpus()).context("Could not remove shared corpus")?;
                fs::rename(self.corpus_minimized(), self.corpus())
                    .context("Could not move minimized corpus over")?;
                fs::remove_dir_all(self.corpus_tmp())
                    .context("Could not remove temporary corpus")?;
            }
        } else {
            let _ = process::Command::new("mkdir")
                .args(["-p", &self.corpus()])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;
        }

        // We create an initial corpus file, so that AFL++ starts-up properly if corpus is empty
        let is_empty = fs::read_dir(self.corpus())?.next().is_none(); // check if corpus has some seeds
        if is_empty {
            let mut initial_corpus = File::create(self.corpus() + "/init")?;
            writeln!(&mut initial_corpus, "00000000")?;
            drop(initial_corpus);
        }

        let mut processes = self.spawn_new_fuzzers()?;

        self.start_time = Instant::now();

        let mut last_synced_queue_id: u32 = 0;
        let mut last_sync_time = Instant::now();
        let mut afl_output_ok = false;

        if self.no_afl && self.coverage_worker {
            return Err(anyhow!("cannot use --no-afl with --coverage-worker!"));
        }

        // We prepare builds for the coverage worker
        if self.coverage_worker {
            Cover::clean_old_cov()?;
            Cover::build_runner()?;
        }
        let cov_start_time = Arc::new(Mutex::new(None));
        let cov_end_time = Arc::new(Mutex::new(Instant::now()));
        let coverage_now_running = Arc::new(Mutex::new(false));
        let workspace_root = cargo_metadata::MetadataCommand::new()
            .exec()?
            .workspace_root
            .to_string();
        let target = self.target.clone();
        let main_corpus = self.corpus();
        let output_target = self.output_target();

        loop {
            let sleep_duration = Duration::from_secs(1);
            thread::sleep(sleep_duration);

            let coverage_status = match (
                self.coverage_worker,
                *coverage_now_running.lock().unwrap(),
                cov_end_time.lock().unwrap().elapsed().as_secs() / 60,
            ) {
                (true, false, wait) if wait < self.coverage_interval => {
                    format!("waiting {} minutes", self.coverage_interval - wait)
                }
                (true, false, _) => String::from("starting"),
                (true, true, _) => String::from("running"),
                (false, _, _) => String::from("disabled"),
            };

            self.print_stats(&coverage_status);

            if coverage_status.as_str() == "starting" {
                *coverage_now_running.lock().unwrap() = true;

                let main_corpus = main_corpus.clone();
                let target = target.clone();
                let workspace_root = workspace_root.clone();
                let output_target = output_target.clone();
                let cov_start_time = Arc::clone(&cov_start_time);
                let cov_end_time = Arc::clone(&cov_end_time);
                let coverage_now_running = Arc::clone(&coverage_now_running);

                thread::spawn(move || {
                    let mut seen_new_entry = false;
                    let prev_start_time = {
                        let unlocked = cov_start_time.lock().unwrap();
                        *unlocked
                    };
                    *cov_start_time.lock().unwrap() = Some(Instant::now());
                    let entries = std::fs::read_dir(&main_corpus).unwrap();
                    for entry in entries.flatten().map(|e| e.path()) {
                        // We only want to run corpus entries created since the last time we ran.
                        let created = entry
                            .metadata()
                            .unwrap()
                            .created()
                            .unwrap()
                            .elapsed()
                            .unwrap_or_default();
                        if prev_start_time
                            .map(|s| s.elapsed())
                            .unwrap_or(Duration::MAX)
                            >= created
                        {
                            let _ = process::Command::new(format!(
                                "./target/coverage/debug/{}",
                                &target
                            ))
                            .arg(format!("{}", entry.display()))
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                            seen_new_entry = true;
                        }
                    }
                    if seen_new_entry {
                        let coverage_dir = output_target + "/coverage";
                        let _ = fs::remove_dir_all(&coverage_dir);
                        Cover::run_grcov(&target.clone(), "html", &coverage_dir, &workspace_root)
                            .unwrap();
                    }

                    *cov_end_time.lock().unwrap() = Instant::now();
                    *coverage_now_running.lock().unwrap() = false;
                });
            }

            if !afl_output_ok {
                if let Ok(afl_log) =
                    fs::read_to_string(format!("{}/logs/afl.log", self.output_target()))
                {
                    if afl_log.contains("ready to roll") {
                        afl_output_ok = true;
                    } else if afl_log.contains("echo core >/proc/sys/kernel/core_pattern")
                        || afl_log.contains("cd /sys/devices/system/cpu")
                    {
                        stop_fuzzers(&mut processes)?;
                        eprintln!("We highly recommend you configure your system for better performance:\n");
                        eprintln!("    cargo afl system-config\n");
                        eprintln!(
                            "Or set AFL_SKIP_CPUFREQ and AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES\n"
                        );
                        return Ok(());
                    }
                }
            }

            // We check AFL++ and Honggfuzz's outputs for crash files and copy them over to
            // our own crashes directory
            let crash_dirs = glob(&format!("{}/afl/*/crashes", self.output_target()))
                .map_err(|_| anyhow!("Failed to read crashes glob pattern"))?
                .flatten()
                .chain(vec![format!(
                    "{}/honggfuzz/{}",
                    self.output_target(),
                    self.target
                )
                .into()])
                .chain(vec![
                    format!("{}/libafl/crashes", self.output_target()).into()
                ]);

            for crash_dir in crash_dirs {
                if let Ok(crashes) = fs::read_dir(crash_dir) {
                    for crash_input in crashes.flatten() {
                        let file_name = crash_input.file_name();
                        let to_path = crash_path.join(&file_name);
                        let file_name_str = file_name.to_str().unwrap_or_default();
                        if to_path.exists()
                            || ["", "README.txt", "HONGGFUZZ.REPORT.TXT", "input"]
                                .contains(&file_name_str)
                            || file_name_str.contains(".lafl_lock")
                            || file_name_str.contains(".metadata")
                        {
                            continue;
                        }
                        fs::copy(crash_input.path(), to_path)?;
                    }
                }
            }

            // If both fuzzers are running, we copy over AFL++'s queue for consumption by Honggfuzz.
            // Otherwise, if only AFL++ is up we copy AFL++'s queue to the global corpus.
            // We do this every 10 seconds
            if self.afl() && last_sync_time.elapsed().as_secs() > 10 {
                let afl_corpus = glob(&format!(
                    "{}/afl/mainaflfuzzer/queue/*",
                    self.output_target(),
                ))?
                .flatten();
                for file in afl_corpus {
                    if let Some((file_id, file_name)) = extract_file_id(&file) {
                        if file_id > last_synced_queue_id {
                            let copy_destination = match self.honggfuzz() {
                                true => format!("{}/queue/{file_name}", self.output_target()),
                                false => format!("{}/corpus/{file_name}", self.output_target()),
                            };
                            let _ = fs::copy(&file, copy_destination);
                            last_synced_queue_id = file_id;
                        }
                    }
                }
                last_sync_time = Instant::now();
            }

            if processes
                .iter_mut()
                .all(|p| p.try_wait().unwrap_or(None).is_some())
            {
                stop_fuzzers(&mut processes)?;
                return Ok(());
            }
        }
    }

    pub fn compute_job_repartition(&self) -> (u32, u32, u32) {
        let afl_weight = if self.afl() { FUZZER_WEIGHTS.afl } else { 0 };
        let libafl_weight = if self.libafl() {
            FUZZER_WEIGHTS.libafl
        } else {
            0
        };
        let honggfuzz_weight = if self.honggfuzz() {
            FUZZER_WEIGHTS.honggfuzz
        } else {
            0
        };
        let total_weights = afl_weight + libafl_weight + honggfuzz_weight;

        let mut honggfuzz_jobs = honggfuzz_weight * self.jobs / total_weights;
        let mut afl_jobs = afl_weight * self.jobs / total_weights;
        let mut libafl_jobs = libafl_weight * self.jobs / total_weights;

        // We adjust the numbers because of potential rounding errors
        while honggfuzz_jobs + afl_jobs + libafl_jobs < self.jobs {
            if self.honggfuzz() {
                honggfuzz_jobs += 1;
            } else if self.libafl() {
                libafl_jobs += 1;
            } else if self.afl() {
                afl_jobs += 1;
            }
        }

        // If Honggfuzz is not the only fuzzer, we will not allow it to get more than 4 parallel jobs.
        if honggfuzz_jobs > 4 && (self.afl() || self.libafl()) {
            if self.afl() {
                afl_jobs += honggfuzz_jobs - 4;
            } else if self.libafl() {
                libafl_jobs += honggfuzz_jobs - 4;
            }
            honggfuzz_jobs = 4;
        }

        (afl_jobs, libafl_jobs, honggfuzz_jobs)
    }

    // Spawns new fuzzers
    pub fn spawn_new_fuzzers(&self) -> Result<Vec<process::Child>, anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz && self.no_libafl {
            return Err(anyhow!(
                "Pick at least one fuzzer.\nNote: -b/--binary implies --no-honggfuzz"
            ));
        }

        let mut fuzzer_handles = vec![];

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        // We compute the jobs assigned to each fuzzer, according to FUZZER_WEIGHTS
        let (afl_jobs, libafl_jobs, honggfuzz_jobs) = self.compute_job_repartition();

        if honggfuzz_jobs > 4 {
            eprintln!("Warning: running more honggfuzz jobs than 4 is not effective");
        }

        if afl_jobs > 0 {
            let _ = process::Command::new("mkdir")
                .args(["-p", &format!("{}/afl", self.output_target())])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;

            // https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores
            let afl_modes = [
                "explore", "fast", "coe", "lin", "quad", "exploit", "rare", "explore", "fast",
                "mmopt",
            ];

            for job_num in 0..afl_jobs {
                let is_main_instance = job_num == 0;
                // We set the fuzzer name, and if it's the main or a secondary fuzzer
                let fuzzer_name = match is_main_instance {
                    true => String::from("-Mmainaflfuzzer"),
                    false => format!("-Ssecondaryfuzzer{job_num}"),
                };
                // We only sync to the shared corpus if Honggfuzz is also running
                let use_shared_corpus = match (self.no_honggfuzz, job_num) {
                    (false, 0) => format!("-F{}", &self.corpus()),
                    _ => String::new(),
                };
                let use_initial_corpus_dir = match (&self.initial_corpus, job_num) {
                    (Some(initial_corpus), 0) => {
                        format!("-F{}", &initial_corpus.display().to_string())
                    }
                    _ => String::new(),
                };
                // 10% of secondary fuzzers have the MOpt mutator enabled
                let mopt_mutator = match job_num % 10 {
                    9 => "-L0",
                    _ => "",
                };
                // Power schedule
                let power_schedule = afl_modes
                    .get(job_num as usize % afl_modes.len())
                    .unwrap_or(&"fast");
                // Old queue cycling
                let old_queue_cycling = match job_num % 10 {
                    8 => "-Z",
                    _ => "",
                };
                // Only few instances do cmplog
                let cmplog_options = match job_num {
                    1 => "-l2a",
                    3 => "-l1",
                    14 => "-l2a",
                    22 => "-l3at",
                    _ => "-c-", // disable Cmplog, needs AFL++ 4.08a
                };
                // AFL timeout is in ms so we convert the value
                let timeout_option_afl = match self.timeout {
                    Some(t) => format!("-t{}", t * 1000),
                    None => String::new(),
                };
                let dictionary_option = match &self.dictionary {
                    Some(d) => format!("-x{}", &d.display().to_string()),
                    None => String::new(),
                };
                let mutation_option = match job_num / 5 {
                    0..=1 => "-P600",
                    2..=3 => "-Pexplore",
                    _ => "-Pexploit",
                };
                let input_format_option = self.config.input_format_flag();
                let log_destination = || match job_num {
                    0 => File::create(format!("{}/logs/afl.log", self.output_target()))
                        .unwrap()
                        .into(),
                    1 => File::create(format!("{}/logs/afl_1.log", self.output_target()))
                        .unwrap()
                        .into(),
                    _ => process::Stdio::null(),
                };
                let final_sync = match job_num {
                    0 => "AFL_FINAL_SYNC",
                    _ => "_DUMMY_VAR",
                };
                let target_path = match self.fuzz_binary() {
                    true => self.target.clone(),
                    false => {
                        if self.release {
                            format!("./target/afl/release/{}", self.target)
                        } else if self.asan {
                            format!("./target/afl/{ASAN_TARGET}/debug/{}", self.target)
                        } else {
                            format!("./target/afl/debug/{}", self.target)
                        }
                    }
                };

                let mut afl_flags = self.afl_flags.clone();
                if is_main_instance {
                    for path in &self.foreign_sync_dirs {
                        afl_flags.push(format!("-F {}", path.display()))
                    }
                }

                fuzzer_handles.push(
                    process::Command::new(cargo.clone())
                        .args(
                            [
                                "afl",
                                "fuzz",
                                &fuzzer_name,
                                &format!("-i{}", self.corpus()),
                                &format!("-p{power_schedule}"),
                                &format!("-o{}/afl", self.output_target()),
                                &format!("-g{}", self.min_length),
                                &format!("-G{}", self.max_length),
                                &use_shared_corpus,
                                &use_initial_corpus_dir,
                                old_queue_cycling,
                                cmplog_options,
                                mopt_mutator,
                                mutation_option,
                                input_format_option,
                                &timeout_option_afl,
                                &dictionary_option,
                            ]
                            .iter()
                            .filter(|a| a != &&""),
                        )
                        .args(afl_flags)
                        .arg(target_path)
                        .env("AFL_AUTORESUME", "1")
                        .env("AFL_TESTCACHE_SIZE", "100")
                        .env("AFL_FAST_CAL", "1")
                        .env("AFL_FORCE_UI", "1")
                        .env("AFL_IGNORE_UNKNOWN_ENVS", "1")
                        .env("AFL_CMPLOG_ONLY_NEW", "1")
                        .env("AFL_DISABLE_TRIM", "1")
                        .env("AFL_NO_WARN_INSTABILITY", "1")
                        .env("AFL_FUZZER_STATS_UPDATE_INTERVAL", "10")
                        .env("AFL_IMPORT_FIRST", "1")
                        .env(final_sync, "1")
                        .env("AFL_IGNORE_SEED_PROBLEMS", "1")
                        .stdout(log_destination())
                        .stderr(log_destination())
                        .spawn()?,
                )
            }
            eprintln!("{} afl           ", style("    Launched").green().bold());
        }

        if libafl_jobs > 0 {
            let _ = process::Command::new("mkdir")
                .args(["-p", &format!("{}/libafl/logs", self.output_target())])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;

            fuzzer_handles.push(
                process::Command::new(format!(
                    "./target/libafl/x86_64-unknown-linux-gnu/release/{}",
                    self.target
                ))
                .env("LIBAFL_TARGET_NAME", &self.target)
                .env("LIBAFL_SHARED_CORPUS", self.corpus())
                .env(
                    "LIBAFL_CRASHES",
                    &format!("{}/libafl/crashes", self.output_target()),
                )
                .env("LIBAFL_CORES", format!("{libafl_jobs}"))
                .stderr(File::create(format!(
                    "{}/logs/libafl.log",
                    self.output_target(),
                ))?)
                .stdout(File::create(format!(
                    "{}/logs/libafl.log",
                    self.output_target()
                ))?)
                .spawn()?,
            );
            eprintln!(
                "{} libafl                 ",
                style("    Launched").green().bold()
            );
        }

        if honggfuzz_jobs > 0 {
            let hfuzz_help = process::Command::new(&cargo)
                .args(["hfuzz", "run", &self.target])
                .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                .env(
                    "HFUZZ_WORKSPACE",
                    format!("{}/honggfuzz", self.output_target()),
                )
                .env("HFUZZ_RUN_ARGS", "--help")
                .output()
                .context("could not run `cargo hfuzz run --help`")?;

            if !std::str::from_utf8(hfuzz_help.stdout.as_slice())
                .unwrap_or_default()
                .contains("dynamic_input")
                && !std::str::from_utf8(hfuzz_help.stderr.as_slice())
                    .unwrap_or_default()
                    .contains("dynamic_input")
            {
                return Err(anyhow!("Outdated version of honggfuzz, please update the ziggy version in your Cargo.toml or rebuild the project"));
            }

            let dictionary_option = match &self.dictionary {
                Some(d) => format!("-w{}", &d.display().to_string()),
                None => String::new(),
            };

            let timeout_option = match self.timeout {
                Some(t) => format!("-t{t}"),
                None => String::new(),
            };

            // The `script` invocation is a trick to get the correct TTY output for honggfuzz
            fuzzer_handles.push(
                process::Command::new("script")
                    .args([
                        "--flush",
                        "--quiet",
                        "-c",
                        &format!("{} hfuzz run {}", cargo, &self.target),
                        "/dev/null",
                    ])
                    .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                    .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                    .env(
                        "HFUZZ_WORKSPACE",
                        format!("{}/honggfuzz", self.output_target()),
                    )
                    .env(
                        "HFUZZ_RUN_ARGS",
                        format!(
                            "--input={} -o{} -n{honggfuzz_jobs} -F{} --dynamic_input={}/queue {timeout_option} {dictionary_option}",
                            &self.corpus(),
                            &self.corpus(),
                            self.max_length,
                            self.output_target(),
                        ),
                    )
                    .stdin(std::process::Stdio::null())
                    .stderr(File::create(format!(
                        "{}/logs/honggfuzz.log",
                        self.output_target()
                    ))?)
                    .stdout(File::create(format!(
                        "{}/logs/honggfuzz.log",
                        self.output_target()
                    ))?)
                    .spawn()?,
            );
            eprintln!(
                "{} honggfuzz              ",
                style("    Launched").green().bold()
            );
        }

        eprintln!("\nSee more live information by running:");
        if afl_jobs > 0 {
            eprintln!(
                "  {}",
                style(format!("tail -f {}/logs/afl.log", self.output_target())).bold()
            );
        }
        if afl_jobs > 1 {
            eprintln!(
                "  {}",
                style(format!("tail -f {}/logs/afl_1.log", self.output_target())).bold()
            );
        }
        if honggfuzz_jobs > 0 {
            eprintln!(
                "  {}",
                style(format!(
                    "tail -f {}/logs/honggfuzz.log",
                    self.output_target()
                ))
                .bold()
            );
        }

        Ok(fuzzer_handles)
    }

    fn all_seeds(&self) -> Result<Vec<PathBuf>> {
        Ok(glob(&format!("{}/afl/*/queue/*", self.output_target()))
            .map_err(|_| anyhow!("Failed to read AFL++ queue glob pattern"))?
            .chain(
                glob(&format!("{}/*", self.corpus()))
                    .map_err(|_| anyhow!("Failed to read Honggfuzz corpus glob pattern"))?,
            )
            .flatten()
            .filter(|f| f.is_file())
            .collect())
    }

    // Copy all corpora into `corpus`
    pub fn copy_corpora(&self) -> Result<()> {
        self.all_seeds()?.iter().for_each(|s| {
            let _ = fs::copy(
                s.to_str().unwrap_or_default(),
                format!(
                    "{}/{}",
                    &self.corpus_tmp(),
                    s.file_name()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default(),
                ),
            );
        });
        Ok(())
    }

    pub fn run_minimization(&self) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!(
            "\n    {}",
            &style("Running minimization").magenta().bold()
        ))?;

        let input_corpus = &self.corpus_tmp();
        let minimized_corpus = &self.corpus_minimized();

        let old_corpus_size = fs::read_dir(input_corpus)
            .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

        let engine = match (self.no_afl, self.no_honggfuzz, self.jobs) {
            (false, _, _) => FuzzingEngines::AFLPlusPlus,
            (true, false, _) => FuzzingEngines::Honggfuzz,
            (true, true, _) => return Err(anyhow!("Pick at least one fuzzer")),
        };

        let mut minimization_args = Minimize {
            target: self.target.clone(),
            input_corpus: PathBuf::from(input_corpus),
            output_corpus: PathBuf::from(minimized_corpus),
            ziggy_output: self.ziggy_output.clone(),
            jobs: self.jobs,
            engine,
        };
        match minimization_args.minimize() {
            Ok(_) => {
                let new_corpus_size = fs::read_dir(minimized_corpus)
                    .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

                term.move_cursor_up(1)?;

                if new_corpus_size == *"err" || new_corpus_size == *"0" {
                    return Err(anyhow!("Please check the logs and make sure the right version of the fuzzers are installed"));
                } else {
                    term.write_line(&format!(
                        "{} the corpus ({} -> {} files)             \n",
                        style("    Minimized").magenta().bold(),
                        old_corpus_size,
                        new_corpus_size
                    ))?;
                }
            }
            Err(_) => {
                return Err(anyhow!("Please check the logs, this might be an oom error"));
            }
        };
        Ok(())
    }

    pub fn print_stats(&self, cov_worker_status: &str) {
        let fuzzer_name = format!(" {} ", self.target);

        let reset = "\x1b[0m";
        let gray = "\x1b[1;90m";
        let red = "\x1b[1;91m";
        let green = "\x1b[1;92m";
        let yellow = "\x1b[1;93m";
        let purple = "\x1b[1;95m";
        let blue = "\x1b[1;96m";

        // First step: execute afl-whatsup
        let mut afl_status = format!("{green}running{reset} ─");
        let mut afl_total_execs = String::new();
        let mut afl_instances = String::new();
        let mut afl_speed = String::new();
        let mut afl_coverage = String::new();
        let mut afl_crashes = String::new();
        let mut afl_timeouts = String::new();
        let mut afl_new_finds = String::new();
        let mut afl_faves = String::new();

        if !self.afl() {
            afl_status = format!("{yellow}disabled{reset} ")
        } else {
            let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
            let afl_stats_process = process::Command::new(cargo)
                .args([
                    "afl",
                    "whatsup",
                    "-s",
                    &format!("{}/afl", self.output_target()),
                ])
                .output();

            if let Ok(process) = afl_stats_process {
                let s = std::str::from_utf8(&process.stdout).unwrap_or_default();

                for mut line in s.split('\n') {
                    line = line.trim();
                    if let Some(total_execs) = line.strip_prefix("Total execs : ") {
                        afl_total_execs =
                            String::from(total_execs.split(',').next().unwrap_or_default());
                    } else if let Some(instances) = line.strip_prefix("Fuzzers alive : ") {
                        afl_instances = String::from(instances);
                    } else if let Some(speed) = line.strip_prefix("Cumulative speed : ") {
                        afl_speed = String::from(speed);
                    } else if let Some(coverage) = line.strip_prefix("Coverage reached : ") {
                        afl_coverage = String::from(coverage);
                    } else if let Some(crashes) = line.strip_prefix("Crashes saved : ") {
                        afl_crashes = String::from(crashes);
                    } else if let Some(timeouts) = line.strip_prefix("Hangs saved : ") {
                        afl_timeouts = String::from(timeouts.split(' ').next().unwrap_or_default());
                    } else if let Some(new_finds) = line.strip_prefix("Time without finds : ") {
                        afl_new_finds =
                            String::from(new_finds.split(',').next().unwrap_or_default());
                    } else if let Some(pending_items) = line.strip_prefix("Pending items : ") {
                        afl_faves = String::from(
                            pending_items
                                .split(',')
                                .next()
                                .unwrap_or_default()
                                .strip_suffix(" faves")
                                .unwrap_or_default(),
                        );
                    }
                }
            }
        }

        // Second step: Get stats from libafl
        let mut libafl_status = format!("{green}running{reset} ─");
        let mut libafl_clients = String::new();
        let mut libafl_speed = String::new();
        let mut libafl_coverage = String::new();
        let mut libafl_crashes = String::new();
        let mut libafl_total_execs = String::new();

        if !self.libafl() {
            libafl_status = format!("{yellow}disabled{reset} ");
        } else {
            let hf_stats_process = process::Command::new("tail")
                .args(["-n10", &format!("{}/logs/libafl.log", self.output_target())])
                .output();
            if let Ok(process) = hf_stats_process {
                let s = std::str::from_utf8(&process.stdout).unwrap_or_default();
                for raw_line in s.split('\n') {
                    let global = raw_line.contains("GLOBAL");
                    let stripped_line = strip_str(raw_line);
                    let line = stripped_line.trim();
                    for stat in line.split(", ") {
                        if global {
                            if let Some(clients) = stat.strip_prefix("clients: ") {
                                libafl_clients = format!(
                                    "{}",
                                    clients.parse::<usize>().unwrap_or(1).saturating_sub(1)
                                )
                            } else if let Some(objectives) = stat.strip_prefix("objectives: ") {
                                libafl_crashes = objectives.to_string();
                            } else if let Some(executions) = stat.strip_prefix("executions: ") {
                                libafl_total_execs = executions.to_string();
                            } else if let Some(exec_sec) = stat.strip_prefix("exec/sec: ") {
                                libafl_speed = exec_sec.to_string();
                            }
                        } else if let Some(edges) = stat.strip_prefix("edges: ") {
                            libafl_coverage = edges.to_string();
                        }
                    }
                }
            }
        }

        // Third step: Get stats from honggfuzz logs
        let mut hf_status = format!("{green}running{reset} ─");
        let mut hf_total_execs = String::new();
        let mut hf_threads = String::new();
        let mut hf_speed = String::new();
        let mut hf_coverage = String::new();
        let mut hf_crashes = String::new();
        let mut hf_timeouts = String::new();
        let mut hf_new_finds = String::new();

        if !self.honggfuzz() {
            hf_status = format!("{yellow}disabled{reset} ");
        } else {
            let hf_stats_process = process::Command::new("tail")
                .args([
                    "-n300",
                    &format!("{}/logs/honggfuzz.log", self.output_target()),
                ])
                .output();
            if let Ok(process) = hf_stats_process {
                let s = std::str::from_utf8(&process.stdout).unwrap_or_default();
                for raw_line in s.split('\n') {
                    let stripped_line = strip_str(raw_line);
                    let line = stripped_line.trim();
                    if let Some(total_execs) = line.strip_prefix("Iterations : ") {
                        hf_total_execs =
                            String::from(total_execs.split(' ').next().unwrap_or_default());
                    } else if let Some(threads) = line.strip_prefix("Threads : ") {
                        hf_threads = String::from(threads.split(',').next().unwrap_or_default());
                    } else if let Some(speed) = line.strip_prefix("Speed : ") {
                        hf_speed = String::from(
                            speed
                                .split("[avg: ")
                                .nth(1)
                                .unwrap_or_default()
                                .strip_suffix(']')
                                .unwrap_or_default(),
                        ) + "/sec";
                    } else if let Some(coverage) = line.strip_prefix("Coverage : ") {
                        hf_coverage = String::from(
                            coverage
                                .split('[')
                                .nth(1)
                                .unwrap_or_default()
                                .split(']')
                                .next()
                                .unwrap_or_default(),
                        );
                    } else if let Some(crashes) = line.strip_prefix("Crashes : ") {
                        hf_crashes = String::from(crashes.split(' ').next().unwrap_or_default());
                    } else if let Some(timeouts) = line.strip_prefix("Timeouts : ") {
                        hf_timeouts = String::from(timeouts.split(' ').next().unwrap_or_default());
                    } else if let Some(new_finds) = line.strip_prefix("Cov Update : ") {
                        hf_new_finds = String::from(new_finds.trim());
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("0 days ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("00 hrs ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("00 mins ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds.strip_suffix(" ago").unwrap_or(&hf_new_finds),
                        );
                    }
                }
            }
        }

        // Fourth step: Get global stats
        let mut total_run_time = time_humanize::HumanTime::from(self.start_time.elapsed())
            .to_text_en(
                time_humanize::Accuracy::Rough,
                time_humanize::Tense::Present,
            );
        if total_run_time == "now" {
            total_run_time = String::from("...");
        }

        // Fifth step: Print stats
        let mut screen = String::new();
        // We start by clearing the screen
        screen += "\x1B[1;1H\x1B[2J";
        screen += &format!("┌─ {blue}ziggy{reset} {purple}rocking{reset} ─────────{fuzzer_name:─^25.25}──────────────────{blue}/{red}////{reset}──┐\n");
        screen += &format!(
            "│{gray}run time :{reset} {total_run_time:17.17}                                       {blue}/{red}///{reset}    │\n"
        );
        screen += &format!("├─ {blue}afl++{reset} {afl_status:0}─────────────────────────────────────────────────────{blue}/{red}///{reset}─┤\n");
        if !afl_status.contains("disabled") {
            screen += &format!("│       {gray}instances :{reset} {afl_instances:17.17} │ {gray}best coverage :{reset} {afl_coverage:11.11}   {blue}/{red}//{reset}   │\n");
            if afl_crashes == "0" {
                screen += &format!("│{gray}cumulative speed :{reset} {afl_speed:17.17} │ {gray}crashes saved :{reset} {afl_crashes:11.11}  {blue}/{red}/{reset}     │\n");
            } else {
                screen += &format!("│{gray}cumulative speed :{reset} {afl_speed:17.17} │ {gray}crashes saved :{reset} {red}{afl_crashes:11.11}{reset}  {blue}/{red}/{reset}     │\n");
            }
            screen += &format!(
                "│     {gray}total execs :{reset} {afl_total_execs:17.17} │{gray}timeouts saved :{reset} {afl_timeouts:17.17}   │\n"
            );
            screen += &format!("│ {gray}top inputs todo :{reset} {afl_faves:17.17} │   {gray}no find for :{reset} {afl_new_finds:17.17}   │\n");
        }
        screen += &format!(
            "├─ {blue}libafl{reset} {libafl_status:0}──────────────────────────────────────────────────────┬──┘\n"
        );
        if !libafl_status.contains("disabled") {
            screen += &format!("│         {gray}clients :{reset} {libafl_clients:17.17} │{gray}best coverage :{reset} {libafl_coverage:17.17} │\n");
            if libafl_crashes == "0" {
                screen += &format!("│{gray}cumulative speed :{reset} {libafl_speed:17.17} │{gray}crashes saved :{reset} {libafl_crashes:17.17} │\n");
            } else {
                screen += &format!("│{gray}cumulative speed :{reset} {libafl_speed:17.17} │{gray}crashes saved :{reset} {red}{libafl_crashes:17.17}{reset} │\n");
            }
            screen += &format!("│     {gray}total execs :{reset} {libafl_total_execs:17.17} │                                  │\n");
        }
        screen += &format!(
            "├─ {blue}honggfuzz{reset} {hf_status:0}─────────────────────────────────────────────────┬─┘\n"
        );
        if !hf_status.contains("disabled") {
            screen += &format!("│      {gray}threads :{reset} {hf_threads:17.17} │      {gray}coverage :{reset} {hf_coverage:17.17} │\n");
            if hf_crashes == "0" {
                screen += &format!("│{gray}average speed :{reset} {hf_speed:17.17} │ {gray}crashes saved :{reset} {hf_crashes:17.17} │\n");
            } else {
                screen += &format!("│{gray}average speed :{reset} {hf_speed:17.17} │ {gray}crashes saved :{reset} {red}{hf_crashes:17.17}{reset} │\n");
            }
            screen += &format!("│  {gray}total execs :{reset} {hf_total_execs:17.17} │{gray}timeouts saved :{reset} {hf_timeouts:17.17} │\n");
            screen += &format!("│                                  │   {gray}no find for :{reset} {hf_new_finds:17.17} │\n");
        }
        if self.coverage_worker {
            screen += &format!(
                "├─ {blue}coverage{reset} {green}enabled{reset} ───────────┬───────────────────────────────────────┘\n"
            );
            // TODO Add countdown
            screen += &format!("│{gray}status :{reset} {cov_worker_status:20.20} │\n");
            screen += "└──────────────────────────────┘";
        } else {
            screen += "└──────────────────────────────────────────────────────────────────────┘\n";
        }
        eprintln!("{screen}");
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum FuzzingConfig {
    Generic,
    Binary,
    Text,
    Blockchain,
}

impl FuzzingConfig {
    fn input_format_flag(&self) -> &str {
        match self {
            Self::Text => "-atext",
            Self::Binary => "-abinary",
            _ => "",
        }
    }
}

use std::fmt;

impl fmt::Display for FuzzingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn kill_subprocesses_recursively(pid: &str) -> Result<(), Error> {
    let subprocesses = process::Command::new("pgrep")
        .arg(format!("-P{pid}"))
        .output()?;

    for subprocess in std::str::from_utf8(&subprocesses.stdout)?.split('\n') {
        if subprocess.is_empty() {
            continue;
        }

        kill_subprocesses_recursively(subprocess)
            .context("Error in kill_subprocesses_recursively for pid {pid}")?;
    }

    unsafe {
        libc::kill(pid.parse::<i32>().unwrap(), libc::SIGTERM);
    }
    Ok(())
}

// Stop all fuzzer processes
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), Error> {
    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
    }
    Ok(())
}

pub fn extract_file_id(file: &Path) -> Option<(u32, String)> {
    let file_name = file.file_name()?.to_str()?;
    if file_name.len() < 9 {
        return None;
    }
    let (id_part, _) = file_name.split_at(9);
    let str_id = id_part.strip_prefix("id:")?;
    let file_id = str_id.parse::<u32>().ok()?;
    Some((file_id, String::from(file_name)))
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Instant};
    #[test]
    fn job_repartition_works() {
        let mut fuzz = crate::Fuzz {
            target: String::new(),
            corpus: PathBuf::new(),
            initial_corpus: None,
            ziggy_output: PathBuf::new(),
            jobs: 0,
            timeout: None,
            minimize: false,
            dictionary: None,
            max_length: 0,
            min_length: 0,
            no_afl: false,
            no_libafl: false,
            no_honggfuzz: false,
            start_time: Instant::now(),
        };
        for i in 0..1024 {
            fuzz.jobs = i;
            fuzz.no_afl = i % 7 == 0;
            fuzz.no_libafl = i % 11 == 0;
            fuzz.no_honggfuzz = i % 5 == 0;
            if i % 385 == 0 {
                continue;
            }
            let (afl_jobs, libafl_jobs, honggfuzz_jobs) = fuzz.compute_job_repartition();
            assert_eq!(
                afl_jobs + libafl_jobs + honggfuzz_jobs,
                fuzz.jobs,
                "Jobs total mismatch"
            );
        }
    }
}
