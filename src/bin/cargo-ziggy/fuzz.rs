use crate::*;
use anyhow::{anyhow, Error};
use console::{style, Term};
use glob::glob;
use std::{
    env,
    fs::File,
    io::Write,
    path::Path,
    process, thread,
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

    /// Returns true if Honggfuzz is enabled
    pub fn honggfuzz(&self) -> bool {
        self.no_afl || (!self.no_honggfuzz && self.jobs > 1)
    }

    fn fuzz_binary(&self) -> bool {
        self.binary.is_some()
    }

    // Manages the continuous running of fuzzers
    pub fn fuzz(&mut self) -> Result<(), anyhow::Error> {
        let fuzz_binary = self.fuzz_binary();

        // Note: we cannot fuzz AFL++ instrumented binaries with honggfuzz so if we
        // are fuzzing an already instrumented binary - then we run AFL++ only
        if self.fuzz_binary() {
            self.no_honggfuzz = true;
        }

        if !fuzz_binary {
            let build = Build {
                no_afl: !self.afl(),
                no_honggfuzz: !self.honggfuzz(),
                release: self.release,
            };
            build.build().context("Failed to build the fuzzers")?;
        }

        info!("Running fuzzer");

        self.target = if fuzz_binary {
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

            // We create an initial corpus file, so that AFL++ starts-up properly
            let mut initial_corpus = File::create(self.corpus() + "/init")?;
            writeln!(
                &mut initial_corpus,
                "00000000000000000000********0000########111111111111111111111111"
            )?;
            drop(initial_corpus);
        }

        // We create an initial corpus file, so that AFL++ starts-up properly if corpus is empty
        let mut initial_corpus = File::create(self.corpus() + "/init")?;
        writeln!(&mut initial_corpus, "00000000")?;
        drop(initial_corpus);

        let mut processes = self.spawn_new_fuzzers()?;

        self.start_time = Instant::now();

        let mut last_synced_queue_id: u32 = 0;
        let mut last_sync_time = Instant::now();
        let mut afl_output_ok = false;

        loop {
            let sleep_duration = Duration::from_secs(1);
            thread::sleep(sleep_duration);

            self.print_stats();

            if !afl_output_ok {
                if let Ok(afl_log) =
                    fs::read_to_string(format!("{}/logs/afl.log", self.output_target()))
                {
                    if afl_log.contains("ready to roll") {
                        afl_output_ok = true;
                    } else if afl_log.contains("echo core >/proc/sys/kernel/core_pattern") {
                        stop_fuzzers(&mut processes)?;
                        eprintln!("AFL++ needs you to run the following command before it can start fuzzing:\n");
                        eprintln!("    echo core >/proc/sys/kernel/core_pattern\n");
                        return Ok(());
                    } else if afl_log.contains("cd /sys/devices/system/cpu") {
                        stop_fuzzers(&mut processes)?;
                        eprintln!("AFL++ needs you to run the following commands before it can start fuzzing:\n");
                        eprintln!("    cd /sys/devices/system/cpu");
                        eprintln!("    echo performance | tee cpu*/cpufreq/scaling_governor\n");
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
                .into()]);

            for crash_dir in crash_dirs {
                if let Ok(crashes) = fs::read_dir(crash_dir) {
                    for crash_input in crashes.flatten() {
                        let file_name = crash_input.file_name();
                        let to_path = crash_path.join(&file_name);
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
                warn!("Fuzzers stopped, check for errors!");
                return Ok(());
            }
        }
    }

    // Spawns new fuzzers
    pub fn spawn_new_fuzzers(&self) -> Result<Vec<process::Child>, anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            return Err(anyhow!(
                "Pick at least one fuzzer.\nNote: -b/--binary implies --no-honggfuzz"
            ));
        }

        info!("Spawning new fuzzers");

        let mut fuzzer_handles = vec![];

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let (afl_jobs, honggfuzz_jobs) = {
            if self.no_afl {
                (0, self.jobs)
            } else if self.no_honggfuzz {
                (self.jobs, 0)
            } else {
                // we assign roughly 2/3 to AFL++, 1/3 to honggfuzz, however do
                // not apply more than 4 jobs to honggfuzz
                match self.jobs {
                    1 => (1, 0),
                    2..=12 => (self.jobs - ((self.jobs + 2) / 3), (self.jobs + 2) / 3),
                    _ => (self.jobs - 4, 4),
                }
            }
        };

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
                // We set the fuzzer name, and if it's the main or a secondary fuzzer
                let fuzzer_name = match job_num {
                    0 => String::from("-Mmainaflfuzzer"),
                    n => format!("-Ssecondaryfuzzer{n}"),
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
                let target_path = if self.fuzz_binary() {
                    self.target.clone()
                } else {
                    format!("./target/afl/debug/{}", self.target)
                };
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
                        .args(self.afl_flags.clone())
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
            (false, false, 1) => FuzzingEngines::AFLPlusPlus,
            (false, false, _) => FuzzingEngines::All,
            (false, true, _) => FuzzingEngines::AFLPlusPlus,
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

    pub fn print_stats(&self) {
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

        // Second step: Get stats from honggfuzz logs
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

        // Third step: Get global stats
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
            "├─ {blue}honggfuzz{reset} {hf_status:0}─────────────────────────────────────────────────┬────┘\n"
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
        screen += "└──────────────────────────────────────────────────────────────────────┘";
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

    info!("Killing pid {pid}");
    unsafe {
        libc::kill(pid.parse::<i32>().unwrap(), libc::SIGTERM);
    }
    Ok(())
}

// Stop all fuzzer processes
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), Error> {
    info!("Stopping fuzzer processes");

    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
        info!("Process kill: {:?}", process.kill());
        info!("Process wait: {:?}", process.wait());
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
