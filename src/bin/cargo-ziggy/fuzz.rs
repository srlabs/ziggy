use crate::*;
use anyhow::{anyhow, Context, Result};
use console::{style, Term};
use glob::glob;
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

impl Fuzz {
    // Manages the continuous running of fuzzers
    pub fn fuzz(&mut self) -> Result<(), anyhow::Error> {
        let build = Build {
            no_afl: self.no_afl,
            no_honggfuzz: self.no_honggfuzz,
        };
        build.build().context("Failed to build the fuzzers")?;

        info!("Running fuzzer");

        self.target = find_target(&self.target)?;

        let fuzzer_stats_file = format!("./output/{}/afl/mainaflfuzzer/fuzzer_stats", self.target);

        let term = Term::stdout();

        // Variables for stats printing
        let mut exec_speed = String::new();
        let mut execs_done = String::new();
        let mut edges_found = String::new();
        let mut total_edges = String::new();
        let mut saved_crashes = String::new();

        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        let ziggy_crash_dir = format!("./output/{}/crashes/{}/", self.target, time);
        let ziggy_crash_path = Path::new(&ziggy_crash_dir);

        fs::create_dir_all(ziggy_crash_path)?;

        self.share_all_corpora()?;

        let _ = process::Command::new("mkdir")
            .args(["-p", &format!("./output/{}/logs/", self.target)])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        if Path::new(&self.parsed_corpus()).exists() {
            if !self.skip_initial_minimization {
                self.run_minimization()?;
            }
        } else {
            let _ = process::Command::new("mkdir")
                .args(["-p", &self.parsed_corpus()])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;

            // We create an initial corpus file, so that AFL++ starts-up properly
            let mut initial_corpus = File::create(self.parsed_corpus() + "/init")?;
            writeln!(&mut initial_corpus, "00000000")?;
            drop(initial_corpus);
        }

        let mut processes = self.spawn_new_fuzzers()?;

        let mut crash_has_been_found = false;

        loop {
            let sleep_duration = Duration::from_millis(1000);
            thread::sleep(sleep_duration);

            // We retrieve the stats from the fuzzer_stats file
            if let Ok(file) = File::open(fuzzer_stats_file.clone()) {
                let lines = BufReader::new(file).lines();
                for line in lines.flatten() {
                    match &line[..20] {
                        "execs_ps_last_min : " => exec_speed = String::from(&line[20..]),
                        "execs_done        : " => execs_done = String::from(&line[20..]),
                        "edges_found       : " => edges_found = String::from(&line[20..]),
                        "total_edges       : " => total_edges = String::from(&line[20..]),
                        "saved_crashes     : " => saved_crashes = String::from(&line[20..]),
                        _ => {}
                    }
                }
                if saved_crashes.trim() != "0" && !saved_crashes.trim().is_empty() {
                    crash_has_been_found = true;
                }
            }

            if exec_speed.is_empty() || exec_speed == "0.00" {
                if let Ok(afl_log) =
                    fs::read_to_string(format!("./output/{}/logs/afl.log", self.target))
                {
                    if afl_log.contains("echo core >/proc/sys/kernel/core_pattern") {
                        stop_fuzzers(&mut processes)?;
                        eprintln!("AFL++ needs you to run the following command before it can start fuzzing:\n");
                        eprintln!("    echo core >/proc/sys/kernel/core_pattern\n");
                        return Ok(());
                    }
                    if afl_log.contains("cd /sys/devices/system/cpu") {
                        stop_fuzzers(&mut processes)?;
                        eprintln!("AFL++ needs you to run the following commands before it can start fuzzing:\n");
                        eprintln!("    cd /sys/devices/system/cpu");
                        eprintln!("    echo performance | tee cpu*/cpufreq/scaling_governor\n");
                        return Ok(());
                    }
                }
            }

            // We print the new values
            term.move_cursor_up(7)?;
            let exec_speed_formated = match exec_speed.as_str() {
                "0.00" | "" => String::from("..."),
                _ => utils::stringify_integer(exec_speed.parse::<f64>().unwrap_or_default() as u64),
            };
            term.write_line(&format!(
                "{} {}/sec  ",
                style("          exec speed :").dim(),
                exec_speed_formated,
            ))?;
            term.write_line(&format!(
                "{} {}      ",
                style("          execs done :").dim(),
                utils::stringify_integer(execs_done.parse().unwrap_or_default()),
            ))?;
            let edges_percentage = 100f64 * edges_found.parse::<f64>().unwrap_or_default()
                / total_edges.parse::<f64>().unwrap_or(1f64);
            term.write_line(&format!(
                "{} {} ({:.2}%)          ",
                style("         edges found :").dim(),
                utils::stringify_integer(edges_found.parse().unwrap_or_default()),
                &edges_percentage
            ))?;
            term.write_line(&format!(
                "{} {}         ",
                style("       saved crashes :").dim(),
                utils::stringify_integer(saved_crashes.parse().unwrap_or_default()),
            ))?;
            if crash_has_been_found {
                term.write_line("\nCrashes have been found       ")?;
            } else {
                term.write_line("\nNo crash has been found so far")?;
            }
            term.write_line("")?;

            // We only start checking for crashes after AFL++ has started responding to us
            if !exec_speed.is_empty() || exec_speed == "0.00" {
                // We check AFL++ and Honggfuzz's outputs for crash files
                //let afl_crash_dir = format!("./output/{}/afl/mainaflfuzzer/crashes/", self.target);

                let crash_dirs = glob(&format!("./output/{}/afl/*/crashes", self.target))
                    .map_err(|_| anyhow!("Failed to read crashes glob pattern"))?
                    .flatten()
                    .chain(vec![format!(
                        "./output/{}/honggfuzz/{}/",
                        self.target, self.target
                    )
                    .into()]);

                for crash_dir in crash_dirs {
                    if let Ok(crashes) = fs::read_dir(crash_dir) {
                        for crash_input in crashes.flatten() {
                            let file_name = crash_input.file_name();
                            let to_path = ziggy_crash_path.join(&file_name);
                            if to_path.exists()
                                || ["", "README.txt", "HONGGFUZZ.REPORT.TXT", "input"]
                                    .contains(&file_name.to_str().unwrap_or_default())
                            {
                                continue;
                            }
                            crash_has_been_found = true;
                            fs::copy(crash_input.path(), to_path)?;
                        }
                    }
                }
            }

            // Every DEFAULT_MINIMIZATION_TIMEOUT, the fuzzers will stop and we will minimize the
            // shared corpus, before launching the fuzzers again
            if processes
                .iter_mut()
                .all(|p| p.try_wait().unwrap_or(None).is_some())
            {
                stop_fuzzers(&mut processes)?;

                self.run_minimization()?;

                processes = self.spawn_new_fuzzers()?;
            }
        }
    }

    // Spawns new fuzzers
    pub fn spawn_new_fuzzers(&self) -> Result<Vec<process::Child>, anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            return Err(anyhow!("Pick at least one fuzzer"));
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

        if !self.no_afl && afl_jobs > 0 {
            let _ = process::Command::new("mkdir")
                .args(["-p", &format!("./output/{}/afl", self.target)])
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
                    0 => format!("-F{}", &self.parsed_corpus()),
                    _ => String::new(),
                };
                let use_initial_corpus_dir = match (&self.initial_corpus, job_num) {
                    (Some(initial_corpus), 0) => {
                        format!("-F{}", &initial_corpus.display().to_string())
                    }
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
                // Only cmplog for the first two instances
                let cmplog_options = match job_num {
                    0 => "-l2",
                    1 => "-l2a",
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
                let log_destination = || match job_num {
                    0 => File::create(format!("output/{}/logs/afl.log", self.target))
                        .unwrap()
                        .into(),
                    1 => File::create(format!("output/{}/logs/afl_1.log", self.target))
                        .unwrap()
                        .into(),
                    _ => process::Stdio::null(),
                };
                let final_sync = match job_num {
                    0 => "1",
                    _ => "0",
                };

                fuzzer_handles.push(
                    process::Command::new(cargo.clone())
                        .args(
                            [
                                "afl",
                                "fuzz",
                                &fuzzer_name,
                                &format!("-i{}", &self.parsed_corpus()),
                                &format!("-p{power_schedule}"),
                                &format!("-ooutput/{}/afl", self.target),
                                &format!("-g{}", self.min_length),
                                &format!("-G{}", self.max_length),
                                &use_shared_corpus,
                                &use_initial_corpus_dir,
                                &format!(
                                    "-V{}",
                                    self.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL
                                ),
                                old_queue_cycling,
                                cmplog_options,
                                mopt_mutator,
                                &timeout_option_afl,
                                &dictionary_option,
                                &format!("./target/afl/debug/{}", self.target),
                            ]
                            .iter()
                            .filter(|a| a != &&""),
                        )
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
                        .env("AFL_FINAL_SYNC", final_sync) // upcoming in v4.09c
                        .env("AFL_IGNORE_SEED_PROBLEMS", "1") // upcoming in v4.09c
                        .stdout(log_destination())
                        .stderr(log_destination())
                        .spawn()?,
                )
            }
            eprintln!("{} afl           ", style("    Launched").green().bold());
        }

        if !self.no_honggfuzz && honggfuzz_jobs > 0 {
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
                        format!("./output/{}/honggfuzz", self.target),
                    )
                    .env(
                        "HFUZZ_RUN_ARGS",
                        format!(
                            "--run_time={} -i{} -n{} -F{} {timeout_option} {dictionary_option}",
                            self.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL,
                            &self.parsed_corpus(),
                            honggfuzz_jobs,
                            self.max_length,
                        ),
                    )
                    .stdin(std::process::Stdio::null())
                    .stderr(File::create(format!(
                        "./output/{}/logs/honggfuzz.log",
                        self.target
                    ))?)
                    .stdout(File::create(format!(
                        "./output/{}/logs/honggfuzz.log",
                        self.target
                    ))?)
                    .spawn()?,
            );
            eprintln!(
                "{} honggfuzz              ",
                style("    Launched").green().bold()
            );
        }

        eprintln!(
            "\nSee more live info by running\n  {}\nor\n  {}\n",
            style(format!("tail -f ./output/{}/logs/afl.log", self.target)).bold(),
            style(format!(
                "tail -f ./output/{}/logs/honggfuzz.log",
                self.target
            ))
            .bold(),
        );
        eprintln!(
            "{}",
            &style("    AFL++ main process stats")
                .yellow()
                .bold()
                .to_string()
        );
        eprintln!();
        eprintln!("   Waiting for afl++ to");
        eprintln!("   finish executing the");
        eprintln!("   existing corpus once");
        eprintln!("\n\n");

        Ok(fuzzer_handles)
    }

    // Share AFL++ corpora in the shared_corpus directory
    pub fn share_all_corpora(&self) -> Result<()> {
        for path in glob(&format!("./output/{}/afl/*/queue/*", self.target))
            .map_err(|_| anyhow!("Failed to read glob pattern"))?
            .flatten()
        {
            if path.is_file() {
                fs::copy(
                    path.to_str()
                        .ok_or_else(|| anyhow!("Could not parse input path"))?,
                    format!(
                        "{}/{}",
                        &self.parsed_corpus(),
                        path.file_name()
                            .ok_or_else(|| anyhow!("Could not parse input file name"))?
                            .to_str()
                            .ok_or_else(|| anyhow!("Could not parse input file name path"))?
                    ),
                )?;
            }
        }
        Ok(())
    }

    pub fn run_minimization(&self) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!(
            "\n    {}",
            &style("Running minimization").magenta().bold()
        ))?;

        self.share_all_corpora()?;

        let old_corpus_size = fs::read_dir(self.parsed_corpus())
            .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

        let minimized_corpus = DEFAULT_MINIMIZATION_CORPUS.replace("{target_name}", &self.target);

        process::Command::new("rm")
            .args(["-r", &minimized_corpus])
            .output()
            .map_err(|_| anyhow!("Could not remove minimized corpus directory"))?;

        let mut minimization_args = Minimize {
            target: self.target.clone(),
            input_corpus: PathBuf::from(&self.parsed_corpus()),
            output_corpus: PathBuf::from(&minimized_corpus),
            jobs: self.jobs,
        };
        match minimization_args.minimize() {
            Ok(_) => {
                let new_corpus_size = fs::read_dir(&minimized_corpus)
                    .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

                term.move_cursor_up(1)?;

                if new_corpus_size == *"err" || new_corpus_size == *"0" {
                    term.write_line("error during minimization... please check the logs and make sure the right version of the fuzzers are installed")?;
                } else {
                    term.write_line(&format!(
                        "{} the corpus ({} -> {} files)             \n",
                        style("    Minimized").magenta().bold(),
                        old_corpus_size,
                        new_corpus_size
                    ))?;

                    fs::remove_dir_all(self.parsed_corpus())?;
                    fs::rename(minimized_corpus, self.parsed_corpus())?;
                }
            }
            Err(_) => {
                term.write_line("error running minimization... probably a memory error")?;
            }
        };
        Ok(())
    }

    pub fn parsed_corpus(&self) -> String {
        self.corpus
            .display()
            .to_string()
            .replace("{target_name}", &self.target)
    }
}

pub fn kill_subprocesses_recursively(pid: &str) -> Result<(), anyhow::Error> {
    let subprocesses = process::Command::new("pgrep")
        .arg(&format!("-P{pid}"))
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
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), anyhow::Error> {
    info!("Stopping fuzzer processes");

    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
        info!("Process kill: {:?}", process.kill());
        info!("Process wait: {:?}", process.wait());
    }
    Ok(())
}
