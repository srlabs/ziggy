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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// Manages the continuous running of fuzzers
pub fn run_fuzzers(args: &Fuzz) -> Result<(), anyhow::Error> {
    info!("Running fuzzer");

    let mut processes = spawn_new_fuzzers(args)?;

    let parsed_corpus = args
        .corpus
        .display()
        .to_string()
        .replace("{target_name}", &args.target);

    let term = Term::stdout();

    // Variables for stats printing
    let mut execs_per_sec = String::new();
    let mut execs_done = String::new();
    let mut edges_found = String::new();
    let mut total_edges = String::new();
    let mut saved_crashes = String::new();

    let mut last_merge = Instant::now();

    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    let ziggy_crash_dir = format!("./output/{}/crashes/{}/", args.target, time);
    let ziggy_crash_path = Path::new(&ziggy_crash_dir);

    fs::create_dir_all(ziggy_crash_path)?;

    let mut crash_has_been_found = false;

    loop {
        let sleep_duration = Duration::from_millis(1000);
        thread::sleep(sleep_duration);

        // We retrieve the stats from the fuzzer_stats file
        if let Ok(file) = File::open(format!(
            "./output/{}/afl/mainaflfuzzer/fuzzer_stats",
            args.target
        )) {
            let lines = BufReader::new(file).lines();
            for maybe_line in lines {
                if let Ok(line) = maybe_line {
                    match &line[..20] {
                        "execs_per_sec     : " => execs_per_sec = String::from(&line[20..]),
                        "execs_done        : " => execs_done = String::from(&line[20..]),
                        "edges_found       : " => edges_found = String::from(&line[20..]),
                        "total_edges       : " => total_edges = String::from(&line[20..]),
                        "saved_crashes     : " => saved_crashes = String::from(&line[20..]),
                        _ => {}
                    }
                }
            }
            if saved_crashes.trim() != "0" && !saved_crashes.trim().is_empty() {
                crash_has_been_found = true;
            }
        }

        if execs_per_sec.is_empty() {
            if let Ok(afl_log) =
                fs::read_to_string(format!("./output/{}/logs/afl.log", args.target))
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
        term.write_line(&format!(
            "{} {}      ",
            style("       execs per sec :").dim(),
            utils::stringify_integer(execs_per_sec.parse::<f64>().unwrap_or_default() as u64),
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

            match minimize::minimize_corpus(
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
                        .map_err(|_| anyhow!("Could not remove main_corpus"))?;

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

            processes = spawn_new_fuzzers(args)?;
        }
    }
}

// Spawns new fuzzers
pub fn spawn_new_fuzzers(args: &Fuzz) -> Result<Vec<process::Child>, anyhow::Error> {
    // No fuzzers for you
    if args.no_afl && args.no_honggfuzz {
        return Err(anyhow!("Pick at least one fuzzer"));
    }

    info!("Spawning new fuzzers");

    let mut fuzzer_handles = vec![];

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

    let (afl_jobs, honggfuzz_jobs) = {
        if args.no_afl {
            (0, args.jobs)
        } else if args.no_honggfuzz {
            (args.jobs, 0)
        } else {
            // We assign half/half with priority to AFL++
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

            // AFL timeout is in ms so we convert the value
            let timeout_option_afl = match args.timeout {
                Some(t) => format!("-t{}", t * 1000),
                None => String::new(),
            };

            let dictionary_option = match &args.dictionary {
                Some(d) => format!("-x{}", &d.display().to_string()),
                None => String::new(),
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
                    .env("AFL_AUTORESUME", "1")
                    .env("AFL_TESTCACHE_SIZE", "100")
                    .env("AFL_FAST_CAL", "1")
                    // TODO Should we remove this?
                    .env("AFL_MAP_SIZE", "10000000")
                    .env("AFL_FORCE_UI", "1")
                    .env("AFL_FUZZER_STATS_UPDATE_INTERVAL", "1")
                    .stdout(log_destination())
                    .stderr(log_destination())
                    .spawn()?,
            )
        }
        eprintln!("{} afl           ", style("    Launched").green().bold());
    }

    if !args.no_honggfuzz {
        let dictionary_option = match &args.dictionary {
            Some(d) => format!("-w{}", &d.display().to_string()),
            None => String::new(),
        };

        let timeout_option = match args.timeout {
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
        eprintln!(
            "{} honggfuzz              ",
            style("    Launched").green().bold()
        );
    }

    eprintln!(
        "\nSee more live info by running\n  {}\nor\n  {}\n",
        style(format!("tail -f ./output/{}/logs/afl.log", args.target)).bold(),
        style(format!(
            "tail -f ./output/{}/logs/honggfuzz.log",
            args.target
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
    eprintln!("");
    eprintln!("   Waiting for afl++ to");
    eprintln!("   finish executing the");
    eprintln!("   existing corpus once");
    eprintln!("\n\n");

    Ok(fuzzer_handles)
}

pub fn kill_subprocesses_recursively(pid: &str) -> Result<(), anyhow::Error> {
    info!("Killing pid {pid}");

    let subprocesses = process::Command::new("pgrep")
        .arg(&format!("-P{pid}"))
        .output()?;

    for subprocess in std::str::from_utf8(&subprocesses.stdout)?.split('\n') {
        if subprocess.is_empty() {
            continue;
        }

        kill_subprocesses_recursively(subprocess)
            .context("Error in kill_subprocesses_recursively for pid {pid}")?;

        process::Command::new("kill")
            .arg(subprocess)
            .output()
            .context("Error killing subprocess: {subprocess}")?;
    }
    Ok(())
}

// Stop all fuzzer processes
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), anyhow::Error> {
    info!("Stopping fuzzer processes");

    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
        process.kill()?;
        process.wait()?;
    }
    Ok(())
}

// Share AFL++ corpora in the shared_corpus directory
pub fn share_all_corpora(args: &Fuzz, parsed_corpus: &String) -> Result<()> {
    for path in glob(&format!("./output/{}/afl/**/queue/*", args.target))
        .map_err(|_| anyhow!("Failed to read glob pattern"))?
        .flatten()
    {
        if path.is_file() {
            fs::copy(
                path.to_str()
                    .ok_or_else(|| anyhow!("Could not parse input path"))?,
                format!(
                    "{}/{}",
                    &parsed_corpus,
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
