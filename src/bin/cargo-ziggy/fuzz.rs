use crate::*;
use anyhow::{anyhow, Context, Result};
use console::{style, Term};
use glob::glob;
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    net::UdpSocket,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// Manages the continuous running of fuzzers
pub fn run_fuzzers(args: &Fuzz) -> Result<(), anyhow::Error> {
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
pub fn spawn_new_fuzzers(args: &Fuzz) -> Result<(Vec<process::Child>, u16), anyhow::Error> {
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

pub fn kill_subprocesses_recursively(pid: &str) -> Result<(), anyhow::Error> {
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
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), anyhow::Error> {
    println!("📋  Stopping fuzzer processes");

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
