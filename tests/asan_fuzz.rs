use std::{
    env, fs,
    path::PathBuf,
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn kill_subprocesses_recursively(pid: &str) {
    let subprocesses = process::Command::new("pgrep")
        .arg(format!("-P{pid}"))
        .output()
        .unwrap();

    for subprocess in std::str::from_utf8(&subprocesses.stdout)
        .unwrap()
        .split('\n')
    {
        if subprocess.is_empty() {
            continue;
        }

        kill_subprocesses_recursively(subprocess);
    }

    println!("Killing pid {pid}");
    unsafe {
        libc::kill(pid.parse::<i32>().unwrap(), libc::SIGTERM);
    }
}

#[test]
fn asan_crashes() {
    // Not optimal but seems to work fine
    if !env!("CARGO").contains("nightly") {
        println!("Not running nightly, skipping");
        return;
    }
    let unix_time = format!(
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let temp_dir_path = env::temp_dir().join(unix_time);
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("asan");

    // TODO Custom target path

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .arg("--asan")
        .arg("--no-honggfuzz")
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    // cargo ziggy fuzz --asan
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("--asan")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(40));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(temp_dir_path
        .join("asan-fuzz")
        .join("afl")
        .join("mainaflfuzzer")
        .join("fuzzer_stats")
        .is_file());
    assert!(
        fs::read_dir(
            temp_dir_path
                .join("asan-fuzz")
                .join("afl")
                .join("mainaflfuzzer")
                .join("crashes")
        )
        .unwrap()
        .count()
            != 0
    );
}
