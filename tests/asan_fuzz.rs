use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    process,
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

static EXCLUSIVE: Mutex<()> = Mutex::new(());

fn exclusive_guard() -> MutexGuard<'static, ()> {
    EXCLUSIVE.lock().unwrap_or_else(|e| {
        EXCLUSIVE.clear_poison();
        e.into_inner()
    })
}
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

#[allow(clippy::zombie_processes)]
#[test]
fn afl_crashes() {
    let _guard = exclusive_guard();
    // Not optimal but seems to work fine
    if !env!("CARGO").contains("nightly") {
        println!("Not running nightly, skipping");
        return;
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
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
        .arg("--no-honggfuzz")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(
        temp_dir_path
            .join("asan-fuzz")
            .join("afl")
            .join("mainaflfuzzer")
            .join("fuzzer_stats")
            .is_file()
    );
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

#[allow(clippy::zombie_processes)]
#[test]
fn afl_release_crashes() {
    let _guard = exclusive_guard();
    // Not optimal but seems to work fine
    if !env!("CARGO").contains("nightly") {
        println!("Not running nightly, skipping");
        return;
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
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
        .arg("--release")
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
        .arg("--release")
        .arg("--no-honggfuzz")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(
        temp_dir_path
            .join("asan-fuzz")
            .join("afl")
            .join("mainaflfuzzer")
            .join("fuzzer_stats")
            .is_file()
    );
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

#[allow(clippy::zombie_processes)]
#[test]
fn honggfuzz_crashes() {
    let _guard = exclusive_guard();
    // Not optimal but seems to work fine
    if !env!("CARGO").contains("nightly") {
        println!("Not running nightly, skipping");
        return;
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("asan");

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .arg("--asan")
        .arg("--no-afl")
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    // provide unlocking seed
    std::fs::create_dir_all(temp_dir_path.join("asan-fuzz/corpus")).unwrap();
    let mut file = std::fs::File::create(temp_dir_path.join("asan-fuzz/corpus/unlock")).unwrap();
    file.write_all(b"fuzzer").unwrap();

    // cargo ziggy fuzz --asan
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("--asan")
        .arg("--no-afl")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(5));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(
        fs::read_dir(temp_dir_path.join("asan-fuzz/honggfuzz/asan-fuzz"))
            .unwrap()
            .filter(|entry| {
                entry.as_ref().is_ok_and(|entry| {
                    entry
                        .path()
                        .file_name()
                        .and_then(std::ffi::OsStr::to_str)
                        .is_some_and(|n| n.starts_with("SIGABRT"))
                })
            })
            .count()
            != 0
    );
}

#[allow(clippy::zombie_processes)]
#[test]
fn honggfuzz_builds_once() {
    let _guard = exclusive_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path().join("output");
    let target_dir = temp_dir.path().join("target");
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let cargo_ziggy = metadata.target_directory.join("debug/cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples/asan");
    let hfuzz_dir = output_dir.join("asan-fuzz/honggfuzz");

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .arg("--no-afl")
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");
    assert!(build_status.success(), "`cargo ziggy build` failed");

    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("--no-afl")
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("ZIGGY_OUTPUT", &output_dir)
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(1));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));
    assert!(hfuzz_dir.is_dir());

    if !env!("CARGO").contains("nightly") {
        return;
    }
    std::fs::remove_dir_all(&hfuzz_dir).unwrap();
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .arg("--no-afl")
        .arg("--asan")
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");
    assert!(build_status.success(), "`cargo ziggy build` failed");

    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("--no-afl")
        .arg("--asan")
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("ZIGGY_OUTPUT", &output_dir)
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(1));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));
    assert!(hfuzz_dir.is_dir());
}
