use std::{
    fs,
    path::PathBuf,
    process::{self, ExitStatus},
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
fn integration() {
    let _guard = exclusive_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("url");

    // TODO Custom target path

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    // cargo ziggy fuzz -j 2 -t 5
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(temp_dir_path
        .join("url-fuzz")
        .join("afl")
        .join("mainaflfuzzer")
        .join("fuzzer_stats")
        .is_file());
    assert!(temp_dir_path
        .join("url-fuzz")
        .join("honggfuzz")
        .join("url-fuzz")
        .join("input")
        .is_dir());

    // We resume fuzzing
    // cargo ziggy fuzz -j 2 -t 5
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    // cargo ziggy minimize
    let minimization = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("minimize")
        .arg("-j2")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy minimize`");

    assert!(minimization.success());
    assert!(temp_dir_path
        .join("url-fuzz")
        .join("logs")
        .join("minimization_afl.log")
        .is_file());

    fs::remove_dir_all(temp_dir_path.join("url-fuzz").join("corpus_minimized")).unwrap();

    // cargo ziggy minimize -e honggfuzz
    let minimization = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("minimize")
        .arg("-ehonggfuzz")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy minimize`");

    assert!(minimization.success());
    assert!(temp_dir_path
        .join("url-fuzz")
        .join("logs")
        .join("minimization_honggfuzz.log")
        .is_file());

    // cargo ziggy cover
    let coverage = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("cover")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy cover`");

    assert!(coverage.success());
    assert!(temp_dir_path
        .join("url-fuzz")
        .join("coverage")
        .join("index.html")
        .is_file());

    // cargo ziggy plot
    let plot = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("plot")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy plot`");

    assert!(plot.success());
    assert!(temp_dir_path
        .join("url-fuzz")
        .join("plot")
        .join("index.html")
        .is_file());
}

#[allow(clippy::zombie_processes)]
#[test]
fn coverage_regression() {
    let _guard = exclusive_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("url");

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    // cargo ziggy fuzz -j 2 -t 5
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .arg("--no-honggfuzz")
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    // cargo ziggy cover lcov regression test
    let coverage: ExitStatus = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("cover")
        .arg("--output-types")
        .arg("lcov")
        .arg("--output")
        .arg(temp_dir_path.join("url-fuzz").join("cover_lcov"))
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("Failed to run lcov coverage");

    let coverage_second: ExitStatus = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("cover")
        .arg("--output-types")
        .arg("lcov")
        .arg("--output")
        .arg(temp_dir_path.join("url-fuzz").join("cover_lcov"))
        .env("ZIGGY_OUTPUT", format!("{}", temp_dir_path.display()))
        .current_dir(&fuzzer_directory)
        .status()
        .expect("Failed to run lcov coverage");

    assert!(coverage.success());
    assert!(coverage_second.success());
    assert!(temp_dir_path.join("url-fuzz").join("cover_lcov").is_file());
}

#[allow(clippy::zombie_processes)]
#[test]
fn fuzz_binary() {
    let _guard = exclusive_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug/cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples/url");
    let binary_path = temp_dir_path.join("binary");

    // cargo ziggy build
    let build_status = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("build")
        .arg("--no-honggfuzz")
        .current_dir(&fuzzer_directory)
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    std::fs::create_dir_all(temp_dir_path).expect("failed creating output dir");
    std::fs::copy(target_directory.join("afl/debug/url-fuzz"), &binary_path)
        .expect("failed to move instrumented binary into output dir");

    // cargo ziggy fuzz -j 2 -t 5
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-b")
        .arg(&binary_path)
        .arg("--no-honggfuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .env("ZIGGY_OUTPUT", temp_dir_path)
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(temp_dir_path)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(temp_dir_path
        .join("afl/mainaflfuzzer/fuzzer_stats")
        .is_file());

    // We resume fuzzing
    // cargo ziggy fuzz -j 2 -t 5
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-b")
        .arg(&binary_path)
        .arg("--no-honggfuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .env("ZIGGY_OUTPUT", temp_dir_path)
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(temp_dir_path)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));
}

#[allow(clippy::zombie_processes)]
#[test]
fn clean() {
    let _guard = exclusive_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug/cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples/url");

    {
        let afl_build_path = target_directory.join("afl/debug/url-fuzz");
        let hfuzz_build_path = target_directory.join(format!(
            "honggfuzz/{}/debug/url-fuzz",
            target_triple::TARGET
        ));

        // cargo ziggy build
        let build_status = process::Command::new(&cargo_ziggy)
            .arg("ziggy")
            .arg("build")
            .current_dir(&fuzzer_directory)
            .status()
            .expect("failed to run `cargo ziggy build`");

        assert!(build_status.success(), "`cargo ziggy build` failed");
        assert!(afl_build_path.is_file(), "no afl harness");
        assert!(hfuzz_build_path.is_file(), "no honggfuzz harness");

        let clean_status = process::Command::new(&cargo_ziggy)
            .args(["ziggy", "clean", "-p", "url-fuzz"])
            .current_dir(&fuzzer_directory)
            .status()
            .expect("failed to run `cargo ziggy clean`");
        assert!(clean_status.success(), "`cargo ziggy clean` failed");
        assert!(!afl_build_path.exists(), "afl harness not cleaned");
        assert!(!hfuzz_build_path.exists(), "honggfuzz harness not cleaned");
    }

    {
        // use temp_dir_path as target-dir
        let afl_build_path = temp_dir_path.join("afl/debug/url-fuzz");
        let hfuzz_build_path = temp_dir_path.join(format!(
            "honggfuzz/{}/debug/url-fuzz",
            target_triple::TARGET
        ));

        // cargo ziggy build
        let build_status = process::Command::new(&cargo_ziggy)
            .arg("ziggy")
            .arg("build")
            .env("CARGO_TARGET_DIR", temp_dir_path)
            .current_dir(&fuzzer_directory)
            .status()
            .expect("failed to run `cargo ziggy build`");

        assert!(build_status.success(), "`cargo ziggy build` failed");
        assert!(afl_build_path.is_file(), "no afl harness");
        assert!(hfuzz_build_path.is_file(), "no honggfuzz harness");

        let clean_status = process::Command::new(&cargo_ziggy)
            .args(["ziggy", "clean", "-p", "url-fuzz"])
            .env("CARGO_TARGET_DIR", temp_dir_path)
            .current_dir(&fuzzer_directory)
            .status()
            .expect("failed to run `cargo ziggy clean`");
        assert!(clean_status.success(), "`cargo ziggy clean` failed");
        assert!(!afl_build_path.exists(), "afl harness not cleaned");
        assert!(!hfuzz_build_path.exists(), "honggfuzz harness not cleaned");
    }
}
