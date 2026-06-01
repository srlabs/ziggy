use std::{path::PathBuf, process, thread, time::Duration};

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
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_dir_path = temp_dir.path();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("unstable");

    // cargo ziggy fuzz -j 2 -t 5 -o temp_dir
    let fuzzer = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-j2")
        .arg("-t5")
        .arg("-G100")
        .env("ZIGGY_OUTPUT", temp_dir_path)
        .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        .env("AFL_SKIP_CPUFREQ", "1")
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(
        temp_dir_path
            .join("unstable-fuzz/afl/mainaflfuzzer/fuzzer_stats")
            .is_file()
    );

    let stability = process::Command::new(&cargo_ziggy)
        .arg("ziggy")
        .arg("stability")
        .env("ZIGGY_OUTPUT", temp_dir_path)
        .current_dir(&fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy stability`");
    thread::sleep(Duration::from_secs(30));
    kill_subprocesses_recursively(&format!("{}", stability.id()));
}
