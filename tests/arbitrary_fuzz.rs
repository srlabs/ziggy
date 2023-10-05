use std::{env, fs, path::PathBuf, process, thread, time::Duration};

fn kill_subprocesses_recursively(pid: &str) {
    let subprocesses = process::Command::new("pgrep")
        .arg(&format!("-P{pid}"))
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
fn integration() {
    let temp_dir_path = env::temp_dir();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_root: PathBuf = metadata.workspace_root.into();
    let target_directory: PathBuf = metadata.target_directory.into();
    let cargo_ziggy = target_directory.join("debug").join("cargo-ziggy");
    let fuzzer_directory = workspace_root.join("examples").join("arbitrary");

    // TODO Custom target path

    // cargo ziggy build
    let build_status = process::Command::new(cargo_ziggy.clone())
        .arg("ziggy")
        .arg("build")
        .current_dir(fuzzer_directory.clone())
        .status()
        .expect("failed to run `cargo ziggy build`");

    assert!(build_status.success(), "`cargo ziggy build` failed");

    // cargo ziggy fuzz -j 2 -t 5 -o temp_dir
    let fuzzer = process::Command::new(cargo_ziggy)
        .arg("ziggy")
        .arg("fuzz")
        .arg("-j2")
        .arg("-t5")
        .arg(format!("-o{}", temp_dir_path.display()))
        .current_dir(fuzzer_directory)
        .spawn()
        .expect("failed to run `cargo ziggy fuzz`");
    thread::sleep(Duration::from_secs(10));
    kill_subprocesses_recursively(&format!("{}", fuzzer.id()));

    assert!(temp_dir_path
        .join("arbitrary-fuzz")
        .join("afl")
        .join("mainaflfuzzer")
        .join("fuzzer_stats")
        .is_file());
    assert!(fs::read_dir(
        temp_dir_path
            .join("arbitrary-fuzz")
            .join("afl")
            .join("mainaflfuzzer")
            .join("crashes")
    )
    .unwrap()
    .count() != 0);
    assert!(temp_dir_path
        .join("arbitrary-fuzz")
        .join("honggfuzz")
        .join("arbitrary-fuzz")
        .join("input")
        .is_dir());
}
