use crate::{find_target, Cover};
use anyhow::{anyhow, Context, Result};
use async_std::stream::StreamExt;
use std::{env, fs, io::Write, path::PathBuf, process, sync::Arc};
use tokio::{runtime, sync::Semaphore};

impl Cover {
    async fn execute_on_file(
        semaphore: Arc<Semaphore>,
        input_path: impl AsRef<async_std::path::Path>,
        cmd: String,
        profile_format: String,
    ) {
        // Acquire a permit from the semaphore.
        let _permit = semaphore.acquire().await;

        println!("Running {} ...", &input_path.as_ref().display().to_string());

        let result = process::Command::new(cmd)
            .arg(input_path.as_ref().display().to_string())
            .env("LLVM_PROFILE_FILE", profile_format)
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        if !result.status.success() {
            eprintln!(
                "Coverage crashed on {}, continuing.",
                input_path.as_ref().display()
            )
        }

        // _permit is dropped here, releasing the permit back to the semaphore.
    }

    async fn async_coverage(max_tasks: usize, input_dir: &PathBuf, cmd: String, prof: String) {
        let semaphore = Arc::new(Semaphore::new(max_tasks));
        // Read the directory
        let mut entries = async_std::fs::read_dir(input_dir)
            .await
            .expect("Failed to read directory");
        let mut tasks = Vec::new();

        while let Some(entry) = entries.next().await {
            let path = entry.expect("Failed to read directory entry").path();
            if path.is_file().await {
                let sem_clone = semaphore.clone();
                let task = tokio::task::spawn(Self::execute_on_file(
                    sem_clone,
                    path,
                    cmd.clone(),
                    prof.clone(),
                ));
                tasks.push(task);
            }
        }

        // Await all tasks to complete
        for task in tasks {
            task.await.expect("Task panicked");
        }
    }

    pub fn check_program(cmd: &str) {
        let msg = format!("⚠️  couldn't spawn {}, please install!\nError", cmd);
        process::Command::new(cmd)
            .args(["--help"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect(&msg)
            .wait()
            .unwrap();
    }

    pub fn generate_coverage(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Generating coverage");

        Self::check_program("llvm-profdata");
        Self::check_program("llvm-cov");

        self.target =
            find_target(&self.target).context("⚠️  couldn't find the target to start coverage")?;

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let coverage_rustflags = env::var("COVERAGE_RUSTFLAGS").unwrap_or_else(|_| String::from("--cfg=coverage -Zinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"));

        // We build the runner with the appropriate flags for coverage
        process::Command::new(cargo)
            .args(["rustc", "--target-dir=target/coverage"])
            .env("RUSTFLAGS", coverage_rustflags)
            .env("RUSTDOCFLAGS", "-Cpanic=unwind")
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTC_BOOTSTRAP", "1") // Trick to avoid forcing user to use rust nightly
            .spawn()
            .context("⚠️  couldn't spawn rustc for coverage")?
            .wait()
            .context("⚠️  couldn't wait for the rustc during coverage")?;

        let prof_dir = format!("output/{}/profdata", &self.target);
        fs::remove_dir_all(&prof_dir).unwrap_or_default();
        if fs::metadata(&prof_dir)
            .map(|meta| meta.is_dir())
            .unwrap_or(false)
        {
            panic!("Please remove {:?} first", prof_dir);
        }

        let mut shared_corpus = PathBuf::new();

        shared_corpus.push(
            self.corpus
                .display()
                .to_string()
                .replace("{target_name}", &self.target)
                .as_str(),
        );

        let mut afl_dir = PathBuf::new();
        afl_dir.push(
            shared_corpus
                .display()
                .to_string()
                .replace("/shared_corpus", "/afl/mainaflfuzzer/queue")
                .as_str(),
        );

        if afl_dir.is_dir() {
            shared_corpus = afl_dir;
        }

        info!("Corpus directory is {}", shared_corpus.display());

        // parallel execution of the coverage target with the inputs
        let cmd = format!("./target/coverage/debug/{}", &self.target);
        let profile_format = format!("{}/coverage-%p.profraw", &prof_dir);
        let runtime = runtime::Runtime::new().unwrap();
        runtime.block_on(Self::async_coverage(
            self.jobs,
            &shared_corpus,
            cmd.clone(),
            profile_format,
        ));

        // the profile data is saved to prof_dir, for the next step these
        // files have to be written into a text file.
        println!();
        println!("Collecting profile files ...");
        let mut prof_files: Vec<String> = vec![];
        let prof_directory: PathBuf = (&prof_dir).into();
        prof_directory
            .canonicalize()?
            .read_dir()?
            .for_each(|input| {
                prof_files.push(input.unwrap().path().display().to_string());
            });
        let prof_collection = format!("{}/files.txt", &prof_dir);
        let mut fd = fs::File::create(&prof_collection)?;
        for line in &prof_files {
            writeln!(fd, "{}", line)?;
        }
        let _ = fd.flush();

        // now we merge the profile data
        println!("Merging profile data ...");
        let prof_merged = format!("{}/merged.profdata", &prof_dir);
        process::Command::new("llvm-profdata")
            .args([
                "merge",
                "-o",
                &prof_merged,
                "-f",
                &prof_collection,
                &format!("--num-threads={}", self.jobs),
            ])
            .spawn()
            .context("⚠️  cannot find llvm-profdata in your path, please install it")?
            .wait()
            .context("⚠️  couldn't wait for the llvm-profdata process")?;

        println!("Generating coverage report ...");

        let output_dir = self
            .output
            .display()
            .to_string()
            .replace("{target_name}", &self.target);

        // We remove the previous coverage
        if let Err(error) = fs::remove_dir_all(&output_dir) {
            match error.kind() {
                std::io::ErrorKind::NotFound => {}
                e => return Err(anyhow!(e)),
            }
        };

        process::Command::new("llvm-cov")
            .args([
                "show",
                "-format=html",
                &format!("-output-dir={}", &output_dir),
                &cmd,
                &format!("-instr-profile={}", &prof_merged),
            ])
            .spawn()
            .context("⚠️  cannot find llvm-profdata in your path, please install it")?
            .wait()
            .context("⚠️  couldn't wait for the llvm-profdata process")?;

        println!();
        println!("Coverage report is ready at {}", output_dir);
        Ok(())
    }
}
