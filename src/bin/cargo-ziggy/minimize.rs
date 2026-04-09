use crate::{
    Build, Common, FuzzingEngines, Minimize,
    util::{Context, ContextView, hash_file},
};
use anyhow::{Context as _, Result, bail};
use std::{
    fs::{self, File},
    thread,
    time::Duration,
};

impl Minimize {
    pub fn minimize(&self, common: &Common) -> Result<(), anyhow::Error> {
        let cx = Context::new(common, self.target.clone())?;
        let cx_view = cx.view(common);
        let build = Build {
            no_afl: self.engine == FuzzingEngines::Honggfuzz,
            no_honggfuzz: self.engine == FuzzingEngines::AFLPlusPlus,
            release: false,
            asan: false,
            target: Some(cx.bin_target.clone()),
        };
        build.build(common).context("Failed to build the fuzzers")?;

        if fs::read_dir(self.output_corpus(&cx)).is_ok() {
            bail!(
                "Directory {} exists, please move it before running minimization",
                self.output_corpus(&cx)
            );
        }

        let entries = fs::read_dir(self.input_corpus(&cx))?;
        let original_count = entries.flatten().count();
        println!("Running minimization on a corpus of {original_count} files");

        match self.engine {
            FuzzingEngines::All => {
                std::thread::scope(|s| -> Result<()> {
                    let handle_afl = { s.spawn(move || self.minimize_afl(cx_view)) };
                    thread::sleep(Duration::from_millis(1000));
                    let handle_honggfuzz = { s.spawn(move || self.minimize_honggfuzz(cx_view)) };

                    handle_afl
                        .join()
                        .unwrap()
                        .and_then(|()| handle_honggfuzz.join().unwrap())
                })?;
            }
            FuzzingEngines::AFLPlusPlus => {
                self.minimize_afl(cx_view)?;
            }
            FuzzingEngines::Honggfuzz => {
                self.minimize_honggfuzz(cx_view)?;
            }
        }

        // We rename every file to its hash
        let out_dir = self.output_corpus(&cx);
        let min_entries = fs::read_dir(self.output_corpus(&cx))?;
        for file in min_entries.flatten() {
            if let Ok(hash) = hash_file(file.path().as_path()) {
                let _ = fs::rename(file.path(), format!("{out_dir}/{hash:x}"));
            }
        }

        let min_entries_hashed = fs::read_dir(self.output_corpus(&cx))?;
        let minimized_count = min_entries_hashed.flatten().count();
        println!("Minimized corpus contains {minimized_count} files");

        Ok(())
    }

    fn input_corpus(&self, cx: &Context) -> String {
        self.input_corpus
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target)
    }

    fn output_corpus(&self, cx: &Context) -> String {
        self.output_corpus
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &cx.bin_target)
    }

    // AFL++ minimization
    fn minimize_afl(&self, cx: ContextView) -> Result<(), anyhow::Error> {
        println!("Minimizing with AFL++");

        let jobs_option = match self.jobs {
            0 | 1 => String::from("all"),
            t => format!("{t}"),
        };
        let target_dir = cx.target_dir().join("afl/debug").join(cx.bin_target());

        // AFL++ minimization
        let log_file = File::create(format!(
            "{}/{}/logs/minimization_afl.log",
            &self.ziggy_output.display(),
            cx.bin_target(),
        ))?;
        cx.common()
            .cargo()
            .args([
                "afl",
                "cmin",
                "-i",
                &self.input_corpus(cx.as_ref()),
                "-o",
                &self.output_corpus(cx.as_ref()),
                "-T",
                &jobs_option,
                "-t",
                &format!("{}", self.timeout),
                "--",
                target_dir.as_str(),
            ])
            .stderr(log_file.try_clone()?)
            .stdout(log_file)
            .spawn()?
            .wait()?;
        Ok(())
    }

    // HONGGFUZZ minimization
    fn minimize_honggfuzz(&self, cx: ContextView) -> Result<(), anyhow::Error> {
        println!("Minimizing with honggfuzz");

        let log_file = File::create(format!(
            "{}/{}/logs/minimization_honggfuzz.log",
            &self.ziggy_output.display(),
            cx.bin_target(),
        ))?;
        cx.common()
            .cargo()
            .args(["hfuzz", "run", cx.bin_target()])
            .env("CARGO_TARGET_DIR", cx.target_dir().join("honggfuzz"))
            .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
            .env(
                "HFUZZ_WORKSPACE",
                format!(
                    "{}/{}/honggfuzz",
                    &self.ziggy_output.display(),
                    cx.bin_target()
                ),
            )
            .env(
                "HFUZZ_RUN_ARGS",
                format!(
                    "-i{} -M -o{} -t{}",
                    &self.input_corpus(cx.as_ref()),
                    &self.output_corpus(cx.as_ref()),
                    self.timeout
                ),
            )
            .stderr(log_file.try_clone()?)
            .stdout(log_file)
            .spawn()?
            .wait()?;
        Ok(())
    }
}
