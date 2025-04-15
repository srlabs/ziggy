use crate::{find_target, Cover, CoverCpp};
use anyhow::{anyhow, Context, Result};
use cmake::Config;
use glob::glob;
use std::process::Command;
use std::{env, fs, path::PathBuf, process};

impl CoverCpp {
    pub fn generate_coverage(&mut self) -> Result<(), anyhow::Error> {
        // build the runner
        Self::build_runner()?;

        // We remove the previous coverage files
        if !self.keep {
            Cover::clean_old_cov()?;
        }
        Ok(())
    }

    /// Build the runner with the appropriate flags for coverage
    pub fn build_runner() -> Result<(), anyhow::Error> {
        eprintln!("Please, ensure you are at the root of your project ALSO where your global CMakeList.txt is");

        let common_flags =
            "-fprofile-arcs -ftest-coverage -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION";
        let linker_flags = "--coverage";

        let _dst = Config::new(".")
            .env("CC", "clang")
            .env("CXX", "clang++")
            .env("CFLAGS", common_flags)
            .env("CXXFLAGS", common_flags)
            .env("CPPFLAGS", common_flags)
            .env("LDFLAGS", linker_flags)
            .define("ENABLE_FUZZ_MAIN", "ON") // This is used to enable the `main()` function in our harness 
            .always_configure(true)
            .very_verbose(true)
            .build();

        Ok(())
    }
}
