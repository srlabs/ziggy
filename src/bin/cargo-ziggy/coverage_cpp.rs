use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::process::{Command, ExitStatus};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const REPORT_DIR_NAME: &str = "report";
const BASE_TRACE_FILENAME: &str = "trace.lcov_base";
const INFO_TRACE_FILENAME: &str = "trace.lcov_info";
const TMP_TRACE_FILENAME: &str = "trace.lcov_tmp";
const FINAL_TRACE_FILENAME: &str = "trace.lcov_info_final";

pub struct CoverCpp {
    project_root: PathBuf,
    queue_dir: PathBuf,
    target_executable: PathBuf,
    output_dir: PathBuf,
    build_dir: PathBuf,
    keep_intermediate: bool, // Optional: Flag to keep intermediate files
}

impl CoverCpp {
    pub fn new(project_root: PathBuf, queue_dir: PathBuf, keep_intermediate: bool) -> Result<Self> {
        let output_dir = project_root.join(REPORT_DIR_NAME);
        // Build dir will be determined after build_runner
        Ok(CoverCpp {
            project_root,
            queue_dir,
            target_executable: PathBuf::new(), // Will be set after build
            output_dir,
            build_dir: PathBuf::new(), // Will be set after build
            keep_intermediate,
        })
    }

    fn run_command(cmd: &mut Command, context_msg: &str) -> Result<ExitStatus> {
        eprintln!("Executing: {:?}", cmd);
        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {:?}", cmd))?;

        if !status.success() {
            return Err(anyhow!("{} failed with status: {}", context_msg, status));
        }
        Ok(status)
    }

    fn lcov_base_args(&self) -> Vec<String> {
        vec![
            "--gcov-tool".to_string(),
            "llvm-cov".to_string(), // Assume llvm-cov is gcov tool
            "gcov".to_string(),     // llvm-cov needs subcommand
            "--no-checksum".to_string(),
            "--ignore-errors".to_string(),
            "inconsistent,unsupported".to_string(),
        ]
    }

    pub fn generate_coverage_report(&mut self) -> Result<()> {
        self.build_dir = Self::build_runner(&self.project_root)?;

        // Find the actual target executable path within the build directory
        // CMake usually puts it in the root of the build dir or a sub-dir like bin/
        // For simplicity, assume it's in the root for now. Adjust if needed.
        self.target_executable = self.build_dir.join(
            self.target_executable
                .file_name()
                .ok_or_else(|| anyhow!("Invalid target executable name"))?,
        );

        if !self.queue_dir.is_dir() {
            return Err(anyhow!("Queue directory not found: {:?}", self.queue_dir));
        }
        if !self.target_executable.is_file() {
            return Err(anyhow!(
                "Target executable not found or not a file: {:?}",
                self.target_executable
            ));
            // Add check for executable permission if needed (platform specific)
        }

        if self.output_dir.exists() && !self.keep_intermediate {
            fs::remove_dir_all(&self.output_dir).with_context(|| {
                format!(
                    "Failed to remove old report directory: {:?}",
                    self.output_dir
                )
            })?;
        }
        fs::create_dir_all(&self.output_dir)
            .with_context(|| format!("Failed to create report directory: {:?}", self.output_dir))?;

        let lcov_common_args = self.lcov_base_args();
        let build_dir_str = self
            .build_dir
            .to_str()
            .ok_or_else(|| anyhow!("Build directory path is not valid UTF-8"))?;
        let output_dir_str = self
            .output_dir
            .to_str()
            .ok_or_else(|| anyhow!("Output directory path is not valid UTF-8"))?;

        // 1. Zero counters
        Self::run_command(
            Command::new("lcov")
                .current_dir(&self.project_root)
                .args(&lcov_common_args)
                .arg("--zerocounters")
                .arg("--directory")
                .arg(build_dir_str), // Point to where .gcda files are (build dir)
            "lcov --zerocounters",
        )?;

        // 2. Capture baseline
        let base_trace_path = self.output_dir.join(BASE_TRACE_FILENAME);
        Self::run_command(
            Command::new("lcov")
                .current_dir(&self.project_root)
                .args(&lcov_common_args)
                .arg("--capture")
                .arg("--initial")
                .arg("--directory")
                .arg(build_dir_str)
                .arg("--output-file")
                .arg(&base_trace_path),
            "lcov --capture --initial",
        )?;

        // 3. Run the target executable with inputs from queue_dir
        let mut target_cmd = Command::new(&self.target_executable);
        target_cmd.current_dir(&self.project_root); // Or build_dir? Depends on the target's needs. Project root is safer.

        let pattern = self.queue_dir.join("*");
        let pattern_str = pattern
            .to_str()
            .ok_or_else(|| anyhow!("Queue directory pattern is not valid UTF-8"))?;

        let mut file_args = Vec::new();
        for entry in glob(pattern_str).context("Failed to read glob pattern")? {
            match entry {
                Ok(path) => {
                    if path.is_file() {
                        // Only pass files as arguments
                        file_args.push(path);
                    }
                }
                Err(e) => eprintln!("Warning: Skipping path due to error: {}", e),
            }
        }

        if file_args.is_empty() {
            eprintln!(
                "Warning: No input files found in queue directory: {:?}",
                self.queue_dir
            );
            // Decide if this should be an error or just proceed
        } else {
            target_cmd.args(&file_args);
        }

        // Run even if no files, maybe it generates coverage without input files
        Self::run_command(&mut target_cmd, "target executable execution")?;

        // 4. Capture coverage after execution
        let info_trace_path = self.output_dir.join(INFO_TRACE_FILENAME);
        Self::run_command(
            Command::new("lcov")
                .current_dir(&self.project_root)
                .args(&lcov_common_args)
                .arg("--capture")
                .arg("--directory")
                .arg(build_dir_str)
                .arg("--output-file")
                .arg(&info_trace_path),
            "lcov --capture",
        )?;

        // 5. Combine baseline and execution traces
        let tmp_trace_path = self.output_dir.join(TMP_TRACE_FILENAME);
        Self::run_command(
            Command::new("lcov")
                .current_dir(&self.project_root)
                .args(&lcov_common_args)
                .arg("-a")
                .arg(&base_trace_path)
                .arg("-a")
                .arg(&info_trace_path)
                .arg("--output-file")
                .arg(&tmp_trace_path),
            "lcov combine traces",
        )?;

        // 6. Remove system includes
        let final_trace_path = self.output_dir.join(FINAL_TRACE_FILENAME);
        Self::run_command(
            Command::new("lcov")
                .current_dir(&self.project_root)
                .args(&lcov_common_args)
                .arg("-r")
                .arg(&tmp_trace_path)
                .arg("/usr/include/*") // This pattern should be handled by lcov
                .arg("--output-file")
                .arg(&final_trace_path),
            "lcov remove system includes",
        )?;

        // 7. Generate HTML report
        Self::run_command(
            Command::new("genhtml")
                .current_dir(&self.project_root)
                .arg("--ignore-errors")
                .arg("source,format")
                .arg("--output-directory")
                .arg(output_dir_str) // Use the absolute/relative path string
                .arg(&final_trace_path),
            "genhtml report generation",
        )?;

        // 8. Clean up intermediate files if not keeping them
        if !self.keep_intermediate {
            let _ = fs::remove_file(&base_trace_path);
            let _ = fs::remove_file(&info_trace_path);
            let _ = fs::remove_file(&tmp_trace_path);
            // Keep final_trace_path as it might be useful
        }

        let report_index = self.output_dir.join("index.html");
        println!("\nReport: {}", report_index.display());

        Ok(())
    }

    pub fn build_runner(project_root: &Path) -> Result<PathBuf> {
        eprintln!(
            "Building coverage-instrumented target in {:?}...",
            project_root
        );

        // Ensure clang and clang++ are available
        let clang_path = which::which("clang").context("clang not found in PATH")?;
        let clangpp_path = which::which("clang++").context("clang++ not found in PATH")?;

        let common_flags = "-fprofile-instr-generate -fcoverage-mapping -O0 -g";
        let linker_flags = "-fprofile-instr-generate -fcoverage-mapping";

        let buf = project_root.join("CMakeLists.txt");
        if !buf.exists() {
            panic!("{:?} should exist", buf);
        }
        println!("CMakeList is at: {:?}", buf);

        let mut config = cmake::Config::new(buf);

        config
            .env("CC", clang_path)
            .env("CXX", clangpp_path)
            .env("CFLAGS", common_flags)
            .env("CXXFLAGS", common_flags)
            .env("LDFLAGS", linker_flags)
            .define("CMAKE_BUILD_TYPE", "Debug") // Ensure debug symbols and no optimization interfering with coverage
            .define("ENABLE_FUZZ_MAIN", "ON") // Assuming this is still needed
            .always_configure(true)
            .very_verbose(true); // Keep verbose for debugging build issues

        // Check for specific CMake cache variables to set compiler flags more robustly
        config.define("CMAKE_C_FLAGS_INIT", common_flags);
        config.define("CMAKE_CXX_FLAGS_INIT", common_flags);
        config.define("CMAKE_EXE_LINKER_FLAGS_INIT", linker_flags);
        config.define("CMAKE_SHARED_LINKER_FLAGS_INIT", linker_flags);

        let dst = config.build(); // Builds in target/debug/build/<crate-hash>/out

        // The actual build directory is often one level up from 'out'
        let build_dir = dst
            .parent()
            .ok_or_else(|| anyhow!("Failed to get parent directory of cmake output"))?
            .to_path_buf();

        eprintln!("Build completed. Artifacts in: {:?}", build_dir);
        Ok(build_dir)
    }
}
