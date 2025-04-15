use anyhow::anyhow;
use cmake::Config;
use regex::Regex;
use std::fs;
use std::{env, path::Path, path::PathBuf};
use which::which;

/// # Documentation
/// ## Goal
/// The goal of this build.rs is to manage the compilation of the C++ target
///
/// ## Environment variables used:
/// Below are the different env. var. used to customize the fuzzing compilation
///     `ENABLE_ASAN` : Should we compile with ASAN
///     `ENABLE_UBSAN` : TODO: Should we compile with UBSAN
///     `TARGET_LIB_NAME` : The name of the `project()` in the `CMakeList.txt`
///     `AFL_COMPILER_MODE` : Using AFL++ LTO or FAST compiler
///     `PROFILE` : Compile in Debug or Release mode

fn main() {
    let cpp_project_path = Path::new(".."); // We are always in `PROJECT/fuzzer`, so we just `..`
    let cmakelist = cpp_project_path.join("CMakeLists.txt");

    // To fetch the target name, we do it in three ways. Either we get it from TARGET_LIB_NAME env, either we extract it automatically, or we use the one from the example
    let target_lib_name = env::var("TARGET_LIB_NAME").unwrap_or(
        extract_project_name_from_string(&cmakelist).unwrap_or("FuzzTarget".to_string()),
    );

    let enable_asan = env::var("ENABLE_ASAN").is_ok();
    let mut config = cmake::Config::new(cpp_project_path);

    // Disable cache if the `CMakeLists.txt` changed
    println!("cargo:rerun-if-changed={}", cmakelist.display());

    cmake_with_afl_compilers(&mut config);

    if enable_asan {
        cmake_with_asan(&mut config);
    }

    let lib_dir = print_linkers(&target_lib_name, enable_asan, &mut config);

    // Print the compiled target for the user
    let final_lib_path = lib_dir.join(format!("lib{}.a", target_lib_name));
    println!(
        "cargo:info=Your library to fuzz has been compiled into: {}",
        final_lib_path.display()
    );
}

// `println!` for the linking part
fn print_linkers(target_lib_name: &String, enable_asan: bool, config: &mut Config) -> PathBuf {
    let dst = config.build();
    let lib_dir = dst.join("lib");
    let build_dir = dst.join("build");

    if enable_asan {
        println!("cargo:rustc-link-lib=asan");
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static={}", target_lib_name);
    println!("cargo:rustc-link-lib=static=stdc++");

    lib_dir
}

// Update CMake's `config` with AFL compilers
fn cmake_with_afl_compilers(config: &mut Config) {
    let cmake_build_profile = if env::var("PROFILE").expect("'PROFILE' not set") == "release" {
        "Release"
    } else {
        "Debug"
    };

    // If user specify "lto", then we compile with AFL++ LTO fuzzers, otherwise classic fast fuzzers
    let (c_compiler, cxx_compiler) = match env::var("AFL_COMPILER_MODE").as_deref() {
        Ok("lto") => ("afl-clang-lto", "afl-clang-lto++"),
        Ok("runner") => ("clang", "clang++"),
        _ => ("afl-clang-fast", "afl-clang-fast++"),
    };

    check_compilers(c_compiler, cxx_compiler);
    unsafe {
        env::set_var("CC", c_compiler);
        env::set_var("CXX", cxx_compiler);
    }

    config
        .profile(cmake_build_profile)
        .define("CMAKE_C_COMPILER", c_compiler)
        .define("CMAKE_CXX_COMPILER", cxx_compiler)
        .no_build_target(true)
        .very_verbose(true);
}

/// Append `val` to `name` environment variable
fn append_env_var(name: &str, val: &str) {
    let mut new_val = env::var(name).unwrap_or_default();
    if !new_val.is_empty() {
        new_val.push(' ');
    }
    new_val.push_str(val);
    unsafe {
        env::set_var(name, new_val);
    }
}
// Update CMake's `config` with ASAN flags
fn cmake_with_asan(config: &mut cmake::Config) {
    let asan_flags: &str = "-fsanitize=address";

    config.cflag(asan_flags);
    config.cxxflag(asan_flags);

    append_env_var("CMAKE_EXE_LINKER_FLAGS", asan_flags);
    append_env_var("CMAKE_SHARED_LINKER_FLAGS", asan_flags);
    append_env_var("CMAKE_MODULE_LINKER_FLAGS", asan_flags);
}

/// Check if compilers exist in the system
fn check_compilers(c_compiler: &str, cxx_compiler: &str) {
    if which(c_compiler).is_err() {
        panic!("Compiler '{}' not found", c_compiler);
    }
    if which(cxx_compiler).is_err() {
        panic!("Compiler '{}' not found", cxx_compiler);
    }
}

fn extract_project_name_from_string(filepath: &PathBuf) -> anyhow::Result<String> {
    // Regex to parse project name from CMakeList.txt
    // - project(Name)
    // - project(Name LANGUAGES)
    // - project(Name LANGUAGES VERSION)
    // - project ( Name ) with spaces

    let content = fs::read_to_string(filepath)?;
    let re = Regex::new(r"(?i)project\s*\(\s*([A-Za-z0-9_]+)(?:\s+[A-Za-z0-9_]+)*\s*\)")?;

    if let Some(captures) = re.captures(&content) {
        if let Some(project_match) = captures.get(1) {
            return Ok(project_match.as_str().to_string());
        }
    }

    Err(anyhow!("Could not find project name in CMakeLists.txt"))
}
