use crate::walkdir::WalkDir;
use anyhow::anyhow;
use cmake::Config;
use std::collections::HashSet;
use std::fs;
use std::{env, path::Path, path::PathBuf};
use walkdir;
use which::which;

extern crate num_cpus;
/// # Documentation
/// ## Objectives
/// The goal of this build.rs is to manage the compilation of the C++ target
///
/// ## Environment variables used:
/// Below are the different env. var. used to customize the fuzzing compilation
///     `ENABLE_ASAN` : Should we compile with ASAN
///     `ENABLE_UBSAN` : TODO: Should we compile with UBSAN
///     `TARGET_LIB_NAME` : The name of the library containing the `LLVMFuzzerTestOneInput` in the `CMakeList.txt`
///     `AFL_COMPILER_MODE` : Using AFL++ LTO or FAST compiler
///     `CMAKELISTS_PATH` : Path to the high level CMakeLists.txt like `/home/kevin/toz/CMakeLists.txt`, default is `./CMakeLists.txt`
///     `PROFILE` : Compile in Debug or Release mode
///     `ADDITIONAL_LIBS` : Additional targets to link (i.e `sodium`, `crypto`, `pthread`, `dl`, `microhttpd`..;)

fn main() {
    let curr_dir = env::current_dir().unwrap();
    println!("Working from {}", curr_dir.display());

    let cmakelist_path = PathBuf::from(env::var("CMAKELISTS_PATH").unwrap());
    let cmakelist_fullpath = cmakelist_path.join("CMakeLists.txt");

    let target_lib_name = env::var("TARGET_LIB_NAME").unwrap_or("FuzzTarget".to_string());

    assert!(
        !cmakelist_path
            .display()
            .to_string()
            .contains("CMakeLists.txt"),
        "`--cmakelist-path` seems to contain the CMakeLists file, please just provide the path to it"
    );

    assert!(
        cmakelist_fullpath.exists(),
        "CMakeLists.txt should exist, please check your `--cmakelist-path`"
    );

    let (c_compiler, cxx_compiler, is_lto) = match env::var("AFL_COMPILER_MODE").as_deref() {
        Ok("lto") => {
            println!("cargo:info=Using AFL++ LTO mode");
            ("afl-clang-lto", "afl-clang-lto++", true)
        }
        Ok("runner") => {
            println!("cargo:info=Using Clang runner mode");
            ("clang", "clang++", false)
        }
        _ => {
            println!("cargo:info=Using AFL++ FAST mode");
            ("afl-clang-fast", "afl-clang-fast++", false)
        }
    };

    check_compilers(c_compiler, cxx_compiler);
    unsafe {
        env::set_var("CC", c_compiler);
        env::set_var("CXX", cxx_compiler);
    }
    if is_lto {
        let ar_tool = "llvm-ar";
        let ranlib_tool = "llvm-ranlib";
        let as_tool = "llvm-as";

        program_exist(ar_tool);
        program_exist(ranlib_tool);
        program_exist(as_tool);
        unsafe {
            env::set_var("AR", ar_tool);
            env::set_var("RANLIB", ranlib_tool);
            env::set_var("AS", as_tool);
        }
    } else {
        unsafe {
            env::remove_var("AR");
            env::remove_var("RANLIB");
            env::remove_var("AS");
        }
    }

    let enable_asan = env::var("ENABLE_ASAN").is_ok();
    let mut config = cmake::Config::new(fs::canonicalize("..").unwrap()); // Path to the CMakeLists but without the CMakeLists.txt

    // Configure CMake
    configure_cmake_build(&mut config, c_compiler, cxx_compiler, is_lto);

    config.build_target(&target_lib_name); // `--target=FuzzTarget` to avoid compiling useless stuff

    if enable_asan {
        cmake_with_asan(&mut config);
    }

    let target_dir = config.build();

    // Disable cache if the `CMakeLists.txt` or `target_dir` changed
    println!("cargo:rerun-if-changed={}", cmakelist_fullpath.display());
    println!("cargo:rerun-if-changed={}", target_dir.display());

    let additional_libs_str = env::var("ADDITIONAL_LIBS").unwrap_or_default();
    let additional_libs: Option<Vec<String>> = if additional_libs_str.is_empty() {
        None
    } else {
        Some(
            additional_libs_str
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        )
    };

    print_linkers(&target_lib_name, enable_asan, &target_dir, additional_libs);
}

// Configure CMake build settings
fn configure_cmake_build(config: &mut Config, c_compiler: &str, cxx_compiler: &str, is_lto: bool) {
    let cmake_build_profile = if env::var("PROFILE").expect("'PROFILE' not set") == "release" {
        "Release"
    } else {
        "Debug"
    };

    let cpus = num_cpus::get().to_string();

    config
        .profile(cmake_build_profile)
        .define("CMAKE_C_COMPILER", c_compiler)
        .define("CMAKE_CXX_COMPILER", cxx_compiler);

    if is_lto {
        config.define("CMAKE_AR", env::var("AR").unwrap());
        config.define("CMAKE_RANLIB", env::var("RANLIB").unwrap());
        config.define("CMAKE_AS", env::var("AS").unwrap());
    }

    config
        .build_arg(format!("-j{}", &cpus)) // Maximum jobs Brrrrrrr...
        .no_build_target(false)
        .very_verbose(true);
}

/// We link to our Rust targets all the libraries that we can find, plus the ones from the user
fn print_linkers(
    target_lib_name: &str,
    enable_asan: bool,
    target_dir: &Path,
    additional_libs: Option<Vec<String>>,
) {
    let mut search_paths: HashSet<PathBuf> = HashSet::new();
    let mut libraries_to_link: HashSet<String> = HashSet::new();

    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            search_paths.insert(path.to_path_buf());
        } else if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "a" {
                    if let Some(file_stem) = path.file_stem() {
                        if let Some(name_str) = file_stem.to_str() {
                            // Remove "lib" prefix if it exists
                            let lib_name = if name_str.starts_with("lib") {
                                &name_str[3..]
                            } else {
                                name_str
                            };

                            if !lib_name.is_empty() {
                                libraries_to_link.insert(lib_name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    for path in &search_paths {
        if path.exists() && path.is_dir() {
            println!("cargo:rustc-link-search=native={}", path.display());
        } else {
            println!(
                "cargo:warning=Skipping non-existent directory for link search: {}",
                path.display()
            );
        }
    }

    // Link the main target lib first
    println!("cargo:rustc-link-lib=static={}", target_lib_name);

    // Remove it so we don't link it twice
    libraries_to_link.remove(target_lib_name);

    for lib_name in &libraries_to_link {
        // Avoid linking the main target again
        if lib_name != target_lib_name {
            println!("cargo:rustc-link-lib=static={}", lib_name);
        }
    }

    if enable_asan {
        println!("cargo:rustc-link-lib=asan");
    }

    println!("cargo:rustc-link-lib=stdc++");

    // Link other system libraries if needed
    if let Some(libs) = additional_libs {
        for lib_name in libs {
            println!("cargo:rustc-link-lib={}", lib_name);
        }
    }
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
    eprintln!("    Adding correct flags for ASAN");

    let asan_flags: &str = "-fsanitize=address";
    unsafe {
        env::set_var("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0"); // abort_on_error=1 is often better for fuzzing builds
    }

    config.cflag(asan_flags);
    config.cxxflag(asan_flags);
    // Also add to linker flags
    config.define("CMAKE_EXE_LINKER_FLAGS_INIT", asan_flags);
    config.define("CMAKE_SHARED_LINKER_FLAGS_INIT", asan_flags);
    config.define("CMAKE_MODULE_LINKER_FLAGS_INIT", asan_flags);

}

/// Check if compilers exist in the system
fn check_compilers(c_compiler: &str, cxx_compiler: &str) {
    if which(c_compiler).is_err() {
        panic!("Compiler '{}' not found in PATH", c_compiler);
    }
    if which(cxx_compiler).is_err() {
        panic!("Compiler '{}' not found in PATH", cxx_compiler);
    }
    println!(
        "cargo:info=Using C Compiler: {}",
        which(c_compiler).unwrap().display()
    );
    println!(
        "cargo:info=Using CXX Compiler: {}",
        which(cxx_compiler).unwrap().display()
    );
}

fn program_exist(tool: &str) {
    match which(tool) {
        Ok(path) => {
            println!("cargo:info=Found tool '{}' at: {}", tool, path.display());
        }
        Err(_) => {
            panic!("Tool '{}' was not found in PATH, ensure that the necessary LLVM/toolchain components are installed and in your PATH.", tool);
        }
    }
}
