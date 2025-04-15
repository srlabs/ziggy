use std::{env, path::Path};

const CPP_PROJECT_DIR: &str = ".."; // '../../../../examples/libfuzzer_c++'
const C_COMPILER: &str = "afl-clang-fast";
const CXX_COMPILER: &str = "afl-clang-fast++";
const TARGET_LIB_NAME: &str = "FuzzTarget";
const ASAN_FLAG: &str = "-fsanitize=address";

fn main() {
    let cpp_project_path = Path::new(CPP_PROJECT_DIR);
    let enable_asan = env::var("ENABLE_ASAN").is_ok();
    let mut config = cmake::Config::new(cpp_project_path);

    let profile =
        env::var("PROFILE").expect("Build profile environment variable 'PROFILE' not set");

    let cmake_build_profile = if profile == "release" {
        "Release"
    } else {
        "Debug"
    };

    println!(
        "cargo:rerun-if-changed={}",
        cpp_project_path.join("CMakeLists.txt").display()
    );

    unsafe {
        env::set_var("CC", C_COMPILER);
        env::set_var("CXX", CXX_COMPILER);
    }

    config
        .profile(cmake_build_profile)
        .define("CMAKE_C_COMPILER", C_COMPILER)
        .define("CMAKE_CXX_COMPILER", CXX_COMPILER)
        .no_build_target(true)
        .very_verbose(true);

    if enable_asan {
        config
            .cflag(ASAN_FLAG)
            .cxxflag(ASAN_FLAG)
            .define("CMAKE_EXE_LINKER_FLAGS", "ASAN_FLAG")
            .define("CMAKE_SHARED_LINKER_FLAGS", ASAN_FLAG)
            .define("CMAKE_MODULE_LINKER_FLAGS", ASAN_FLAG);
    }

    let dst = config.build();
    let lib_dir = dst.join("lib");
    let build_dir = dst.join("build");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static={}", TARGET_LIB_NAME);
    println!("cargo:rustc-link-lib=static=stdc++");

    if enable_asan {
        println!("cargo:rustc-link-lib=asan");
    }

    let final_lib_path = lib_dir.join(format!("lib{}.a", TARGET_LIB_NAME));
    println!(
        "cargo:info=Your library to fuzz has been compiled into: {}",
        final_lib_path.display()
    );
}
