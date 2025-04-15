use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

const FILES_TO_EXTRACT: &[(&str, &[u8])] = &[
    ("Cargo.toml", include_bytes!("template/Cargo.toml")),
    ("build.rs", include_bytes!("template/build.rs")),
    (
        ".cargo/config.toml",
        include_bytes!("template/.cargo/config.toml"),
    ),
    ("src/main.rs", include_bytes!("template/src/main.rs")),
];

pub const TARGET_SUBDIR: &str = "fuzzer";

pub struct Extractor {}

impl Extractor {
    pub fn new() -> &'static Self {
        &Extractor {}
    }
    pub fn extract(&self) -> PathBuf {
        let target_dir_path = env::current_dir().unwrap().join(TARGET_SUBDIR);
        fs::create_dir_all(&target_dir_path).unwrap();

        for (relative_path_str, file_content) in FILES_TO_EXTRACT {
            let full_target_path = target_dir_path.join(relative_path_str);

            println!("  Extracting to: {}", full_target_path.display());

            if let Some(parent_dir) = full_target_path.parent() {
                fs::create_dir_all(parent_dir).unwrap();
            }

            fs::write(&full_target_path, *file_content).unwrap();
        }

        println!("Extracted the harness to {}", target_dir_path.display());
        target_dir_path
    }
}
