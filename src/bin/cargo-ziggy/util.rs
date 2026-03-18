use anyhow::Result;
use std::{fs::File, hash::Hasher, io, io::Read, path::Path};

pub fn hash_file(path: &Path) -> Result<u64> {
    let mut hasher = twox_hash::XxHash64::with_seed(0);
    let mut file = File::open(path)?;

    let mut buf = [0; 8 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hasher.finish()),
            Ok(n) => hasher.write(&buf[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted) => (),
            Err(e) => return Err(e.into()),
        }
    }
}
