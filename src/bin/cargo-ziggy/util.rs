use crate::Common;
use anyhow::Result;
use std::{fs::File, hash::Hasher, io, io::Read, path::Path};

pub use cargo_metadata::camino::Utf8PathBuf;

#[inline]
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

#[derive(Debug, Clone)]
pub struct Context {
    pub target_dir: Utf8PathBuf,
    pub bin_target: String,
}

impl Context {
    pub fn new(common: &Common, target: Option<String>) -> Result<Self> {
        Ok(Self {
            target_dir: common.target_dir().cloned()?,
            bin_target: common.resolve_bin(target)?,
        })
    }

    pub fn view<'a>(&'a self, common: &'a Common) -> ContextView<'a> {
        ContextView { common, cx: self }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ContextView<'a> {
    common: &'a Common,
    cx: &'a Context,
}

impl<'a> ContextView<'a> {
    #[inline]
    pub fn common(&self) -> &'a Common {
        self.common
    }

    #[inline]
    pub fn target_dir(&self) -> &'a Utf8PathBuf {
        &self.cx.target_dir
    }

    #[inline]
    pub fn bin_target(&self) -> &'a str {
        &self.cx.bin_target
    }
}

impl AsRef<Context> for ContextView<'_> {
    #[inline]
    fn as_ref(&self) -> &Context {
        self.cx
    }
}
