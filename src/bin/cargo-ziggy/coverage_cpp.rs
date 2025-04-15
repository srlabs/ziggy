use crate::{find_target, Cover, CoverCpp};
use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::{env, fs, path::PathBuf, process};


impl CoverCpp {
    pub fn generate_coverage(&mut self) -> Result<(), anyhow::Error> {
        todo!()
    }
}
