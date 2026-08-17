use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde::Serialize;

static JSON: AtomicBool = AtomicBool::new(false);

pub fn init(on: bool) {
    JSON.store(on, Ordering::Relaxed);
}

pub fn is_json() -> bool {
    JSON.load(Ordering::Relaxed)
}

/// Print a line to stdout unless `--json` is collecting a report instead.
pub fn text(msg: impl std::fmt::Display) {
    if !is_json() {
        println!("{msg}");
    }
}

pub fn emit(value: &impl Serialize) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).context("failed to write JSON")?;
    stdout.write_all(b"\n").context("failed to write JSON")?;
    Ok(())
}
