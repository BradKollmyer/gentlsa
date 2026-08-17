use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Print a processing step to stderr when `-v` / `--verbose` is set.
pub fn step(msg: impl std::fmt::Display) {
    if enabled() {
        eprintln!("verbose: {msg}");
    }
}
