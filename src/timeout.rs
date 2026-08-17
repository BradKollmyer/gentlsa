use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

/// Default connect / I/O / DNS budget, matching the old hardcoded socket timeout.
pub const DEFAULT_SECS: u64 = 30;

struct State {
    start: Instant,
    limit: Duration,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

pub fn init(secs: u64) {
    *STATE.lock().expect("timeout state lock") = Some(State {
        start: Instant::now(),
        limit: Duration::from_secs(secs),
    });
}

pub fn limit() -> Duration {
    STATE
        .lock()
        .expect("timeout state lock")
        .as_ref()
        .map(|state| state.limit)
        .unwrap_or(Duration::from_secs(DEFAULT_SECS))
}

/// Time left in the process-wide budget. Errors when the deadline has passed.
pub fn remaining() -> Result<Duration> {
    let guard = STATE.lock().expect("timeout state lock");
    let Some(state) = guard.as_ref() else {
        return Ok(Duration::from_secs(DEFAULT_SECS));
    };
    match leftover(state.limit, state.start.elapsed()) {
        Some(left) => Ok(left),
        None => bail!("timed out after {}s", state.limit.as_secs()),
    }
}

fn leftover(limit: Duration, elapsed: Duration) -> Option<Duration> {
    limit.checked_sub(elapsed).filter(|left| !left.is_zero())
}

pub fn expired_error() -> anyhow::Error {
    anyhow::anyhow!("timed out after {}s", limit().as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leftover_budget() {
        assert_eq!(
            leftover(Duration::from_secs(30), Duration::from_secs(10)),
            Some(Duration::from_secs(20))
        );
        assert_eq!(
            leftover(Duration::from_secs(1), Duration::from_secs(1)),
            None
        );
        assert_eq!(
            leftover(Duration::from_secs(1), Duration::from_millis(1_500)),
            None
        );
        assert!(leftover(Duration::from_secs(DEFAULT_SECS), Duration::ZERO).is_some());
    }
}
