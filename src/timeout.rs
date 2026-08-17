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

/// Re-arm the budget, keeping the configured limit.
///
/// `--timeout` bounds how long a single network operation may take, not how
/// long the process may live. `rollover` deliberately sleeps two TLSA TTLs
/// (hours) between phases and shells out to `--reload`; without re-arming, the
/// deadline would be long past by the time the prune phase opens a connection.
pub fn restart() {
    if let Some(state) = STATE.lock().expect("timeout state lock").as_mut() {
        state.start = Instant::now();
    }
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

/// Serializes tests that touch the process-wide `STATE`, which would otherwise
/// race under the parallel test harness.
#[cfg(test)]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub fn clear_for_test() {
    *STATE.lock().expect("timeout state lock") = None;
}

#[cfg(test)]
pub fn init_for_test(limit: Duration) {
    *STATE.lock().expect("timeout state lock") = Some(State {
        start: Instant::now(),
        limit,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rollover` sleeps two TLSA TTLs between phases and shells out to
    /// `--reload`; without re-arming, the prune phase would open its connection
    /// with a deadline that expired hours earlier and always fail.
    ///
    /// Both cases share the process-wide `STATE`, so they run as one test
    /// rather than racing each other under the parallel test harness.
    #[test]
    fn restart_rearms_an_expired_budget() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_for_test(Duration::from_millis(20));
        assert!(remaining().is_ok());

        std::thread::sleep(Duration::from_millis(40));
        assert!(
            remaining().is_err(),
            "budget should expire once the limit passes"
        );

        restart();
        assert!(
            remaining().is_ok(),
            "restart must re-arm the budget after a deliberate wait"
        );
        // The limit itself is preserved, only the clock moves.
        assert_eq!(limit(), Duration::from_millis(20));

        // Uninitialized state falls back to the default budget, and restarting
        // it is harmless.
        *STATE.lock().expect("timeout state lock") = None;
        restart();
        assert_eq!(remaining().unwrap(), Duration::from_secs(DEFAULT_SECS));
    }

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
