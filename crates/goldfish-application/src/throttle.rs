//! Unlock throttle — exponential backoff against online master-password guessing.
//!
//! After each failed master-password unlock, the next attempt is delayed by an
//! exponentially growing window (1 s, 2 s, 4 s, … capped at 60 s); a successful
//! unlock resets it. Its job is to make interactive/online guessing impractical;
//! offline attacks against a stolen vault file are bounded separately by the
//! Argon2id cost.
//!
//! The service persists the backoff state ([`UnlockThrottle::snapshot`] /
//! [`UnlockThrottle::restore`]) into the vault metadata, so relaunching the app
//! cannot reset the window — a scripted "restart between guesses" attack stays
//! throttled.

use chrono::{DateTime, Duration, Utc};

/// Upper bound on the backoff window, in seconds.
const MAX_BACKOFF_SECS: u64 = 60;

/// Tracks consecutive failed unlocks and the time until the next attempt is
/// allowed.
#[derive(Debug, Default)]
pub struct UnlockThrottle {
    consecutive_failures: u32,
    locked_until: Option<DateTime<Utc>>,
}

impl UnlockThrottle {
    /// Creates an unthrottled instance (no failures recorded).
    pub const fn new() -> Self {
        Self {
            consecutive_failures: 0,
            locked_until: None,
        }
    }

    /// Seconds the caller must still wait before another attempt, or `0` if an
    /// attempt is allowed right now. Rounds up so a partial second still blocks.
    pub fn retry_after(&self, now: DateTime<Utc>) -> u64 {
        match self.locked_until {
            Some(until) if until > now => {
                let ms = (until - now).num_milliseconds().max(0);
                // Round up to whole seconds (1 ms remaining still means "wait 1 s").
                u64::try_from((ms + 999) / 1000).unwrap_or(MAX_BACKOFF_SECS)
            }
            _ => 0,
        }
    }

    /// Records a failed attempt and arms the next backoff window from `now`.
    pub fn record_failure(&mut self, now: DateTime<Utc>) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let backoff = Self::backoff_secs(self.consecutive_failures);
        self.locked_until = Some(now + Duration::seconds(i64::try_from(backoff).unwrap_or(60)));
    }

    /// Clears all backoff state after a successful unlock.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
    }

    /// Rebuilds a throttle from persisted state (see [`Self::snapshot`]). Lets the
    /// backoff survive an app restart instead of resetting to zero.
    pub const fn restore(consecutive_failures: u32, locked_until: Option<DateTime<Utc>>) -> Self {
        Self {
            consecutive_failures,
            locked_until,
        }
    }

    /// Returns `(consecutive_failures, locked_until)` for persistence.
    pub const fn snapshot(&self) -> (u32, Option<DateTime<Utc>>) {
        (self.consecutive_failures, self.locked_until)
    }

    /// Backoff window for the n-th consecutive failure: `2^(n-1)` capped at
    /// [`MAX_BACKOFF_SECS`] (1, 2, 4, 8, 16, 32, 60, 60, …).
    fn backoff_secs(failures: u32) -> u64 {
        let shift = failures.saturating_sub(1).min(20);
        (1u64 << shift).min(MAX_BACKOFF_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn initially_allows_immediately() {
        let throttle = UnlockThrottle::new();
        assert_eq!(throttle.retry_after(at(0)), 0);
    }

    #[test]
    fn first_failure_blocks_one_second() {
        let mut throttle = UnlockThrottle::new();
        throttle.record_failure(at(0));
        assert_eq!(throttle.retry_after(at(0)), 1);
        // …and clears once the window elapses.
        assert_eq!(throttle.retry_after(at(1)), 0);
    }

    #[test]
    fn backoff_doubles_with_each_failure() {
        let mut throttle = UnlockThrottle::new();
        throttle.record_failure(at(0)); // 1 -> 1 s
        throttle.record_failure(at(0)); // 2 -> 2 s
        assert_eq!(throttle.retry_after(at(0)), 2);
        throttle.record_failure(at(0)); // 3 -> 4 s
        assert_eq!(throttle.retry_after(at(0)), 4);
        throttle.record_failure(at(0)); // 4 -> 8 s
        assert_eq!(throttle.retry_after(at(0)), 8);
    }

    #[test]
    fn backoff_is_capped_at_60s() {
        let mut throttle = UnlockThrottle::new();
        for _ in 0..20 {
            throttle.record_failure(at(0));
        }
        assert_eq!(throttle.retry_after(at(0)), MAX_BACKOFF_SECS);
    }

    #[test]
    fn success_resets_backoff() {
        let mut throttle = UnlockThrottle::new();
        throttle.record_failure(at(0));
        throttle.record_failure(at(0));
        throttle.record_success();
        assert_eq!(throttle.retry_after(at(0)), 0);
        // The next failure starts again from the 1 s window.
        throttle.record_failure(at(0));
        assert_eq!(throttle.retry_after(at(0)), 1);
    }

    #[test]
    fn retry_after_rounds_up_partial_seconds() {
        let mut throttle = UnlockThrottle::new();
        throttle.record_failure(at(0)); // locked until +1 s
                                        // 1 ms before the window closes, the caller must still wait a full second.
        let now = at(0) + Duration::milliseconds(1);
        assert_eq!(throttle.retry_after(now), 1);
    }
}
