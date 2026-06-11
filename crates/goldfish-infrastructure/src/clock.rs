//! Wall-clock adapter for the `Clock` port.

use chrono::{DateTime, Utc};
use goldfish_application::Clock;

/// A `Clock` backed by the system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
