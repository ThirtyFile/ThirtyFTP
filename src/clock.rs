//! Deadlines from the settings of the host

use std::time::Duration;
use tokio::time::Instant;

/// Thirty years: further away than any session lasts
const FAR: Duration = Duration::from_secs(30 * 365 * 24 * 3600);

/// The moment `duration` after `start`. A duration too large for the clock (`Duration::MAX` for "never") is a deadline that does not come, not a panic
pub(crate) fn from(start: Instant, duration: Duration) -> Instant {
    start.checked_add(duration).or_else(|| start.checked_add(FAR)).unwrap_or(start)
}

/// The moment `duration` from now
pub(crate) fn after(duration: Duration) -> Instant {
    from(Instant::now(), duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_huge_duration_is_far_away_and_does_not_panic() {
        let now = Instant::now();
        assert!(after(Duration::MAX) > now + Duration::from_secs(365 * 24 * 3600));
        assert!(after(Duration::from_secs(5)) < now + Duration::from_secs(60));
        assert!(after(Duration::ZERO) >= now);
    }
}
