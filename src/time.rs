//! Dates in UTC, for listings, `MDTM` and `MLSD` (RFC 3659 section 2.3 and 3, and the `ls -l` format)

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A date and time of day in UTC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Utc {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u32,
    pub(crate) minute: u32,
    pub(crate) second: u32,
}

/// The date of a time. A time before 1970 is 1970
pub(crate) fn utc(time: SystemTime) -> Utc {
    let seconds = time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (seconds / 86400) as i64;
    let in_day = seconds % 86400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    Utc { year, month, day, hour: (in_day / 3600) as u32, minute: (in_day % 3600 / 60) as u32, second: (in_day % 60) as u32 }
}

/// `YYYYMMDDHHMMSS`, the time value of `MDTM` and of the `modify` fact (RFC 3659)
pub(crate) fn mlsx(time: SystemTime) -> String {
    let t = utc(time);
    format!("{:04}{:02}{:02}{:02}{:02}{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second)
}

/// The date column of `ls -l`: `Oct 20 12:34` for a time within the last six months, `Oct 20  2025` for the others
pub(crate) fn ls(time: SystemTime, now: SystemTime) -> String {
    let t = utc(time);
    let recent = now.duration_since(time).map(|age| age < Duration::from_secs(182 * 86400)).unwrap_or(false);
    let month = MONTHS[(t.month - 1) as usize];
    if recent { format!("{month} {:2} {:02}:{:02}", t.day, t.hour, t.minute) } else { format!("{month} {:2}  {:04}", t.day, t.year) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn known_dates() {
        assert_eq!(mlsx(at(0)), "19700101000000");
        assert_eq!(mlsx(at(951_782_400 + 3661)), "20000229010101");
        assert_eq!(mlsx(at(1_000_000_000)), "20010909014640");
        assert_eq!(mlsx(at(1_781_959_845)), "20260620125045");
        assert_eq!(mlsx(at(4_102_444_799)), "20991231235959");
        assert_eq!(mlsx(at(4_107_542_400)), "21000301000000");
    }

    #[test]
    fn a_time_before_1970_is_1970() {
        assert_eq!(mlsx(UNIX_EPOCH - Duration::from_secs(10)), "19700101000000");
    }

    #[test]
    fn the_ls_format_has_the_time_for_a_recent_file_and_the_year_for_an_old_one() {
        let now = at(1_781_959_845);
        assert_eq!(ls(at(1_781_959_845 - 3600), now), "Jun 20 11:50");
        assert_eq!(ls(at(1_781_959_845 - 200 * 86400), now), "Dec  2  2025");
        assert_eq!(ls(at(0), now), "Jan  1  1970");
        // A time in the future has the year
        assert_eq!(ls(at(1_781_959_845 + 86400), now), "Jun 21  2026");
    }
}
