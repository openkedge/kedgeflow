//! Trusted clock boundary. Request data never selects verifier time.
use time::{OffsetDateTime, UtcDateTime, format_description::well_known::Rfc3339};

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        unix_millis_now()
    }
}

pub fn unix_millis_now() -> i64 {
    UtcDateTime::now()
        .unix_timestamp_nanos()
        .div_euclid(1_000_000) as i64
}

pub fn unix_seconds_now() -> i64 {
    UtcDateTime::now().unix_timestamp()
}

fn legacy_range(value: UtcDateTime) -> Option<UtcDateTime> {
    // Preserve the previous Gregorian date range, including extended years.
    (-262143..=262142).contains(&value.year()).then_some(value)
}

fn format_utc(value: UtcDateTime, millis: bool) -> String {
    let year = value.year();
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    };
    let fraction = if millis {
        format!("{:03}", value.nanosecond() / 1_000_000)
    } else {
        format!("{:09}", value.nanosecond())
    };
    format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}.{fraction}Z",
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

pub fn rfc3339_millis(at: i64) -> Option<String> {
    let value = UtcDateTime::from_unix_timestamp_nanos(i128::from(at) * 1_000_000).ok()?;
    Some(format_utc(legacy_range(value)?, true))
}

pub fn rfc3339_now_nanos() -> String {
    format_utc(UtcDateTime::now(), false)
}

/// UTC ordering retains RFC3339 leap-second placement used by existing cursors.
/// It does not allow request data to select any authority clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireTimestamp {
    seconds: i64,
    nanos: u32,
}

impl WireTimestamp {
    pub fn from_millis(at: i64) -> Option<Self> {
        legacy_range(UtcDateTime::from_unix_timestamp_nanos(i128::from(at) * 1_000_000).ok()?)?;
        Some(Self {
            seconds: at.div_euclid(1000),
            nanos: (at.rem_euclid(1000) as u32) * 1_000_000,
        })
    }

    pub fn timestamp_millis(self) -> i64 {
        self.seconds * 1000 + i64::from(self.nanos / 1_000_000)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidTimestamp;

impl std::fmt::Display for InvalidTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid RFC3339 timestamp")
    }
}
impl std::error::Error for InvalidTimestamp {}

pub fn parse_rfc3339(raw: &str) -> Result<WireTimestamp, InvalidTimestamp> {
    // The previous parser represents second 60 as second 59 plus >=1e9 ns.
    // Preserve its ordering before the following ordinary second, rather than
    // silently normalizing a leap boundary into a different cursor position.
    let leap = raw.as_bytes().get(17..19) == Some(b"60");
    let mut input = raw.to_owned();
    if leap {
        input.replace_range(17..19, "59");
    }
    let parsed = OffsetDateTime::parse(&input, &Rfc3339).map_err(|_| InvalidTimestamp)?;
    Ok(WireTimestamp {
        seconds: parsed.unix_timestamp(),
        nanos: parsed.nanosecond() + if leap { 1_000_000_000 } else { 0 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn legacy_timestamp_wire_and_ordering_corpus() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../fixtures/compat/legacy-time-wire.json"
        ))
        .unwrap();
        for row in corpus["formats"].as_array().unwrap() {
            let at = row["millis"].as_i64().unwrap();
            assert_eq!(
                serde_json::to_value(rfc3339_millis(at)).unwrap(),
                row["text"],
                "{at}"
            );
            let nanos = UtcDateTime::from_unix_timestamp_nanos(i128::from(at) * 1_000_000)
                .ok()
                .and_then(legacy_range)
                .map(|v| format_utc(v, false));
            assert_eq!(serde_json::to_value(nanos).unwrap(), row["nanos"], "{at}");
        }
        for row in corpus["parsed"].as_array().unwrap() {
            let input = row["input"].as_str().unwrap();
            let parsed = parse_rfc3339(input).ok();
            assert_eq!(
                serde_json::to_value(parsed.map(WireTimestamp::timestamp_millis)).unwrap(),
                row["millis"],
                "{input}"
            );
            for (format, expected) in corpus["formats"]
                .as_array()
                .unwrap()
                .iter()
                .zip(row["at_or_after"].as_array().unwrap())
            {
                let at = format["millis"].as_i64().unwrap();
                let actual =
                    parsed.is_some_and(|p| WireTimestamp::from_millis(at).is_some_and(|v| v >= p));
                assert_eq!(actual, expected.as_bool().unwrap(), "{input} at {at}");
            }
        }
    }
}
