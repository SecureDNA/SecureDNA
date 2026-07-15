// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, de};
use serde_json::Value;

/// Deserialize a boolean, treating `"true"` as `true` and `"false"` as `false`.
pub fn bool_or_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    match serde::de::Deserialize::deserialize(deserializer)? {
        Value::Bool(b) => Ok(b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(serde::de::Error::custom("Expected boolean")),
    }
}

/// A wrapper around `std::time::Duration` that supports parsing from strings
/// like "1day", "2weeks", "3min", etc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FriendlyDuration(pub Duration);

impl FromStr for FriendlyDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(i) = s.find(char::is_alphabetic) else {
            return Err("must specify a unit like `12hr` or `2days`".to_owned());
        };

        let amount: u64 = s[..i]
            .trim()
            .parse()
            .map_err(|e| format!("failed to parse amount: {e}"))?;

        let unit_string = s[i..].trim().to_ascii_lowercase();
        let unit = match unit_string.as_str() {
            "s" | "sec" | "second" | "seconds" => 1,
            "m" | "min" | "minute" | "minutes" => 60,
            "h" | "hr" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 24 * 3600,
            "wk" | "week" | "weeks" => 7 * 24 * 3600,
            _ => return Err(format!("unknown unit {unit_string:?}")),
        };

        let Some(seconds) = amount.checked_mul(unit) else {
            return Err("duration is greater than 2^64 seconds".to_owned());
        };
        Ok(FriendlyDuration(Duration::from_secs(seconds)))
    }
}

impl fmt::Display for FriendlyDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0.as_secs())
    }
}

impl<'de> Deserialize<'de> for FriendlyDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_via_parse(deserializer)
    }
}

/// Deserialize a value by parsing it as a string using `FromStr`.
pub fn deserialize_via_parse<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    FromStr::from_str(&s).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_friendly_duration() {
        assert_eq!(
            FriendlyDuration::from_str("3min"),
            Ok(FriendlyDuration(Duration::from_mins(3)))
        );
        assert_eq!(
            FriendlyDuration::from_str("1D"),
            Ok(FriendlyDuration(Duration::from_hours(24)))
        );
        assert_eq!(
            FriendlyDuration::from_str("2 weeks"),
            Ok(FriendlyDuration(Duration::from_hours(2 * 7 * 24)))
        );
        assert_eq!(
            FriendlyDuration::from_str("-2 days"),
            Err("failed to parse amount: invalid digit found in string".to_owned())
        );
        assert_eq!(
            FriendlyDuration::from_str("2"),
            Err("must specify a unit like `12hr` or `2days`".to_owned())
        );
        assert_eq!(
            FriendlyDuration::from_str("weeks"),
            Err("failed to parse amount: cannot parse integer from empty string".to_owned())
        );
        assert_eq!(
            FriendlyDuration::from_str("2 xyz"),
            Err("unknown unit \"xyz\"".to_owned())
        );
        assert_eq!(
            FriendlyDuration::from_str("10000000000000000000 weeks"),
            Err("duration is greater than 2^64 seconds".to_owned())
        );
    }

    #[test]
    fn test_display_friendly_duration() {
        assert_eq!(FriendlyDuration(Duration::from_mins(3)).to_string(), "180s");
        assert_eq!(
            FriendlyDuration(Duration::from_hours(24)).to_string(),
            "86400s"
        );
    }

    #[test]
    fn test_serde_friendly_duration() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestStruct {
            duration: FriendlyDuration,
        }

        let test = TestStruct {
            duration: FriendlyDuration(Duration::from_hours(2)),
        };

        // Test deserialization with the original string format
        let json_s = r#"{"duration":"7200s"}"#;
        let deserialized_s: TestStruct = serde_json::from_str(json_s).unwrap();
        assert_eq!(test, deserialized_s);

        // Test deserialization with the friendly format
        let json_alt = r#"{"duration":"2h"}"#;
        let deserialized_alt: TestStruct = serde_json::from_str(json_alt).unwrap();
        assert_eq!(test, deserialized_alt);

        let json_invalid = r#"{"duration":"2years"}"#;
        assert!(serde_json::from_str::<TestStruct>(json_invalid).is_err());
    }
}
