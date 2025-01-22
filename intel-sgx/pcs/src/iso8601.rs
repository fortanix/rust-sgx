use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer};
use serde::de;

const ISO8601_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DateTime<Utc>, D::Error> {
    let timestamp = String::deserialize(deserializer)?;
    let timestamp = NaiveDateTime::parse_from_str(&timestamp, &ISO8601_FORMAT).map_err(de::Error::custom)?;
    Ok(timestamp.and_utc())
}
