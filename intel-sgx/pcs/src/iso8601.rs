use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer};
use serde::de;

const ISO8601_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

pub fn serialize<S>(timestamp: &DateTime<Utc>, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
{
    let timestamp = timestamp.format(ISO8601_FORMAT).to_string();
    serializer.serialize_str(&timestamp)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DateTime<Utc>, D::Error> {
    let timestamp = String::deserialize(deserializer)?;
    let timestamp = NaiveDateTime::parse_from_str(&timestamp, &ISO8601_FORMAT).map_err(de::Error::custom)?;
    Ok(timestamp.and_utc())
}
