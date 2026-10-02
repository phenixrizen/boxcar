// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Session identifiers.

use std::fmt;
use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, Error as _};
use serde::ser::{Serialize, Serializer};
use uuid::Uuid;

/// The identifier of one boxcar session: a UUIDv7 in lowercase hyphenated text,
/// such as `017f22e2-79b0-7cc3-98c4-dc0c0c07398f`.
///
/// The text is what every audit record carries, what seeds the hash chain
/// (the genesis `prev` is the blake3 of it), and what names the session
/// directory. A session id therefore has exactly one accepted spelling:
/// [`FromStr`] and [`Deserialize`] reject any other spelling of a UUID.
///
/// A session id is always made on purpose ([`SessionId::new`]) or parsed:
/// there is no `Default`, so a struct that holds one cannot get a fresh
/// session by accident from `..Default::default()`.
///
/// ```compile_fail
/// let _ = boxcar_proto::SessionId::default();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionId(String);

/// The text is not a lowercase hyphenated UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session id must be a lowercase hyphenated UUID")]
pub struct ParseSessionIdError;

impl SessionId {
    /// A fresh id from the current time, so ids sort by creation order.
    // No `Default` on purpose: a session id is never made by accident
    // (see the type's docs).
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SessionId(Uuid::now_v7().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks that `text` is a UUID written exactly as `Uuid::to_string` writes it.
fn validate(text: &str) -> Result<(), ParseSessionIdError> {
    let uuid = Uuid::parse_str(text).map_err(|_| ParseSessionIdError)?;
    let mut buf = Uuid::encode_buffer();
    if uuid.hyphenated().encode_lower(&mut buf) == text {
        Ok(())
    } else {
        Err(ParseSessionIdError)
    }
}

impl FromStr for SessionId {
    type Err = ParseSessionIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        validate(text)?;
        Ok(SessionId(text.to_owned()))
    }
}

/// On the wire a string: a lowercase hyphenated UUID.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for SessionId {
    fn schema_name() -> String {
        "SessionId".to_owned()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        };
        schema.string().pattern =
            Some("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$".to_owned());
        schema.metadata().description =
            Some("A session id: a UUIDv7 in lowercase hyphenated text.".to_owned());
        schema.into()
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        validate(&text).map_err(D::Error::custom)?;
        Ok(SessionId(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

    #[test]
    fn new_ids_are_lowercase_hyphenated_uuid_v7() {
        let id = SessionId::new();
        assert_eq!(id.as_str().len(), 36);
        assert_eq!(id.to_string(), id.as_str());
        assert_eq!(id.as_str(), id.as_str().to_ascii_lowercase());
        let uuid = uuid::Uuid::parse_str(id.as_str()).unwrap();
        assert_eq!(uuid.get_version_num(), 7);
        assert_ne!(SessionId::new(), SessionId::new());
    }

    #[test]
    fn an_id_parses_back_to_itself() {
        let id = SessionId::new();
        assert_eq!(id.as_str().parse::<SessionId>().unwrap(), id);
        assert_eq!(ID.parse::<SessionId>().unwrap().as_str(), ID);
    }

    #[test]
    fn from_str_accepts_only_the_canonical_text_of_a_uuid() {
        assert!("00000000-0000-0000-0000-000000000000"
            .parse::<SessionId>()
            .is_ok());
        for bad in [
            "",
            "not-a-uuid",
            // Valid UUIDs in a form other than lowercase hyphenated: one
            // session id must have exactly one text form, because that text
            // is hashed into the chain and names the session directory.
            "017F22E2-79B0-7CC3-98C4-DC0C0C07398F",
            "017f22e279b07cc398c4dc0c0c07398f",
            "{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}",
            "urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            " 017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f\n",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398ff",
        ] {
            assert!(bad.parse::<SessionId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn serde_uses_a_plain_string_and_validates_on_the_way_in() {
        let id: SessionId = ID.parse().unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{ID}\""));
        assert_eq!(
            serde_json::from_str::<SessionId>(&format!("\"{ID}\"")).unwrap(),
            id
        );
        assert!(serde_json::from_str::<SessionId>("\"nope\"").is_err());
        assert!(serde_json::from_str::<SessionId>("7").is_err());
        assert!(serde_json::from_str::<SessionId>("null").is_err());
    }
}
