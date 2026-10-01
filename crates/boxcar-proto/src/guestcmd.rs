// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The command the guest init runs as the session, as it travels on the
//! kernel command line in `boxcar.cmd=<value>`.
//!
//! The value is the argv as a JSON array of strings, base64url-encoded
//! without padding, so it is one token of printable ASCII with no spaces,
//! quotes or `=` whatever the arguments hold. The host encodes it; the
//! guest init decodes it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Why a `boxcar.cmd` value is not a command.
#[derive(Debug, thiserror::Error)]
pub enum GuestCmdError {
    /// The value is not base64url without padding.
    #[error("not base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The decoded bytes are not a JSON array of strings.
    #[error("not a JSON array of strings: {0}")]
    Json(#[from] serde_json::Error),
    /// The array is empty: there is no program to run.
    #[error("the command is empty")]
    Empty,
}

/// The `boxcar.cmd` value for `argv`: its JSON array, base64url-encoded
/// without padding.
pub fn encode(argv: &[String]) -> String {
    // A slice of strings always serializes.
    let json = serde_json::to_vec(argv).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json)
}

/// The argv a `boxcar.cmd` value carries. Fails on anything [`encode`]
/// cannot have produced, and on an empty argv.
pub fn decode(s: &str) -> Result<Vec<String>, GuestCmdError> {
    let json = URL_SAFE_NO_PAD.decode(s)?;
    let argv: Vec<String> = serde_json::from_slice(&json)?;
    if argv.is_empty() {
        return Err(GuestCmdError::Empty);
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn round_trips_any_strings() {
        for args in [
            argv(&["/bin/sh", "-l"]),
            argv(&[
                "/bin/sh",
                "-c",
                "echo \"hi there\" > /workspace/a.txt; exit 7",
            ]),
            argv(&["x", "", " ", "a=b", "tab\tnewline\n", "ünïcødé", "\\", "'"]),
            argv(&["only"]),
        ] {
            let encoded = encode(&args);
            assert_eq!(decode(&encoded).unwrap(), args, "{encoded}");
        }
    }

    #[test]
    fn the_value_is_one_cmdline_safe_token() {
        let encoded = encode(&argv(&["/bin/sh", "-c", "a b \"c\" = d?>~"]));
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{encoded}"
        );
    }

    #[test]
    fn it_is_base64url_of_the_json_array() {
        assert_eq!(
            encode(&argv(&["/bin/sh", "-l"])),
            b64(br#"["/bin/sh","-l"]"#)
        );
    }

    #[test]
    fn invalid_base64_is_rejected() {
        for bad in ["not base64!", "a", "WyIvYmluL3NoIl0=", "WyIvYmluL3NoIl0+"] {
            assert!(
                matches!(decode(bad), Err(GuestCmdError::Base64(_))),
                "{bad:?}: {:?}",
                decode(bad)
            );
        }
    }

    #[test]
    fn valid_base64_that_is_not_an_array_of_strings_is_rejected() {
        for json in [
            &b"\"/bin/sh\""[..],
            b"{\"argv\":[\"/bin/sh\"]}",
            b"[\"/bin/sh\",1]",
            b"[[\"/bin/sh\"]]",
            b"null",
            b"[\"/bin/sh\"] trailing",
            b"\xff\xfe",
            b"",
        ] {
            let value = b64(json);
            assert!(
                matches!(decode(&value), Err(GuestCmdError::Json(_))),
                "{json:?}: {:?}",
                decode(&value)
            );
        }
    }

    #[test]
    fn an_empty_array_is_rejected() {
        assert!(matches!(decode(&b64(b"[]")), Err(GuestCmdError::Empty)));
        assert!(matches!(decode(&encode(&[])), Err(GuestCmdError::Empty)));
    }
}
