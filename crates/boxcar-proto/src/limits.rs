// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Size limits for audit records (design spec, section 6).
//!
//! Producers cut an oversized field with [`truncate_utf8`] before they put it
//! in a record.

/// Longest path recorded, in bytes.
pub const MAX_PATH: usize = 4096;
/// Most argv elements recorded.
pub const MAX_ARGV_ELEMS: usize = 256;
/// Most argv bytes recorded, summed over all elements.
pub const MAX_ARGV_BYTES: usize = 16384;
/// Longest summary recorded, in bytes.
pub const MAX_SUMMARY: usize = 512;
/// Largest body stored inline in a record. A larger body is hashed, never inlined.
pub const INLINE_MAX: usize = 8192;
/// Largest serialized record, in bytes.
pub const MAX_RECORD_BYTES: usize = 65536;

/// Marks the end of a string that was cut.
const ELLIPSIS: &str = "…";

/// Cuts `s` so that the result is at most `max` bytes, and reports whether it
/// was cut.
///
/// A string that already fits comes back whole with `false`. Otherwise the
/// result is the longest prefix of `s` that ends on a char boundary and still
/// leaves room for a trailing `…` (3 bytes), so a cut never splits a
/// multi-byte char and the result never exceeds `max`, ellipsis included.
/// When `max` is under 3 there is no room for the ellipsis: the result is
/// then the longest prefix that fits, without one.
pub fn truncate_utf8(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_owned(), false);
    }
    let (budget, suffix) = match max.checked_sub(ELLIPSIS.len()) {
        Some(budget) => (budget, ELLIPSIS),
        None => (max, ""),
    };
    let end = s.floor_char_boundary(budget);
    let mut out = String::with_capacity(end + suffix.len());
    out.push_str(&s[..end]);
    out.push_str(suffix);
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_match_the_spec() {
        assert_eq!(MAX_PATH, 4096);
        assert_eq!(MAX_ARGV_ELEMS, 256);
        assert_eq!(MAX_ARGV_BYTES, 16 * 1024);
        assert_eq!(MAX_SUMMARY, 512);
        assert_eq!(INLINE_MAX, 8 * 1024);
        assert_eq!(MAX_RECORD_BYTES, 64 * 1024);
    }

    #[test]
    fn a_string_that_fits_is_returned_whole() {
        assert_eq!(truncate_utf8("hello", 5), ("hello".to_string(), false));
        assert_eq!(truncate_utf8("hello", 500), ("hello".to_string(), false));
        assert_eq!(truncate_utf8("", 0), (String::new(), false));
        let mixed = "héllo wörld 世界 😀";
        assert_eq!(
            truncate_utf8(mixed, mixed.len()),
            (mixed.to_string(), false)
        );
    }

    #[test]
    fn a_cut_ascii_string_ends_with_an_ellipsis_and_stays_within_max() {
        let (out, cut) = truncate_utf8("abcdefghij", 8);
        assert!(cut);
        assert_eq!(out, "abcde…");
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn a_cut_backs_up_to_a_char_boundary_rather_than_splitting_a_char() {
        // 'é' is 2 bytes. With max 6 the content budget is 3 bytes: "ab" is 2,
        // and the next char would span bytes 2..4, so it is dropped whole.
        assert_eq!(truncate_utf8("abéééé", 6), ("ab…".to_string(), true));
        // A 3-byte char: budget 5, 'a' (1) + '世' (3) fit, the next '界' does not.
        assert_eq!(truncate_utf8("a世界世界", 8), ("a世…".to_string(), true));
        // A 4-byte char: budget 7, one emoji fits, two do not.
        assert_eq!(truncate_utf8("😀😀😀😀", 10), ("😀…".to_string(), true));
    }

    #[test]
    fn the_result_never_exceeds_max_and_keeps_the_longest_prefix() {
        let samples = [
            "",
            "a",
            "abc",
            "aaaaaaaaaaaaaaaaaaaa",
            "héllo wörld",
            "日本語のテキスト",
            "😀 emoji 😀 mix é 世",
        ];
        for s in samples {
            for max in 0..=s.len() + 2 {
                let (out, cut) = truncate_utf8(s, max);
                if s.len() <= max {
                    assert_eq!((out.as_str(), cut), (s, false), "{s:?} max {max}");
                    continue;
                }
                assert!(cut, "{s:?} max {max}");
                assert!(out.len() <= max, "{s:?} max {max}: {out:?}");
                if max >= ELLIPSIS.len() {
                    let kept = out
                        .strip_suffix(ELLIPSIS)
                        .expect("cut output ends with an ellipsis");
                    assert!(s.starts_with(kept), "{s:?} max {max}: {out:?}");
                    // Longest prefix: the next char would not have fit.
                    let next = s[kept.len()..].chars().next().unwrap();
                    assert!(
                        kept.len() + next.len_utf8() + ELLIPSIS.len() > max,
                        "{s:?} max {max}: {out:?} dropped more than it had to"
                    );
                } else {
                    // No room even for the ellipsis: a bare prefix, still <= max.
                    assert!(s.starts_with(out.as_str()), "{s:?} max {max}: {out:?}");
                }
            }
        }
    }
}
