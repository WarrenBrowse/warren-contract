//! Environment-value parsing shared by every client and the backend.
//!
//! Boolean knobs are spelled inconsistently across the stack (`1`, `true`,
//! `yes`, `on`). A strict `true`/`false`-only parser that aborts on any other
//! value once crash-looped a privileged process when a manifest set
//! `WARREN_ENABLE_DAITA=1`. Parsing every knob through one lenient helper that
//! returns `None` (rather than aborting) on an unrecognized value removes that
//! whole class of failure and keeps the accepted dialect identical everywhere.

/// Strictness of [`parse_bool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolParse {
    /// Accept the full dialect: `true`/`1`/`yes`/`on` and
    /// `false`/`0`/`no`/`off`, case-insensitive, surrounding whitespace
    /// trimmed. This is the safe default for a runtime knob: a numeric or
    /// `yes`/`no` spelling is honored instead of being fatal.
    Lenient,
    /// Accept only the canonical `true`/`false` spelling (case-insensitive,
    /// trimmed). Every other value is rejected. For a setting where an
    /// ambiguous spelling should be surfaced rather than guessed.
    Strict,
}

/// Parses a boolean environment value, returning `None` for an unrecognized
/// form so the caller keeps control of the fallback instead of the process
/// aborting.
#[must_use]
pub fn parse_bool(raw: &str, mode: BoolParse) -> Option<bool> {
    let v = raw.trim();
    let matches_any = |set: &[&str]| set.iter().any(|w| v.eq_ignore_ascii_case(w));
    match mode {
        BoolParse::Strict => {
            if v.eq_ignore_ascii_case("true") {
                Some(true)
            } else if v.eq_ignore_ascii_case("false") {
                Some(false)
            } else {
                None
            }
        }
        BoolParse::Lenient => {
            if matches_any(&["true", "1", "yes", "on"]) {
                Some(true)
            } else if matches_any(&["false", "0", "no", "off"]) {
                Some(false)
            } else {
                None
            }
        }
    }
}

/// Convenience wrapper for the `std::env::var(name).ok()` shape: an absent
/// (`None`) or unrecognized value yields `default`, so a caller never has to
/// re-derive the fallback branch.
#[must_use]
pub fn parse_bool_or(raw: Option<&str>, default: bool, mode: BoolParse) -> bool {
    raw.and_then(|v| parse_bool(v, mode)).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::{BoolParse, parse_bool, parse_bool_or};

    #[test]
    fn lenient_accepts_every_truthy_spelling() {
        for raw in ["true", "TRUE", "True", "1", "yes", "YES", "on", "On"] {
            assert_eq!(
                parse_bool(raw, BoolParse::Lenient),
                Some(true),
                "{raw:?} must parse as true in lenient mode"
            );
        }
    }

    #[test]
    fn lenient_accepts_every_falsy_spelling() {
        for raw in ["false", "FALSE", "False", "0", "no", "NO", "off", "Off"] {
            assert_eq!(
                parse_bool(raw, BoolParse::Lenient),
                Some(false),
                "{raw:?} must parse as false in lenient mode"
            );
        }
    }

    #[test]
    fn lenient_trims_surrounding_whitespace() {
        assert_eq!(parse_bool("  1 ", BoolParse::Lenient), Some(true));
        assert_eq!(parse_bool("\tfalse\n", BoolParse::Lenient), Some(false));
    }

    #[test]
    fn lenient_rejects_garbage_instead_of_guessing() {
        for raw in ["", "2", "tru", "enable", "y", "n", "10"] {
            assert_eq!(
                parse_bool(raw, BoolParse::Lenient),
                None,
                "{raw:?} is not a recognized boolean and must yield None"
            );
        }
    }

    #[test]
    fn strict_accepts_only_true_false() {
        assert_eq!(parse_bool("true", BoolParse::Strict), Some(true));
        assert_eq!(parse_bool("FALSE", BoolParse::Strict), Some(false));
        // The lenient spellings must be rejected under strict mode.
        for raw in ["1", "0", "yes", "no", "on", "off"] {
            assert_eq!(
                parse_bool(raw, BoolParse::Strict),
                None,
                "{raw:?} must not be accepted in strict mode"
            );
        }
    }

    #[test]
    fn parse_bool_or_falls_back_on_absent_or_unrecognized() {
        assert!(
            parse_bool_or(None, true, BoolParse::Lenient),
            "absent value keeps the default"
        );
        assert!(
            parse_bool_or(Some("garbage"), true, BoolParse::Lenient),
            "unrecognized value keeps the default"
        );
        // A recognized value wins over the default, in both directions.
        assert!(
            !parse_bool_or(Some("0"), true, BoolParse::Lenient),
            "an explicit 0 overrides a true default"
        );
        assert!(
            parse_bool_or(Some("on"), false, BoolParse::Lenient),
            "an explicit on overrides a false default"
        );
    }
}
