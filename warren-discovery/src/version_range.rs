//! Client-version targeting shared by the broadcast envelopes (notices,
//! announcements).
//!
//! One implementation on purpose: the two envelopes are independent
//! formats, but an operator who targets `>= 1.10.0` has to get the same
//! audience from both, and a second copy of a version comparison drifts
//! the moment one of them grows a case the other does not.

use core::cmp::Ordering;

/// True if `client_version` satisfies the optional `min` / `max` bounds
/// (both inclusive). No bound at all applies to every client, including
/// one whose version is unknown.
///
/// A document that declares a range is **withheld** when the client
/// version is absent or unparseable: a targeted message shown to an
/// untargeted client is worse than one not shown.
pub(crate) fn in_bounds(
    client_version: Option<&str>,
    min: Option<&str>,
    max: Option<&str>,
) -> bool {
    if min.is_none() && max.is_none() {
        return true;
    }
    let Some(client) = client_version else {
        return false;
    };
    if let Some(min) = min
        && cmp_version(client, min).is_none_or(Ordering::is_lt)
    {
        return false;
    }
    if let Some(max) = max
        && cmp_version(client, max).is_none_or(Ordering::is_gt)
    {
        return false;
    }
    true
}

/// Compares two dotted numeric versions component-wise, so `1.11.0`
/// orders above `1.9.0` (a lexicographic compare gets that backwards).
/// A leading `v` and any pre-release suffix (`-beta1`, `+build`) are
/// ignored; missing trailing components read as 0, so `1.9` equals
/// `1.9.0`. `None` when either side carries no leading numeric
/// component, which callers treat as "cannot decide, do not show".
fn cmp_version(a: &str, b: &str) -> Option<Ordering> {
    let left = numeric_components(a)?;
    let right = numeric_components(b)?;
    let len = left.len().max(right.len());
    for i in 0..len {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}

/// Numeric components of a version string, stopping at the first
/// component that does not start with a digit. `None` when the very
/// first component is not numeric.
fn numeric_components(v: &str) -> Option<Vec<u64>> {
    let trimmed = v.trim().trim_start_matches(['v', 'V']);
    let mut out = Vec::new();
    for part in trimmed.split('.') {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        out.push(digits.parse::<u64>().ok()?);
        if digits.len() != part.len() {
            // Pre-release / build suffix: stop, the numeric prefix decides.
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}
