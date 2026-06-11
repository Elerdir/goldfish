//! Password strength estimation via the `zxcvbn` crate.
//!
//! Exposed as a use case so the Tauri layer can answer the UI's live strength
//! queries without the frontend bundling a JS estimator. Returns the familiar
//! 0–4 zxcvbn score.

/// Estimates the strength of `password` on a 0 (weakest) – 4 (strongest) scale.
///
/// `user_inputs` (e.g. the entry title or username) are penalized if they
/// appear in the password.
#[must_use]
pub fn estimate_strength(password: &str, user_inputs: &[&str]) -> u8 {
    if password.is_empty() {
        return 0;
    }
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    entropy.score().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(estimate_strength("", &[]), 0);
    }

    #[test]
    fn trivial_password_is_weak() {
        assert!(estimate_strength("password", &[]) <= 1);
    }

    #[test]
    fn long_random_password_is_strong() {
        assert!(estimate_strength("9!qX#2vL8@mZ4wR^7tB&", &[]) >= 3);
    }

    #[test]
    fn user_input_is_penalized() {
        // A password equal to a user input should score poorly.
        let plain = estimate_strength("goldfish-app", &[]);
        let penalized = estimate_strength("goldfish-app", &["goldfish-app"]);
        assert!(penalized <= plain);
    }

    #[test]
    fn score_is_within_range() {
        for pw in [
            "a",
            "abc123",
            "correct horse battery staple",
            "Tr0ub4dour&3",
        ] {
            assert!(estimate_strength(pw, &[]) <= 4);
        }
    }
}
