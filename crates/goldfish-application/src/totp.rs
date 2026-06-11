//! TOTP (RFC 6238) code generation and secret validation.
//!
//! Accepts either a raw Base32 secret (SHA-1, 6 digits, 30 s — the de-facto
//! authenticator default) or a full `otpauth://` URL (whose parameters are
//! honored). Time is injected so the use case stays testable.

use totp_rs::{Algorithm, Secret, TOTP};

use crate::ApplicationError;

/// A generated TOTP code with timing for the UI countdown.
pub struct TotpCode {
    /// The current numeric code (zero-padded).
    pub code: String,
    /// Step length in seconds (typically 30).
    pub period: u64,
    /// Seconds until the code rotates.
    pub remaining: u64,
}

fn build(secret: &str) -> Result<TOTP, ApplicationError> {
    if secret.starts_with("otpauth://") {
        TOTP::from_url(secret).map_err(|e| ApplicationError::Totp(format!("{e:?}")))
    } else {
        let bytes = Secret::Encoded(secret.to_owned())
            .to_bytes()
            .map_err(|e| ApplicationError::Totp(format!("{e:?}")))?;
        // `new_unchecked` accepts real-world secrets shorter than the RFC 4226
        // minimum (e.g. 80-bit Google secrets), which `new` would reject.
        // With the `otpauth` feature it also takes issuer/account metadata, which
        // is irrelevant for code generation.
        Ok(TOTP::new_unchecked(
            Algorithm::SHA1,
            6,
            1,
            30,
            bytes,
            None,
            String::new(),
        ))
    }
}

/// Validates that `secret` is a usable Base32 secret or `otpauth://` URL.
pub fn validate_totp(secret: &str) -> Result<(), ApplicationError> {
    build(secret).map(|_| ())
}

/// Generates the TOTP code for `now_unix` (seconds since the Unix epoch).
pub fn generate_totp(secret: &str, now_unix: u64) -> Result<TotpCode, ApplicationError> {
    let totp = build(secret)?;
    let code = totp.generate(now_unix);
    let period = totp.step;
    let remaining = period - (now_unix % period);
    Ok(TotpCode {
        code,
        period,
        remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 reference: ASCII secret "12345678901234567890" (Base32
    /// `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`), SHA-1. At T=59 s the 8-digit code is
    /// 94287082, so the 6-digit truncation is 287082.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn kat_rfc6238_t59() {
        let code = generate_totp(RFC_SECRET, 59).unwrap();
        assert_eq!(code.code, "287082");
    }

    #[test]
    fn remaining_counts_down_within_step() {
        assert_eq!(generate_totp(RFC_SECRET, 0).unwrap().remaining, 30);
        assert_eq!(generate_totp(RFC_SECRET, 59).unwrap().remaining, 1);
        assert_eq!(generate_totp(RFC_SECRET, 45).unwrap().remaining, 15);
    }

    #[test]
    fn period_is_thirty_by_default() {
        assert_eq!(generate_totp(RFC_SECRET, 0).unwrap().period, 30);
    }

    #[test]
    fn validate_accepts_base32() {
        assert!(validate_totp(RFC_SECRET).is_ok());
    }

    #[test]
    fn validate_rejects_garbage() {
        assert!(matches!(
            validate_totp("not base32!!!"),
            Err(ApplicationError::Totp(_))
        ));
    }

    #[test]
    fn parses_otpauth_url() {
        let url = format!("otpauth://totp/Goldfish:user?secret={RFC_SECRET}&issuer=Goldfish");
        assert!(validate_totp(&url).is_ok());
        // Same secret via URL yields the same code as the bare Base32 form.
        assert_eq!(generate_totp(&url, 59).unwrap().code, "287082");
    }
}
