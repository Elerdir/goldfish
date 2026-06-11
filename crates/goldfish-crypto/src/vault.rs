//! Vault key hierarchy — the composition that ties every primitive together.
//!
//! ```text
//! master password ──Argon2id(salt,params)──▶ KEK
//!                                              │
//!         HMAC-SHA256(KEK,"…verifier") ◀───────┤   stored: verifier
//!                                              │
//!         XChaCha20-Poly1305(KEK).seal(DEK) ◀──┘   stored: wrapped_dek + nonce
//!                                              │
//!                                              ▼
//!                                             DEK ──HKDF(entry_id)──▶ per-entry subkey
//!                                                                       │
//!                                              XChaCha20-Poly1305.seal ◀┘
//! ```
//!
//! [`VaultKeyset`] holds the unlocked DEK and is the only handle the rest of
//! the app needs to encrypt/decrypt fields. The KEK lives only for the duration
//! of `create`/`unlock` and is dropped (zeroized) immediately afterward.

use zeroize::Zeroizing;

use crate::aead::{self, Sealed, NONCE_LEN};
use crate::derive;
use crate::kdf::{self, Argon2Params, SALT_LEN};
use crate::key::{SecretKey, KEY_LEN};
use crate::mac::{self, VERIFIER_LEN};
use crate::rng;
use crate::CryptoError;

/// Domain-separation label for per-entry subkey derivation.
const ENTRY_SUBKEY_INFO: &[u8] = b"goldfish-entry-v1";

/// HKDF salt + info for deriving the SQLCipher database key from the DEK.
const DB_KEY_SALT: &[u8] = b"goldfish-db";
const DB_KEY_INFO: &[u8] = b"goldfish-sqlcipher-db-key-v1";

/// AAD binding for the biometric-wrapped DEK.
const BIOMETRIC_AAD: &[u8] = b"goldfish-biometric-dek-v1";

/// Builds the AAD binding the recovery-wrapped DEK to the schema version. Kept
/// distinct from the master and biometric wraps so the ciphertexts can't be
/// cross-used.
fn recovery_dek_aad(schema_version: u32) -> Vec<u8> {
    let mut aad = b"goldfish-recovery-dek-v1".to_vec();
    aad.extend_from_slice(&schema_version.to_le_bytes());
    aad
}

/// Crockford base32 alphabet (omits I, L, O, U to avoid transcription errors).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes bytes as unpadded Crockford base32.
fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Generates a fresh ~160-bit recovery code in dash-separated groups of four.
///
/// The caller shows it to the user once and never stores it; the wrapping key is
/// derived from its normalized form (e.g. `A1B2-C3D4-…`).
#[must_use]
pub fn generate_recovery_code() -> Zeroizing<String> {
    let raw = Zeroizing::new(crockford_encode(&rng::generate::<20>()));
    let mut grouped = String::with_capacity(40);
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(c);
    }
    Zeroizing::new(grouped)
}

/// Builds the AAD that binds a wrapped DEK to the on-disk schema version,
/// preventing a downgrade attack that swaps in an older wrapped DEK.
fn dek_wrap_aad(schema_version: u32) -> Vec<u8> {
    let mut aad = b"goldfish-dek-v1".to_vec();
    aad.extend_from_slice(&schema_version.to_le_bytes());
    aad
}

/// Everything that must be persisted after creating a fresh vault. All fields
/// are public ciphertext/salt — none of them is secret on its own.
#[derive(Debug, Clone)]
pub struct NewVaultMaterial {
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// DEK encrypted under the KEK (includes the Poly1305 tag).
    pub wrapped_dek: Vec<u8>,
    /// Nonce used to wrap the DEK.
    pub wrapped_dek_nonce: [u8; NONCE_LEN],
    /// HMAC verifier for fast constant-time password checks.
    pub verifier: [u8; VERIFIER_LEN],
}

/// Borrowed view of the persisted material needed to unlock a vault.
#[derive(Debug, Clone, Copy)]
pub struct UnlockMaterial<'a> {
    /// Argon2id salt (as stored).
    pub salt: &'a [u8; SALT_LEN],
    /// Wrapped DEK ciphertext (as stored).
    pub wrapped_dek: &'a [u8],
    /// Nonce used to wrap the DEK (as stored).
    pub wrapped_dek_nonce: &'a [u8; NONCE_LEN],
    /// Stored HMAC verifier.
    pub verifier: &'a [u8; VERIFIER_LEN],
}

/// Material for enabling biometric unlock.
///
/// A random protection key (stored in the OS keystore, gated by biometrics)
/// plus the DEK sealed under that key (stored in vault metadata). Neither half
/// alone reveals the DEK.
pub struct BiometricMaterial {
    /// Random 32-byte protection key — store in the OS keystore.
    pub key: Zeroizing<[u8; KEY_LEN]>,
    /// Nonce for the sealed DEK.
    pub nonce: [u8; NONCE_LEN],
    /// DEK sealed under `key` (includes the AEAD tag).
    pub wrapped_dek: Vec<u8>,
}

/// Material for enabling recovery-code unlock.
///
/// A salt plus the DEK wrapped under a key derived from the recovery code. Stored
/// in vault metadata; useless without the code.
pub struct RecoveryMaterial {
    /// Argon2id salt for deriving the recovery key from the code.
    pub salt: [u8; SALT_LEN],
    /// DEK sealed under the recovery key (includes the AEAD tag).
    pub wrapped_dek: Vec<u8>,
    /// Nonce used to wrap the DEK.
    pub wrapped_dek_nonce: [u8; NONCE_LEN],
}

/// An unlocked vault's key material: holds the DEK, zeroized on drop.
#[derive(Debug)]
pub struct VaultKeyset {
    dek: SecretKey,
}

impl VaultKeyset {
    /// Creates a brand-new vault: generates salt + DEK, derives the KEK from the
    /// password, wraps the DEK, and computes the verifier.
    ///
    /// Returns the in-memory keyset plus the [`NewVaultMaterial`] to persist.
    pub fn create(
        password: &[u8],
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<(Self, NewVaultMaterial), CryptoError> {
        let salt: [u8; SALT_LEN] = rng::generate();
        let kek = kdf::derive_kek(password, &salt, params)?;
        let dek = SecretKey::generate();

        let nonce: [u8; NONCE_LEN] = rng::generate();
        let aad = dek_wrap_aad(schema_version);
        let wrapped_dek = aead::seal(&kek, &nonce, dek.as_bytes(), &aad)?;
        let verifier = mac::compute_verifier(&kek);

        let material = NewVaultMaterial {
            salt,
            wrapped_dek,
            wrapped_dek_nonce: nonce,
            verifier,
        };
        Ok((Self { dek }, material))
    }

    /// Unlocks an existing vault. Returns [`CryptoError::Decryption`] if the
    /// password is wrong (verifier mismatch) or the wrapped DEK is corrupt —
    /// the two cases are intentionally indistinguishable to the caller.
    pub fn unlock(
        password: &[u8],
        material: UnlockMaterial<'_>,
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<Self, CryptoError> {
        let kek = kdf::derive_kek(password, material.salt, params)?;
        if !mac::verify_verifier(&kek, material.verifier) {
            return Err(CryptoError::Decryption);
        }
        let aad = dek_wrap_aad(schema_version);
        let dek_bytes = aead::open(&kek, material.wrapped_dek_nonce, material.wrapped_dek, &aad)?;
        let dek = SecretKey::from_slice(&dek_bytes)?;
        Ok(Self { dek })
    }

    /// Re-wraps the **existing** DEK under a fresh salt/KEK derived from the same
    /// password with (typically stronger) `params`. Used to transparently upgrade
    /// a vault's KDF cost on unlock without changing the DEK — so every existing
    /// per-entry ciphertext stays valid. Returns the new material to persist.
    pub fn rewrap(
        &self,
        password: &[u8],
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<NewVaultMaterial, CryptoError> {
        let salt: [u8; SALT_LEN] = rng::generate();
        let kek = kdf::derive_kek(password, &salt, params)?;
        let nonce: [u8; NONCE_LEN] = rng::generate();
        let aad = dek_wrap_aad(schema_version);
        let wrapped_dek = aead::seal(&kek, &nonce, self.dek.as_bytes(), &aad)?;
        let verifier = mac::compute_verifier(&kek);
        Ok(NewVaultMaterial {
            salt,
            wrapped_dek,
            wrapped_dek_nonce: nonce,
            verifier,
        })
    }

    /// Produces [`RecoveryMaterial`] from a recovery `code`: derives a key from
    /// the code (Argon2id, fresh salt) and wraps the DEK under it.
    pub fn export_recovery_material(
        &self,
        code: &[u8],
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<RecoveryMaterial, CryptoError> {
        let salt: [u8; SALT_LEN] = rng::generate();
        let kek = kdf::derive_kek(code, &salt, params)?;
        let nonce: [u8; NONCE_LEN] = rng::generate();
        let aad = recovery_dek_aad(schema_version);
        let wrapped_dek = aead::seal(&kek, &nonce, self.dek.as_bytes(), &aad)?;
        Ok(RecoveryMaterial {
            salt,
            wrapped_dek,
            wrapped_dek_nonce: nonce,
        })
    }

    /// Reconstructs the keyset from a recovery `code` and stored recovery
    /// material. Fails (indistinguishably) on a wrong code or tampered material.
    pub fn from_recovery_material(
        code: &[u8],
        salt: &[u8; SALT_LEN],
        wrapped_dek: &[u8],
        wrapped_dek_nonce: &[u8; NONCE_LEN],
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<Self, CryptoError> {
        let kek = kdf::derive_kek(code, salt, params)?;
        let aad = recovery_dek_aad(schema_version);
        let dek_bytes = aead::open(&kek, wrapped_dek_nonce, wrapped_dek, &aad)?;
        let dek = SecretKey::from_slice(&dek_bytes)?;
        Ok(Self { dek })
    }

    /// Derives the SQLCipher database key (32 raw bytes) from the DEK.
    ///
    /// A dedicated HKDF subkey, so the page-encryption key is cryptographically
    /// independent of the per-entry field keys (defence in depth): compromising
    /// one does not reveal the other.
    pub fn derive_db_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        let subkey = derive::derive_subkey(&self.dek, DB_KEY_SALT, DB_KEY_INFO)
            .expect("HKDF expansion to 32 bytes is infallible");
        Zeroizing::new(*subkey.as_bytes())
    }

    /// Produces [`BiometricMaterial`] for enabling biometric unlock: a fresh
    /// random protection key and the DEK sealed under it.
    pub fn export_biometric_material(&self) -> Result<BiometricMaterial, CryptoError> {
        let protection_key = SecretKey::generate();
        let sealed = aead::seal_random_nonce(&protection_key, self.dek.as_bytes(), BIOMETRIC_AAD)?;
        Ok(BiometricMaterial {
            key: Zeroizing::new(*protection_key.as_bytes()),
            nonce: sealed.nonce,
            wrapped_dek: sealed.ciphertext,
        })
    }

    /// Reconstructs the keyset from a stored biometric protection key and the
    /// sealed DEK. Fails if the key is wrong or the ciphertext was tampered with.
    pub fn from_biometric_material(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        wrapped_dek: &[u8],
    ) -> Result<Self, CryptoError> {
        let protection_key = SecretKey::from_bytes(*key);
        let dek_bytes = aead::open(&protection_key, nonce, wrapped_dek, BIOMETRIC_AAD)?;
        let dek = SecretKey::from_slice(&dek_bytes)?;
        Ok(Self { dek })
    }

    /// Encrypts one entry field. `hkdf_salt` is the entry id; `aad` binds the
    /// ciphertext to its context (entry id + version). A random nonce is used.
    pub fn seal_field(
        &self,
        hkdf_salt: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError> {
        let subkey = derive::derive_subkey(&self.dek, hkdf_salt, ENTRY_SUBKEY_INFO)?;
        aead::seal_random_nonce(&subkey, plaintext, aad)
    }

    /// Decrypts one entry field. Returns the plaintext in zeroizing storage so
    /// it is wiped when the caller drops it.
    pub fn open_field(
        &self,
        hkdf_salt: &[u8],
        aad: &[u8],
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let subkey = derive::derive_subkey(&self.dek, hkdf_salt, ENTRY_SUBKEY_INFO)?;
        let plaintext = aead::open(&subkey, &sealed.nonce, &sealed.ciphertext, aad)?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn fast() -> Argon2Params {
        Argon2Params::new(256, 1, 1)
    }

    fn unlock_view(m: &NewVaultMaterial) -> UnlockMaterial<'_> {
        UnlockMaterial {
            salt: &m.salt,
            wrapped_dek: &m.wrapped_dek,
            wrapped_dek_nonce: &m.wrapped_dek_nonce,
            verifier: &m.verifier,
        }
    }

    #[test]
    fn create_then_unlock_recovers_same_dek() {
        let (ks_a, material) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let ks_b = VaultKeyset::unlock(b"master-pw", unlock_view(&material), fast(), 1).unwrap();

        // Prove both keysets share the same DEK: seal with A, open with B.
        let sealed = ks_a.seal_field(b"entry-id", b"aad", b"hunter2").unwrap();
        let opened = ks_b.open_field(b"entry-id", b"aad", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"hunter2");
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (_ks, material) = VaultKeyset::create(b"correct-pw", fast(), 1).unwrap();
        let err = VaultKeyset::unlock(b"wrong-pw", unlock_view(&material), fast(), 1).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn unlock_with_wrong_schema_version_fails() {
        // Verifier passes (KEK is correct) but the DEK-wrap AAD won't match.
        let (_ks, material) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let err = VaultKeyset::unlock(b"master-pw", unlock_view(&material), fast(), 2).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn unlock_with_tampered_verifier_fails() {
        let (_ks, mut material) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        material.verifier[0] ^= 0x01;
        let err = VaultKeyset::unlock(b"master-pw", unlock_view(&material), fast(), 1).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn unlock_with_tampered_wrapped_dek_fails() {
        let (_ks, mut material) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        material.wrapped_dek[0] ^= 0x01;
        let err = VaultKeyset::unlock(b"master-pw", unlock_view(&material), fast(), 1).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn field_round_trip() {
        let (ks, _m) = VaultKeyset::create(b"pw", fast(), 1).unwrap();
        let sealed = ks.seal_field(b"id-1", b"aad-1", b"value").unwrap();
        let opened = ks.open_field(b"id-1", b"aad-1", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"value");
    }

    #[test]
    fn field_open_with_wrong_aad_fails() {
        let (ks, _m) = VaultKeyset::create(b"pw", fast(), 1).unwrap();
        let sealed = ks.seal_field(b"id-1", b"aad-1", b"value").unwrap();
        let err = ks.open_field(b"id-1", b"aad-2", &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn db_key_is_deterministic_and_stable_across_unlock() {
        let (ks, material) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let k1 = ks.derive_db_key();
        let k2 = ks.derive_db_key();
        assert_eq!(*k1, *k2, "same keyset must yield the same DB key");

        let reopened =
            VaultKeyset::unlock(b"master-pw", unlock_view(&material), fast(), 1).unwrap();
        assert_eq!(*ks.derive_db_key(), *reopened.derive_db_key());
    }

    #[test]
    fn db_key_differs_across_vaults() {
        let (a, _) = VaultKeyset::create(b"same-pw", fast(), 1).unwrap();
        let (b, _) = VaultKeyset::create(b"same-pw", fast(), 1).unwrap();
        assert_ne!(*a.derive_db_key(), *b.derive_db_key());
    }

    #[test]
    fn biometric_material_round_trips_to_same_dek() {
        let (ks, _m) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let bio = ks.export_biometric_material().unwrap();
        let restored =
            VaultKeyset::from_biometric_material(&bio.key, &bio.nonce, &bio.wrapped_dek).unwrap();
        // Same DEK: a field sealed by the original opens with the restored keyset.
        let sealed = ks.seal_field(b"id", b"aad", b"secret").unwrap();
        let opened = restored.open_field(b"id", b"aad", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"secret");
    }

    #[test]
    fn biometric_unwrap_with_wrong_key_fails() {
        let (ks, _m) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let bio = ks.export_biometric_material().unwrap();
        let wrong = [0u8; 32];
        assert!(
            VaultKeyset::from_biometric_material(&wrong, &bio.nonce, &bio.wrapped_dek).is_err()
        );
    }

    #[test]
    fn field_open_with_wrong_entry_id_fails() {
        // Different HKDF salt → different subkey → authentication fails.
        let (ks, _m) = VaultKeyset::create(b"pw", fast(), 1).unwrap();
        let sealed = ks.seal_field(b"id-1", b"aad", b"value").unwrap();
        let err = ks.open_field(b"id-2", b"aad", &sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decryption));
    }

    #[test]
    fn rewrap_keeps_same_dek_under_new_params() {
        let (ks, _m) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        // A field sealed before the re-wrap…
        let sealed = ks.seal_field(b"id", b"aad", b"secret").unwrap();

        let stronger = Argon2Params::new(512, 2, 1);
        let material = ks.rewrap(b"master-pw", stronger, 1).unwrap();

        // …still opens after unlocking with the re-wrapped material (same DEK).
        let reopened =
            VaultKeyset::unlock(b"master-pw", unlock_view(&material), stronger, 1).unwrap();
        let opened = reopened.open_field(b"id", b"aad", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"secret");
    }

    #[test]
    fn rewrap_uses_a_fresh_salt_and_verifier() {
        let (ks, original) = VaultKeyset::create(b"pw", fast(), 1).unwrap();
        let rewrapped = ks.rewrap(b"pw", fast(), 1).unwrap();
        assert_ne!(original.salt, rewrapped.salt);
        assert_ne!(original.verifier, rewrapped.verifier);
    }

    #[test]
    fn recovery_material_round_trips_to_same_dek() {
        let (ks, _m) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let code = b"ABCD-EFGH-1234";
        let rec = ks.export_recovery_material(code, fast(), 1).unwrap();
        let restored = VaultKeyset::from_recovery_material(
            code,
            &rec.salt,
            &rec.wrapped_dek,
            &rec.wrapped_dek_nonce,
            fast(),
            1,
        )
        .unwrap();
        let sealed = ks.seal_field(b"id", b"aad", b"secret").unwrap();
        let opened = restored.open_field(b"id", b"aad", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"secret");
    }

    #[test]
    fn recovery_with_wrong_code_fails() {
        let (ks, _m) = VaultKeyset::create(b"master-pw", fast(), 1).unwrap();
        let rec = ks
            .export_recovery_material(b"right-code", fast(), 1)
            .unwrap();
        assert!(VaultKeyset::from_recovery_material(
            b"wrong-code",
            &rec.salt,
            &rec.wrapped_dek,
            &rec.wrapped_dek_nonce,
            fast(),
            1,
        )
        .is_err());
    }

    #[test]
    fn recovery_code_is_grouped_base32_and_random() {
        let code = generate_recovery_code();
        // 32 base32 chars + 7 separators.
        assert_eq!(code.len(), 39);
        assert_eq!(code.matches('-').count(), 7);
        assert_ne!(*generate_recovery_code(), *code);
    }
}
