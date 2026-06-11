//! Integration test: full vault lifecycle through the public crypto API only.
//!
//! Mirrors how `goldfish-infrastructure` will use the crate: create a vault,
//! persist the material, then unlock from that material and round-trip a field.

use goldfish_crypto::{Argon2Params, UnlockMaterial, VaultKeyset};

/// Fast Argon2 params so the test suite stays quick. Real vaults use DEFAULT.
const fn fast() -> Argon2Params {
    Argon2Params::new(256, 1, 1)
}

fn unlock_view(m: &goldfish_crypto::NewVaultMaterial) -> UnlockMaterial<'_> {
    UnlockMaterial {
        salt: &m.salt,
        wrapped_dek: &m.wrapped_dek,
        wrapped_dek_nonce: &m.wrapped_dek_nonce,
        verifier: &m.verifier,
    }
}

#[test]
fn create_persist_unlock_and_use() {
    const SCHEMA: u32 = 1;

    // 1. Create a fresh vault.
    let (keyset, material) = VaultKeyset::create(b"S3cure-Master!", fast(), SCHEMA).unwrap();

    // 2. Seal some fields (as the repository would on insert).
    let entry_id = b"0190f7c1-uuid-bytes";
    let aad = b"0190f7c1-uuid-bytes|v1";
    let user = keyset.seal_field(entry_id, aad, b"octocat").unwrap();
    let pass = keyset
        .seal_field(entry_id, aad, b"hunter2-correct-horse")
        .unwrap();

    // 3. Drop the live keyset; simulate a fresh app start that only has the
    //    persisted material.
    drop(keyset);

    // 4. Unlock from persisted material.
    let reopened = VaultKeyset::unlock(b"S3cure-Master!", unlock_view(&material), fast(), SCHEMA)
        .expect("unlock with correct password");

    // 5. Decrypt the fields sealed before the "restart".
    let user_pt = reopened.open_field(entry_id, aad, &user).unwrap();
    let pass_pt = reopened.open_field(entry_id, aad, &pass).unwrap();
    assert_eq!(user_pt.as_slice(), b"octocat");
    assert_eq!(pass_pt.as_slice(), b"hunter2-correct-horse");
}

#[test]
fn two_vaults_same_password_are_cryptographically_isolated() {
    // Different salts → different KEKs → different DEKs, even with identical
    // passwords. A field sealed in vault A must not open in vault B.
    let (vault_a, _ma) = VaultKeyset::create(b"same-password", fast(), 1).unwrap();
    let (vault_b, _mb) = VaultKeyset::create(b"same-password", fast(), 1).unwrap();

    let sealed = vault_a.seal_field(b"id", b"aad", b"secret").unwrap();
    let err = vault_b.open_field(b"id", b"aad", &sealed);
    assert!(err.is_err(), "cross-vault decryption must fail");
}

#[test]
fn wrong_password_cannot_unlock() {
    let (_keyset, material) = VaultKeyset::create(b"right-password", fast(), 1).unwrap();
    let err = VaultKeyset::unlock(b"WRONG-password", unlock_view(&material), fast(), 1);
    assert!(err.is_err());
}
