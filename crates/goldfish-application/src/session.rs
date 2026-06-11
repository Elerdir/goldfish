//! Unlocked vault session — the in-memory key material plus the sealing logic.
//!
//! A [`VaultSession`] wraps the unlocked [`VaultKeyset`] and knows how to map
//! between the decrypted [`Entry`] and the encrypted [`SealedEntry`]. Fields are
//! sealed **individually**, each with a fresh random nonce and an AAD that binds
//! it to `entry_id ‖ version ‖ field_tag` — so ciphertext cannot be replayed
//! across entries, versions, or fields (defeats field-swap attacks).

use goldfish_crypto::{Argon2Params, RecoveryMaterial, Sealed, VaultKeyset, NONCE_LEN};
use goldfish_domain::{CustomField, Entry, EntryId, PlaintextSecret, SealedEntry, SealedField};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ApplicationError;

const FIELD_USERNAME: &[u8] = b"username";
const FIELD_PASSWORD: &[u8] = b"password";
const FIELD_NOTES: &[u8] = b"notes";
const FIELD_TOTP: &[u8] = b"totp";
const FIELD_CUSTOM: &[u8] = b"custom-fields";
const FIELD_PW_HISTORY: &[u8] = b"password-history";
const FIELD_ATTACHMENT: &[u8] = b"attachment";

/// Wire form of a custom field for the sealed JSON blob. Labels and values both
/// live inside the ciphertext, so neither leaks on disk.
#[derive(Serialize, Deserialize)]
struct WireField {
    label: String,
    value: String,
    hidden: bool,
}

/// An unlocked vault: holds the DEK-bearing keyset. Dropping it drops
/// (zeroizes) the keyset.
#[derive(Debug)]
pub struct VaultSession {
    keyset: VaultKeyset,
}

/// AAD = entry id (16 B) ‖ version (4 B LE) ‖ field tag. Binds each ciphertext
/// to its exact slot.
fn field_aad(id: EntryId, version: u32, field: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + field.len());
    aad.extend_from_slice(id.0.as_bytes());
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(field);
    aad
}

/// AAD = entry id (16 B) ‖ history-row id (16 B) ‖ tag. Binds a sealed past
/// password to its entry and its unique history row.
fn history_aad(entry_id: EntryId, history_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + FIELD_PW_HISTORY.len());
    aad.extend_from_slice(entry_id.0.as_bytes());
    aad.extend_from_slice(history_id.as_bytes());
    aad.extend_from_slice(FIELD_PW_HISTORY);
    aad
}

/// AAD = entry id (16 B) ‖ attachment id (16 B) ‖ tag. Binds a sealed file to
/// its entry and its unique attachment row.
fn attachment_aad(entry_id: EntryId, attachment_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + FIELD_ATTACHMENT.len());
    aad.extend_from_slice(entry_id.0.as_bytes());
    aad.extend_from_slice(attachment_id.as_bytes());
    aad.extend_from_slice(FIELD_ATTACHMENT);
    aad
}

impl VaultSession {
    /// Wraps an unlocked keyset. Crate-private — sessions only come from the
    /// `VaultService` create/unlock paths.
    pub(crate) const fn new(keyset: VaultKeyset) -> Self {
        Self { keyset }
    }

    /// Produces biometric-unlock material from this unlocked session.
    pub(crate) fn export_biometric_material(
        &self,
    ) -> Result<goldfish_crypto::BiometricMaterial, ApplicationError> {
        self.keyset
            .export_biometric_material()
            .map_err(|e| ApplicationError::Crypto(e.to_string()))
    }

    /// Produces recovery-code material (DEK wrapped under the given code).
    pub(crate) fn export_recovery_material(
        &self,
        code: &[u8],
        params: Argon2Params,
        schema_version: u32,
    ) -> Result<RecoveryMaterial, ApplicationError> {
        self.keyset
            .export_recovery_material(code, params, schema_version)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))
    }

    /// Encrypts a full entry into its sealed, persistable form.
    pub(crate) fn seal_entry(&self, entry: &Entry) -> Result<SealedEntry, ApplicationError> {
        let id = entry.id;
        let version = entry.version;
        let salt = id.0.as_bytes();

        let username = self.seal(salt, id, version, FIELD_USERNAME, entry.username.as_bytes())?;
        let password = self.seal(
            salt,
            id,
            version,
            FIELD_PASSWORD,
            entry.password.expose().as_bytes(),
        )?;
        let notes = entry
            .notes
            .as_ref()
            .map(|n| self.seal(salt, id, version, FIELD_NOTES, n.expose().as_bytes()))
            .transpose()?;
        let totp_secret = entry
            .totp_secret
            .as_ref()
            .map(|t| self.seal(salt, id, version, FIELD_TOTP, t.expose().as_bytes()))
            .transpose()?;
        let custom = self.seal_custom_fields(salt, id, version, &entry.custom_fields)?;

        Ok(SealedEntry {
            id,
            kind: entry.kind,
            title: entry.title.clone(),
            description: entry.description.clone(),
            url: entry.url.clone(),
            app_name: entry.app_name.clone(),
            folder_id: entry.folder_id,
            favorite: entry.favorite,
            version,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            username,
            password,
            notes,
            totp_secret,
            custom,
            tags: entry.tags.clone(),
        })
    }

    /// Decrypts a sealed entry back into its plaintext form.
    pub(crate) fn open_entry(&self, sealed: &SealedEntry) -> Result<Entry, ApplicationError> {
        let id = sealed.id;
        let version = sealed.version;
        let salt = id.0.as_bytes();

        let username_bytes = self.open(salt, id, version, FIELD_USERNAME, &sealed.username)?;
        let username = std::str::from_utf8(username_bytes.as_slice())
            .map_err(|_| ApplicationError::Crypto("invalid utf-8 in username".to_owned()))?
            .to_owned();

        let password = self.open_secret(salt, id, version, FIELD_PASSWORD, &sealed.password)?;
        let notes = sealed
            .notes
            .as_ref()
            .map(|f| self.open_secret(salt, id, version, FIELD_NOTES, f))
            .transpose()?;
        let totp_secret = sealed
            .totp_secret
            .as_ref()
            .map(|f| self.open_secret(salt, id, version, FIELD_TOTP, f))
            .transpose()?;
        let custom_fields = self.open_custom_fields(salt, id, version, sealed.custom.as_ref())?;

        Ok(Entry {
            id,
            kind: sealed.kind,
            title: sealed.title.clone(),
            description: sealed.description.clone(),
            url: sealed.url.clone(),
            app_name: sealed.app_name.clone(),
            username,
            password,
            notes,
            totp_secret,
            folder_id: sealed.folder_id,
            favorite: sealed.favorite,
            custom_fields,
            tags: sealed.tags.clone(),
            version,
            created_at: sealed.created_at,
            updated_at: sealed.updated_at,
        })
    }

    /// Serializes the custom fields to JSON and seals the whole blob as one
    /// field. Returns `None` when there are no custom fields.
    fn seal_custom_fields(
        &self,
        salt: &[u8],
        id: EntryId,
        version: u32,
        fields: &[CustomField],
    ) -> Result<Option<SealedField>, ApplicationError> {
        if fields.is_empty() {
            return Ok(None);
        }
        let wire: Vec<WireField> = fields
            .iter()
            .map(|f| WireField {
                label: f.label.clone(),
                value: f.value.expose().to_owned(),
                hidden: f.hidden,
            })
            .collect();
        let json = Zeroizing::new(
            serde_json::to_vec(&wire).map_err(|e| ApplicationError::Crypto(e.to_string()))?,
        );
        Ok(Some(self.seal(
            salt,
            id,
            version,
            FIELD_CUSTOM,
            json.as_slice(),
        )?))
    }

    /// Opens and deserializes the sealed custom-fields blob (empty if absent).
    fn open_custom_fields(
        &self,
        salt: &[u8],
        id: EntryId,
        version: u32,
        sealed: Option<&SealedField>,
    ) -> Result<Vec<CustomField>, ApplicationError> {
        let Some(field) = sealed else {
            return Ok(Vec::new());
        };
        let bytes = self.open(salt, id, version, FIELD_CUSTOM, field)?;
        let wire: Vec<WireField> = serde_json::from_slice(bytes.as_slice())
            .map_err(|_| ApplicationError::Crypto("invalid custom-fields blob".to_owned()))?;
        Ok(wire
            .into_iter()
            .map(|w| CustomField {
                label: w.label,
                value: PlaintextSecret::from(w.value),
                hidden: w.hidden,
            })
            .collect())
    }

    /// Seals a previous password for a history row (salt = entry id, AAD binds
    /// entry id + history-row id).
    pub(crate) fn seal_history_password(
        &self,
        entry_id: EntryId,
        history_id: Uuid,
        password: &str,
    ) -> Result<SealedField, ApplicationError> {
        let aad = history_aad(entry_id, history_id);
        let sealed = self
            .keyset
            .seal_field(entry_id.0.as_bytes(), &aad, password.as_bytes())
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;
        Ok(SealedField {
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        })
    }

    /// Decrypts a sealed history password back into plaintext.
    pub(crate) fn open_history_password(
        &self,
        entry_id: EntryId,
        history_id: Uuid,
        sealed: &SealedField,
    ) -> Result<PlaintextSecret, ApplicationError> {
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::Crypto("invalid nonce length".to_owned()))?;
        let crypto_sealed = Sealed {
            nonce,
            ciphertext: sealed.ciphertext.clone(),
        };
        let aad = history_aad(entry_id, history_id);
        let bytes = self
            .keyset
            .open_field(entry_id.0.as_bytes(), &aad, &crypto_sealed)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;
        let text = std::str::from_utf8(bytes.as_slice())
            .map_err(|_| ApplicationError::Crypto("invalid utf-8 in history".to_owned()))?;
        Ok(PlaintextSecret::from(text))
    }

    /// Seals an attachment's file bytes (salt = entry id, AAD binds entry id +
    /// attachment-row id).
    pub(crate) fn seal_attachment(
        &self,
        entry_id: EntryId,
        attachment_id: Uuid,
        bytes: &[u8],
    ) -> Result<SealedField, ApplicationError> {
        let aad = attachment_aad(entry_id, attachment_id);
        let sealed = self
            .keyset
            .seal_field(entry_id.0.as_bytes(), &aad, bytes)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;
        Ok(SealedField {
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        })
    }

    /// Decrypts a sealed attachment back into its file bytes (zeroized on drop).
    pub(crate) fn open_attachment(
        &self,
        entry_id: EntryId,
        attachment_id: Uuid,
        sealed: &SealedField,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::Crypto("invalid nonce length".to_owned()))?;
        let crypto_sealed = Sealed {
            nonce,
            ciphertext: sealed.ciphertext.clone(),
        };
        let aad = attachment_aad(entry_id, attachment_id);
        self.keyset
            .open_field(entry_id.0.as_bytes(), &aad, &crypto_sealed)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))
    }

    fn seal(
        &self,
        salt: &[u8],
        id: EntryId,
        version: u32,
        field: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedField, ApplicationError> {
        let aad = field_aad(id, version, field);
        let sealed = self
            .keyset
            .seal_field(salt, &aad, plaintext)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))?;
        Ok(SealedField {
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        })
    }

    fn open(
        &self,
        salt: &[u8],
        id: EntryId,
        version: u32,
        field: &[u8],
        sealed: &SealedField,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ApplicationError::Crypto("invalid nonce length".to_owned()))?;
        let crypto_sealed = Sealed {
            nonce,
            ciphertext: sealed.ciphertext.clone(),
        };
        let aad = field_aad(id, version, field);
        self.keyset
            .open_field(salt, &aad, &crypto_sealed)
            .map_err(|e| ApplicationError::Crypto(e.to_string()))
    }

    fn open_secret(
        &self,
        salt: &[u8],
        id: EntryId,
        version: u32,
        field: &[u8],
        sealed: &SealedField,
    ) -> Result<PlaintextSecret, ApplicationError> {
        let bytes = self.open(salt, id, version, field, sealed)?;
        let text = std::str::from_utf8(bytes.as_slice())
            .map_err(|_| ApplicationError::Crypto("invalid utf-8 in secret".to_owned()))?;
        Ok(PlaintextSecret::from(text))
    }
}
