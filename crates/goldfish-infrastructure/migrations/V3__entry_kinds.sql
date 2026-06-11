-- Entry kinds + custom fields.
-- `kind` is a plaintext discriminator (login / note / card / ssh / token);
-- existing rows default to 'login'. Custom fields are sealed by the application
-- layer as a single JSON blob (labels included), stored like any other field.

ALTER TABLE entries ADD COLUMN kind TEXT NOT NULL DEFAULT 'login';
ALTER TABLE entries ADD COLUMN custom_nonce BLOB;
ALTER TABLE entries ADD COLUMN custom_ct BLOB;
