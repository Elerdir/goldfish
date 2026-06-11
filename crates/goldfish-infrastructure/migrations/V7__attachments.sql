-- Encrypted file attachments on entries. The file contents are sealed by the
-- application layer (AEAD, bound to the entry + attachment id); `name`/`size`
-- are plaintext metadata, like an entry's title. Deleting an entry cascades.

CREATE TABLE attachments (
    id         BLOB PRIMARY KEY NOT NULL, -- 16-byte UUID v7
    entry_id   BLOB    NOT NULL REFERENCES entries (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    size       INTEGER NOT NULL,          -- plaintext byte length
    blob_nonce BLOB    NOT NULL,
    blob_ct    BLOB    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0 -- epoch ms (ordering); 0 for legacy
);

CREATE INDEX idx_attachments_entry ON attachments (entry_id);
