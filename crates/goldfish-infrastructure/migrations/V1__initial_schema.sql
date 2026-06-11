-- Goldfish entry store schema (inside the SQLCipher-encrypted database).
-- Plaintext-searchable metadata lives in clear columns; credential fields are
-- stored as (nonce, ciphertext) pairs sealed by the application layer.

CREATE TABLE entries (
    id             BLOB    PRIMARY KEY NOT NULL, -- 16-byte UUID v7
    title          TEXT    NOT NULL,
    description    TEXT,
    url            TEXT,
    app_name       TEXT,
    folder_id      BLOB,                         -- 16-byte UUID or NULL
    favorite       INTEGER NOT NULL DEFAULT 0,
    version        INTEGER NOT NULL,             -- optimistic lock + AAD binding
    created_at     INTEGER NOT NULL,             -- unix epoch millis
    updated_at     INTEGER NOT NULL,
    username_nonce BLOB    NOT NULL,
    username_ct    BLOB    NOT NULL,
    password_nonce BLOB    NOT NULL,
    password_ct    BLOB    NOT NULL,
    notes_nonce    BLOB,
    notes_ct       BLOB,
    totp_nonce     BLOB,
    totp_ct        BLOB
);

CREATE INDEX idx_entries_title  ON entries (title COLLATE NOCASE);
CREATE INDEX idx_entries_folder ON entries (folder_id);

CREATE TABLE folders (
    id   BLOB PRIMARY KEY NOT NULL,
    name TEXT NOT NULL
);
