-- Past passwords for an entry, recorded whenever its password changes.
-- The prior password is stored as a (nonce, ciphertext) pair sealed by the
-- application layer, exactly like the live credential fields. Deleting an entry
-- cascades to its history.

CREATE TABLE password_history (
    id             BLOB    PRIMARY KEY NOT NULL, -- 16-byte UUID v7 (history row)
    entry_id       BLOB    NOT NULL,             -- FK -> entries(id)
    password_nonce BLOB    NOT NULL,
    password_ct    BLOB    NOT NULL,
    changed_at     INTEGER NOT NULL,             -- unix epoch millis
    FOREIGN KEY (entry_id) REFERENCES entries (id) ON DELETE CASCADE
);

CREATE INDEX idx_password_history_entry ON password_history (entry_id, changed_at DESC);
