-- Tags: free-form labels applied to entries (many-to-many), complementary to
-- folders (one-to-many). Names are plaintext metadata, like folder names.

CREATE TABLE tags (
    id   BLOB PRIMARY KEY NOT NULL, -- 16-byte UUID v7
    name TEXT NOT NULL
);

CREATE TABLE entry_tags (
    entry_id BLOB NOT NULL REFERENCES entries (id) ON DELETE CASCADE,
    tag_id   BLOB NOT NULL REFERENCES tags (id)    ON DELETE CASCADE,
    PRIMARY KEY (entry_id, tag_id)
);

CREATE INDEX idx_entry_tags_tag ON entry_tags (tag_id);
