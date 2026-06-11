-- Per-view manual ordering.
--
-- Two independent position columns let the user arrange entries differently in
-- the "All entries" view (`all_pos`) and within each folder (`folder_pos`). New
-- entries are appended to the end of both; the application maintains them.
--
-- Existing rows are backfilled to match the previous alphabetical display so the
-- order does not visibly reshuffle on first launch after the upgrade. Each row's
-- position is its 0-based rank by (title, id) — globally for `all_pos`, and
-- partitioned by folder for `folder_pos`.

ALTER TABLE entries ADD COLUMN all_pos    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE entries ADD COLUMN folder_pos INTEGER NOT NULL DEFAULT 0;

UPDATE entries SET all_pos = (
    SELECT COUNT(*) FROM entries e2
    WHERE e2.title COLLATE NOCASE < entries.title COLLATE NOCASE
       OR (e2.title COLLATE NOCASE = entries.title COLLATE NOCASE AND e2.id < entries.id)
);

UPDATE entries SET folder_pos = (
    SELECT COUNT(*) FROM entries e2
    WHERE ((e2.folder_id IS NULL AND entries.folder_id IS NULL) OR e2.folder_id = entries.folder_id)
      AND (e2.title COLLATE NOCASE < entries.title COLLATE NOCASE
           OR (e2.title COLLATE NOCASE = entries.title COLLATE NOCASE AND e2.id < entries.id))
);
