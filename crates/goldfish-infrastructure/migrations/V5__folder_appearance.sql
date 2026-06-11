-- Per-folder appearance overrides for the entry list.
--
-- All columns are nullable / falsey by default, meaning "inherit the app theme".
-- Colors are stored as validated hex strings (`#rgb`/`#rrggbb`/`#rrggbbaa`); the
-- application layer rejects anything else, so they are safe to apply as CSS. The
-- "all entries" view stores the same shape in frontend settings, not here.

ALTER TABLE folders ADD COLUMN bg        TEXT;    -- background color or NULL
ALTER TABLE folders ADD COLUMN fg        TEXT;    -- text color or NULL
ALTER TABLE folders ADD COLUMN bold      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN italic    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN font_size INTEGER; -- px or NULL
