-- Feed cache metadata. The raw response bytes live in the cache dir
-- (cache_file); this row says what they are and how fresh they are.
-- Times are RFC 3339 UTC text; NULL means "never" / "unknown".
CREATE TABLE feeds (
    name          TEXT PRIMARY KEY,
    url           TEXT    NOT NULL DEFAULT '', -- URL the cached copy came from (redacted)
    via           TEXT    NOT NULL DEFAULT '', -- 'primary' or 'mirror'
    etag          TEXT    NOT NULL DEFAULT '',
    last_modified TEXT    NOT NULL DEFAULT '',
    cache_file    TEXT    NOT NULL DEFAULT '', -- file name inside the cache dir
    sha256        TEXT    NOT NULL DEFAULT '',
    record_count  INTEGER NOT NULL DEFAULT 0,
    version       TEXT    NOT NULL DEFAULT '', -- feed's own version, e.g. KEV catalogVersion
    published_at  TEXT,                        -- feed's own release time
    fetched_at    TEXT,                        -- last 200 that replaced the cache
    checked_at    TEXT,                        -- last successful contact (200 or 304)
    attempted_at  TEXT,                        -- last attempt, successful or not
    last_error    TEXT    NOT NULL DEFAULT ''  -- why the last attempt failed ('' = it didn't)
) STRICT;

-- Cross-process locks (a scheduled check and a manual run can overlap).
-- A lock whose heartbeat is older than its TTL is treated as abandoned.
CREATE TABLE locks (
    name         TEXT PRIMARY KEY,
    owner        TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL
) STRICT;
