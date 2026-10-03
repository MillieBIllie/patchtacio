-- Notices that are not about a finding (e.g. "the KEV list could not be
-- updated, alerts may be missing"), per destination key and kind, so a
-- lasting problem is reported at most once a day rather than every run.
-- IF NOT EXISTS: a development build of 0002 briefly created it there.
CREATE TABLE IF NOT EXISTS notices (
    channel TEXT NOT NULL,
    kind    TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    PRIMARY KEY (channel, kind)
) STRICT;

-- Values this installation keeps, such as 'install_secret': random bytes
-- (hex) that key the hashes of alert destinations, so a hashed ntfy topic
-- or webhook URL in a copied database cannot be confirmed by guessing.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
