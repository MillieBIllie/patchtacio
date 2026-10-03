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

