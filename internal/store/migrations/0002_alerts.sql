-- Findings: a feed entry that matched one of the user's products. Identity is
-- (source, product, vulnerability); id spells it "kev/<product-id>/<CVE>" so
-- a catalog or config change never merges or splits two findings.
-- Rows are kept when a product is unticked, so re-ticking it does not alert
-- again for entries already delivered.
CREATE TABLE findings (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL,  -- 'kev'
    product_id TEXT NOT NULL,  -- catalog product ID
    vuln_id    TEXT NOT NULL,  -- CVE ID
    due_date   TEXT,           -- YYYY-MM-DD from the feed; NULL = none given
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
) STRICT;

CREATE INDEX findings_vuln ON findings (vuln_id);

-- A finding the user has acknowledged (`patchtacio ack`): no more alerts or
-- reminders for it. It stays listed by `check`, marked as acknowledged.
CREATE TABLE acknowledgements (
    finding_id TEXT PRIMARY KEY REFERENCES findings (id) ON DELETE CASCADE,
    acked_at   TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT ''
) STRICT;

-- Alerts delivered, once per finding, channel ('email', 'webhook', 'ntfy',
-- 'desktop') and kind ('new', 'due-soon', 'overdue'). A channel that failed
-- has no row, so the next run retries it without repeating the others. The
-- newest sent_at per channel is when it last sent anything (digest timing).
CREATE TABLE deliveries (
    finding_id TEXT NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    channel    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    sent_at    TEXT NOT NULL,
    PRIMARY KEY (finding_id, channel, kind)
) STRICT;

CREATE INDEX deliveries_channel_sent ON deliveries (channel, sent_at);
