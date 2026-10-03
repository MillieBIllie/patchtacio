# Patchtacio

> **Status: pre-alpha.** Patchtacio can show the CISA KEV entries for the products you run
> (`patchtacio init`, then `patchtacio check`), check end-of-life dates for products whose version
> you give, and send alerts about both (`patchtacio check --notify`), but does not run on a
> schedule yet.
> See [docs/ROADMAP.md](docs/ROADMAP.md) for what's coming.

Patchtacio is a free, open source, **local-only** tool for small IT teams in schools, local
government, and small businesses. You tick the products you run, and it tells you when one of them:

- appears in the **CISA Known Exploited Vulnerabilities (KEV)** catalog or a vendor advisory, or
- is approaching or past **end-of-life** (data from [endoflife.date](https://endoflife.date)).

Alerts are written in plain language: what's affected, how urgent it is, and what to do by when.
Nothing leaves your machine except requests to the public data feeds and the alerts you choose
to send (email, chat webhook, ntfy).

## Build from source

Requires Go (latest stable). Patchtacio is pure Go, so no C compiler is needed.

```sh
git clone https://github.com/milliebillie/patchtacio.git
cd patchtacio
go build ./cmd/patchtacio
./patchtacio version
```

Release binaries for Linux, Windows, and macOS will be published once v0.1.0 is tagged.

## Try it

```sh
./patchtacio init                    # tick the products you run (type / to search)
./patchtacio check                   # known exploited vulnerabilities for them, newest first
./patchtacio check --json            # the same, with CISA's required action and advisory links
```

`check` matches KEV entries to your products **by name**; it does not compare versions yet, so
check each entry against the version you run. It exits `1` when anything matches, `0` when nothing
matches and the data is up to date, and `3` when nothing matches but the data is out of date
(never `0`, because "nothing found" in old data is not an all clear).

### Alerts

```sh
./patchtacio test-alert              # after adding a notify: section to the configuration
./patchtacio check --notify          # send what is new: one message per channel, each finding once
./patchtacio ack CVE-2024-21762      # dealt with it: no more alerts or reminders
```

Email, Slack, Microsoft Teams, Discord, ntfy and desktop notifications; reminders as CISA's
deadline approaches and passes; optional daily or weekly digest. Setup and details:
[docs/ALERTS.md](docs/ALERTS.md).

Without a terminal (scripts, Docker), pass the products directly. `patchtacio catalog list` shows
the IDs:

```sh
./patchtacio init --products fortinet-fortios,microsoft-exchange-server
./patchtacio check --config ./testdata/config/example.yaml   # use another configuration file
```

### Data feeds

```sh
./patchtacio feeds update            # download the data (about 2 MB the first time, little after that)
./patchtacio feeds status            # how up to date the saved copies are
./patchtacio feeds update --offline  # no network: report on the saved copies only
```

If a source can't be reached, Patchtacio keeps using its saved copy and tells you how old it is.
A download that looks broken (not valid data, or far fewer entries than before) is never used;
if a source really did remove many entries, the warning tells you how to accept it.
It never treats missing or out-of-date data as "nothing to report". Exit codes: `0` everything
up to date, `3` some data could not be updated or is out of date, `2` some data is not available.

Proxies are honored through the usual `HTTPS_PROXY` / `NO_PROXY` environment variables.
Data is stored per user; set `PATCHTACIO_CONFIG_DIR`, `PATCHTACIO_CACHE_DIR` and
`PATCHTACIO_DATA_DIR` to move it.

### The product catalog

`catalog/products/` maps each product to the names CISA KEV uses for it, its CPE prefixes and its
endoflife.date slug. It ships inside the binary.

```sh
./patchtacio catalog list       # products and their IDs
./patchtacio catalog lint       # check the catalog (and against saved feeds, if any)
./patchtacio catalog coverage   # share of recent KEV entries the catalog can alert on
```

To add or fix a product, see the `add-catalog-product` skill in `.claude/skills/`.

## Data sources

Patchtacio is built on public data. Thank you to the people who publish it.

- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  dedicated to the public domain under CC0 1.0 (see [cisagov/kev-data](https://github.com/cisagov/kev-data),
  CISA's official mirror, which Patchtacio uses if cisa.gov can't be reached).
- [endoflife.date](https://endoflife.date): end-of-life dates maintained by the endoflife.date contributors,
  under the [MIT License](testdata/feeds/eol/LICENSE). Patchtacio fetches the dataset in one request and
  revalidates it with an ETag, so repeat checks get a small "not modified" response.

Each request identifies itself as `patchtacio/<version> (+https://github.com/milliebillie/patchtacio)`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

Code: [Apache-2.0](LICENSE). Product catalog (`catalog/`): [CC0 1.0](catalog/LICENSE).
