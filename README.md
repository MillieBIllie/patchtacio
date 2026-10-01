# Patchtacio

> **Status: pre-alpha.** Patchtacio can download and cache its data (`patchtacio feeds update`)
> but does not alert on anything yet. See [docs/ROADMAP.md](docs/ROADMAP.md) for what's coming.

Patchtacio is a free, open source, **local-only** tool for small IT teams in schools, local
government, and small businesses. You tick the products you run, and it tells you when one of them:

- appears in the **CISA Known Exploited Vulnerabilities (KEV)** catalog or a vendor advisory, or
- is approaching or past **end-of-life** (data from [endoflife.date](https://endoflife.date)).

Alerts are written in plain language: what's affected, how urgent it is, and what to do by when.
Nothing leaves your machine except requests to the public data feeds.

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
Data is stored per user; set `PATCHTACIO_CACHE_DIR` and `PATCHTACIO_DATA_DIR` to move it.

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
