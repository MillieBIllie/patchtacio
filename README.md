# Patchtacio

> **Status: pre-alpha.** Nothing useful to run yet beyond `patchtacio version`.
> See [docs/ROADMAP.md](docs/ROADMAP.md) for what's coming.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

Code: [Apache-2.0](LICENSE). Product catalog (`catalog/`): [CC0 1.0](catalog/LICENSE).
