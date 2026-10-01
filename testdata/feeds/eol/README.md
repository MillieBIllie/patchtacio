# endoflife.date fixture

`products_full.json` is a trimmed copy of a real response from
<https://endoflife.date/api/v1/products/full> (API schema 1.2.1), recorded on 2026-10-01 with
`go run ./tools/record eol`. Products are copied verbatim; only the list of products was shortened.

The data comes from the [endoflife.date](https://endoflife.date) project and is licensed under
the MIT License. See `LICENSE` in this directory, which must stay with the fixture.

`golden.json` is Patchtacio's normalized output for the fixture (`go test ./internal/feeds/eol -update`).
