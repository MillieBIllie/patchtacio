// Command record saves a trimmed, real feed response as a test fixture.
//
//	go run ./tools/record kev            # fetch live, trim, write testdata/feeds/kev/
//	go run ./tools/record -from x.json eol   # trim a file you already downloaded
//
// Fixtures stay small (tens of records) but keep the edge cases parsers must
// handle. Records are copied verbatim, including fields we do not use yet.
// This tool is the only code that touches the live feeds outside
// integration tests; never call it from a test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/milliebillie/patchtacio/internal/feeds/eol"
	"github.com/milliebillie/patchtacio/internal/feeds/kev"
	"github.com/milliebillie/patchtacio/internal/httpcache"
	"github.com/milliebillie/patchtacio/internal/version"
)

type recorder struct {
	url     string
	outFile string
	trim    func(raw []byte) ([]byte, error)
	parse   func(raw []byte) error
}

var recorders = map[string]recorder{
	"kev": {
		kev.PrimaryURL, filepath.Join("testdata", "feeds", "kev", "known_exploited_vulnerabilities.json"), trimKEV,
		func(b []byte) error { _, err := kev.ParseCatalog(b); return err },
	},
	"eol": {
		eol.ProductsFullURL, filepath.Join("testdata", "feeds", "eol", "products_full.json"), trimEOL,
		func(b []byte) error { _, err := eol.ParseCatalog(b); return err },
	},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func run() error {
	from := flag.String("from", "", "trim this local file instead of fetching")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run ./tools/record [-from file] kev|eol")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return errors.New("name exactly one feed")
	}
	rec, ok := recorders[flag.Arg(0)]
	if !ok {
		return fmt.Errorf("unknown feed %q", flag.Arg(0))
	}

	var raw []byte
	var err error
	if *from != "" {
		raw, err = os.ReadFile(filepath.Clean(*from))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		var resp *httpcache.Response
		resp, err = httpcache.New(version.UserAgent(), nil).Get(ctx, rec.url, httpcache.Validators{})
		if resp != nil {
			raw = resp.Body
		}
	}
	if err != nil {
		return fmt.Errorf("get %s data: %w", flag.Arg(0), err)
	}
	// Never record something our own parser rejects (a bot-challenge page,
	// a truncated body): it would make every test validate garbage.
	if err := rec.parse(raw); err != nil {
		return fmt.Errorf("refusing to record a response that does not parse: %w", err)
	}
	out, err := rec.trim(raw)
	if err != nil {
		return fmt.Errorf("trim: %w", err)
	}
	if err := rec.parse(out); err != nil {
		return fmt.Errorf("trimmed fixture does not parse: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(rec.outFile), 0o750); err != nil {
		return fmt.Errorf("create fixture dir: %w", err)
	}
	if err := os.WriteFile(rec.outFile, out, 0o600); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", rec.outFile, len(out))
	return nil
}

// trimKEV keeps the newest entries plus entries that exercise edge cases.
func trimKEV(raw []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	var vulns []json.RawMessage
	if err := json.Unmarshal(top["vulnerabilities"], &vulns); err != nil {
		return nil, err
	}
	type probe struct {
		Ransom   string   `json:"knownRansomwareCampaignUse"`
		Forensic string   `json:"forensicTriage"`
		Notes    string   `json:"notes"`
		CWEs     []string `json:"cwes"`
		Desc     string   `json:"shortDescription"`
	}
	probes := make([]probe, len(vulns))
	for i, v := range vulns {
		if err := json.Unmarshal(v, &probes[i]); err != nil {
			return nil, err
		}
	}
	keep := map[int]bool{}
	pick := func(n int, pred func(probe) bool) {
		for i, p := range probes {
			if n == 0 {
				return
			}
			if !keep[i] && pred(p) {
				keep[i] = true
				n--
			}
		}
	}
	pick(8, func(probe) bool { return true }) // newest first in CISA's ordering
	pick(2, func(p probe) bool { return p.Forensic == "Yes" })
	pick(2, func(p probe) bool { return p.Ransom == "Known" })
	pick(2, func(p probe) bool { return len(p.CWEs) == 0 })
	pick(2, func(p probe) bool {
		return strings.Contains(p.Notes, "; ;") || strings.HasSuffix(strings.TrimSpace(p.Notes), ";")
	})
	pick(2, func(p probe) bool { return !isASCII(p.Desc + p.Notes) })
	longest := 0
	for i, p := range probes {
		if len(p.Desc) > len(probes[longest].Desc) {
			longest = i
		}
	}
	keep[longest] = true

	var out []json.RawMessage
	for i, v := range vulns {
		if keep[i] {
			out = append(out, v)
		}
	}
	trimmed, err := marshal(out)
	if err != nil {
		return nil, err
	}
	top["vulnerabilities"] = trimmed
	top["count"] = json.RawMessage(fmt.Sprint(len(out)))
	return encode(top, []string{"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"})
}

// eolProducts are kept in the fixture: LTS, extended support, discontinued,
// null dates, and non-ASCII text all appear among them.
var eolProducts = []string{"windows-server", "ubuntu", "fortios", "confluence", "php", "mssqlserver", "nodejs"}

func trimEOL(raw []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	var products []json.RawMessage
	if err := json.Unmarshal(top["result"], &products); err != nil {
		return nil, err
	}
	type release struct {
		IsDiscontinued bool `json:"isDiscontinued"`
	}
	type probe struct {
		Name     string    `json:"name"`
		Releases []release `json:"releases"`
	}
	var out []json.RawMessage
	found := map[string]bool{}
	haveNonASCII, haveDiscontinued := false, false
	for _, p := range products {
		var pr probe
		if err := json.Unmarshal(p, &pr); err != nil {
			return nil, err
		}
		want := slices.Contains(eolProducts, pr.Name)
		if !want && !haveNonASCII && !isASCII(string(p)) {
			want, haveNonASCII = true, true
		}
		if !want && !haveDiscontinued && slices.ContainsFunc(pr.Releases, func(r release) bool { return r.IsDiscontinued }) {
			want, haveDiscontinued = true, true
		}
		if want {
			found[pr.Name] = true
			out = append(out, p)
		}
	}
	for _, n := range eolProducts {
		if !found[n] {
			return nil, fmt.Errorf("product %q not in the response; update eolProducts", n)
		}
	}
	var err error
	if top["result"], err = marshal(out); err != nil {
		return nil, err
	}
	top["total"] = json.RawMessage(fmt.Sprint(len(out)))
	return encode(top, []string{"schema_version", "generated_at", "last_modified", "total", "result"})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r > 127 {
			return false
		}
		i += size
	}
	return true
}

func marshal(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// encode writes top-level keys in the source's order, then any others, with
// stable indentation so fixture diffs stay readable.
func encode(top map[string]json.RawMessage, order []string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	keys := slices.DeleteFunc(slices.Clone(order), func(k string) bool { _, ok := top[k]; return !ok })
	for k := range top {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	for i, k := range keys {
		var v bytes.Buffer
		if err := json.Indent(&v, top[k], "  ", "  "); err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "  %q: %s", k, v.Bytes())
		if i < len(keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}
