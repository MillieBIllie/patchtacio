// Package version holds build metadata for the patchtacio binary.
//
// Release builds set Version, Commit and Date with -ldflags "-X ...". Builds made
// with `go install` fall back to the module and VCS information embedded by the
// Go toolchain.
package version

import (
	"runtime"
	"runtime/debug"
)

// Set at link time by GoReleaser; see .goreleaser.yaml.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// ProjectURL is the canonical project home, used in the User-Agent.
const ProjectURL = "https://github.com/milliebillie/patchtacio"

// Info is the build metadata reported by `patchtacio version`.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata, filling gaps from the embedded build info.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		fillFromBuildInfo(&info, bi)
	}
	return info
}

func fillFromBuildInfo(info *Info, bi *debug.BuildInfo) {
	if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "none" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "unknown" {
				info.Date = s.Value
			}
		}
	}
}

// UserAgent is the User-Agent header sent on every outbound request.
func UserAgent() string {
	return "patchtacio/" + Get().Version + " (+" + ProjectURL + ")"
}
