package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestUserAgent(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "patchtacio/") {
		t.Errorf("UserAgent() = %q, want prefix %q", ua, "patchtacio/")
	}
	if want := " (+https://github.com/milliebillie/patchtacio)"; !strings.HasSuffix(ua, want) {
		t.Errorf("UserAgent() = %q, want suffix %q", ua, want)
	}
}

func TestGetPlatform(t *testing.T) {
	info := Get()
	if want := runtime.GOOS + "/" + runtime.GOARCH; info.Platform != want {
		t.Errorf("Platform = %q, want %q", info.Platform, want)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
}

func TestFillFromBuildInfo(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc123"},
			{Key: "vcs.time", Value: "2026-09-30T00:00:00Z"},
		},
	}

	t.Run("fills defaults", func(t *testing.T) {
		info := Info{Version: "dev", Commit: "none", Date: "unknown"}
		fillFromBuildInfo(&info, bi)
		want := Info{Version: "v1.2.3", Commit: "abc123", Date: "2026-09-30T00:00:00Z"}
		if info != want {
			t.Errorf("got %+v, want %+v", info, want)
		}
	})

	t.Run("keeps ldflags values", func(t *testing.T) {
		info := Info{Version: "0.1.0", Commit: "fff", Date: "2026-01-01"}
		fillFromBuildInfo(&info, bi)
		want := Info{Version: "0.1.0", Commit: "fff", Date: "2026-01-01"}
		if info != want {
			t.Errorf("got %+v, want %+v", info, want)
		}
	})

	t.Run("ignores devel", func(t *testing.T) {
		info := Info{Version: "dev", Commit: "none", Date: "unknown"}
		fillFromBuildInfo(&info, &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}})
		if info.Version != "dev" {
			t.Errorf("Version = %q, want %q", info.Version, "dev")
		}
	})
}
