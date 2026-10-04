// Package buildinfo carries the identity of this build: which version it was
// cut from, which commit, and when.
//
// It exists so that "which build is this?" has exactly one answer inside warden.
// The version used to live in internal/mcpserver, reported only during MCP
// initialisation, which meant the CLI itself could not answer the question at
// all — `warden --version` said "unknown flag". A tool that cannot name its own
// build is one nobody can debug from a bug report.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Set by -ldflags at build time. The injection path is
// github.com/webteractive/warden/internal/buildinfo.<name>, and
// buildinfo_test.go checks that the release config and the installer both still
// spell it correctly — a typo there is silent, and produces a released binary
// that reports itself as "dev".
var (
	version = ""
	commit  = ""
	date    = ""
)

// Version is the release this build was cut from, or "dev" when it was built
// without an injected version and the module carries none.
func Version() string {
	if version != "" {
		return normalise(version)
	}
	// A `go install module/cmd/warden@v0.1.6` injects nothing, but the module
	// version is recorded in the binary. Reading it back is the difference
	// between reporting the real version and reporting "dev" for an install the
	// user performed exactly as documented.
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return normalise(v)
		}
	}
	return "dev"
}

// normalise drops a leading "v" so every install path reports the number the
// same way.
//
// The sources disagree on the prefix: goreleaser injects {{ .Version }}, which
// has none, while install.sh --source injects `git describe`, which has one. Two
// builds of the same commit reporting "0.1.6" and "v0.1.6" is exactly the kind
// of difference someone comparing a bug report against a tag has to stop and
// think about, for no reason.
func normalise(v string) string {
	return strings.TrimPrefix(v, "v")
}

// String renders the full identity: the version, plus the commit and date when
// the build knows them.
//
// "which build" is usually asked when a released version and a local build
// disagree, and a bare version number cannot tell those apart — two binaries
// both reporting 0.1.6 can differ by every commit since the tag.
func String() string {
	v := Version()
	if detail := strings.Join(nonEmpty(shortCommit(), buildDate()), ", "); detail != "" {
		return v + " (" + detail + ")"
	}
	return v
}

// shortCommit abbreviates the revision the way git log does. The full forty
// characters carry no extra meaning to a human reading a version line.
func shortCommit() string {
	c := commit
	if c == "" {
		c = vcsSetting("vcs.revision")
	}
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

// buildDate returns just the calendar day. The build's clock time is noise in a
// version line, and the timestamp injected by a release and the one recorded by
// the toolchain are formatted differently — trimming to the date makes them
// render alike.
func buildDate() string {
	d := date
	if d == "" {
		d = vcsSetting("vcs.time")
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return d
}

// vcsSetting reads what the Go toolchain stamped into the binary. It is the
// fallback for builds that inject nothing — `go build ./cmd/warden` from a
// checkout still records the commit and its timestamp.
func vcsSetting(key string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
