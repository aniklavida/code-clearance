package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

// version is set with -ldflags at release time. It is deliberately left empty
// for every other build, so nothing has to lie about where a binary came from.
var version string

// reportVersion prints what this binary actually is, and is honest about which
// of the two supported install paths produced it.
//
// A tagged release binary is built with -ldflags and carries a real version,
// a checksum and a signature. `go install` builds on the user's machine and can
// carry none of those — but the module system still records what it built, so
// the binary can say so rather than claiming a release it is not.
func reportVersion(w io.Writer) {
	fmt.Fprintf(w, "code-clearance %s\n", describeVersion())
	fmt.Fprintf(w, "  go:       %s\n", runtime.Version())
	fmt.Fprintf(w, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	if info, ok := debug.ReadBuildInfo(); ok {
		if rev, dirty := vcsState(info); rev != "" {
			state := rev
			if dirty {
				state += " (uncommitted changes)"
			}
			fmt.Fprintf(w, "  revision: %s\n", state)
		}
	}
}

func describeVersion() string {
	if version != "" {
		return version
	}
	// No ldflags: either `go install module@version`, which records the module
	// version, or a local build, which records nothing useful.
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v + " (built from source; unsigned)"
		}
	}
	return "development build (unsigned)"
}

func vcsState(info *debug.BuildInfo) (revision string, dirty bool) {
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
			if len(revision) > 12 {
				revision = revision[:12]
			}
		case "vcs.modified":
			dirty = strings.EqualFold(s.Value, "true")
		}
	}
	return revision, dirty
}
