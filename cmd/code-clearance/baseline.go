package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/aniklavida/code-clearance/internal/baseline"
	"github.com/aniklavida/code-clearance/internal/store"
)

func runBaseline(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "baseline output path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || fs.Arg(0) != "create" {
		fmt.Fprintln(stderr, "usage: code-clearance baseline create [dir] [--output path]")
		return 2
	}
	targetDir := "."
	if fs.NArg() > 1 {
		targetDir = fs.Arg(1)
	}
	path := *output
	if path == "" {
		path = baseline.DefaultPath(targetDir)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(targetDir, path)
	}
	st, err := store.New(filepath.Join(targetDir, ".clearance"))
	if err != nil {
		fmt.Fprintf(stderr, "store error: %v\n", err)
		return 1
	}
	rep, err := st.GetLatestReport()
	if err != nil {
		fmt.Fprintf(stderr, "no previous report found: %v\n", err)
		return 1
	}
	fingerprints := baseline.FromReport(*rep)
	if err := baseline.Save(path, fingerprints, time.Now()); err != nil {
		fmt.Fprintf(stderr, "baseline error: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Baseline written to %s with %d finding fingerprint(s).\n", path, len(fingerprints))
	return 0
}
