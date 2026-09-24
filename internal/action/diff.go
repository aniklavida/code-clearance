// Package action implements the GitHub Action transport for Code Clearance.
//
// It is a thin transport over the shared application core: it calls the same
// app.ScanWithEngine / policy.Evaluate path the CLI and MCP server call, then
// adds the two things a CI transport needs and the others do not — annotations
// scoped to changed lines and SARIF output for code-scanning consumers. It
// never reimplements scanning, normalization or policy evaluation.
package action

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LineRange is an inclusive range of new-side line numbers.
type LineRange struct {
	Start int
	End   int
}

// Diff is the set of files and new-side line ranges introduced by a change.
// It is derived from a unified diff (as produced by `git diff`).
type Diff struct {
	// files holds, per normalized new-side path, the changed line ranges.
	files map[string][]LineRange
	// order preserves a deterministic, sorted list of changed paths.
	order []string
}

// ParseUnifiedDiff parses a unified diff into the changed files and new-side
// line ranges it introduces. Removed lines do not count as changed new-side
// lines; added and modified lines do.
func ParseUnifiedDiff(data []byte) *Diff {
	d := &Diff{files: map[string][]LineRange{}}

	var current string
	var newLine int
	inHunk := false

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for _, raw := range lines {
		switch {
		case strings.HasPrefix(raw, "diff --git "):
			current = ""
			inHunk = false

		case strings.HasPrefix(raw, "+++ "):
			p := strings.TrimSpace(strings.TrimPrefix(raw, "+++ "))
			// "+++ b/path" (or /dev/null for a deletion).
			if p == "/dev/null" {
				current = ""
				continue
			}
			current = normalizeDiffPath(p)
			if current != "" {
				if _, ok := d.files[current]; !ok {
					d.files[current] = []LineRange{}
				}
			}

		case strings.HasPrefix(raw, "@@"):
			hunk, ok := parseHunkHeader(raw)
			if !ok {
				inHunk = false
				continue
			}
			newLine = hunk.newStart
			inHunk = current != ""
			if inHunk && hunk.newCount == 0 {
				// Pure deletion: no new-side lines are introduced.
				inHunk = false
			}

		case inHunk && current != "":
			if raw == "" {
				// A blank line inside a hunk is a context line whose content
				// is a single space, which git emits as " ". A truly empty
				// line ends the hunk.
				continue
			}
			switch raw[0] {
			case '+':
				if raw != "+++" {
					d.files[current] = append(d.files[current], LineRange{Start: newLine, End: newLine})
					newLine++
				}
			case ' ':
				newLine++
			case '-':
				// Deleted line: does not advance the new-side counter.
			case '\\':
				// "\ No newline at end of file" marker; ignore.
			default:
				// Anything else means the hunk has ended.
				inHunk = false
			}
		}
	}

	d.mergeAndSort()
	return d
}

type hunkHeader struct {
	newStart int
	newCount int
}

// parseHunkHeader parses "@@ -a,b +c,d @@ optional". A missing count means 1.
func parseHunkHeader(line string) (hunkHeader, bool) {
	rest := strings.TrimPrefix(line, "@@")
	end := strings.Index(rest, "@@")
	if end < 0 {
		return hunkHeader{}, false
	}
	fields := strings.Fields(rest[:end])
	for _, f := range fields {
		if !strings.HasPrefix(f, "+") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(f, "+"), ",", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return hunkHeader{}, false
		}
		count := 1
		if len(parts) == 2 {
			count, err = strconv.Atoi(parts[1])
			if err != nil {
				return hunkHeader{}, false
			}
		}
		return hunkHeader{newStart: start, newCount: count}, true
	}
	return hunkHeader{}, false
}

func (d *Diff) mergeAndSort() {
	d.order = d.order[:0]
	for path, ranges := range d.files {
		sort.Slice(ranges, func(i, j int) bool {
			if ranges[i].Start != ranges[j].Start {
				return ranges[i].Start < ranges[j].Start
			}
			return ranges[i].End < ranges[j].End
		})
		merged := ranges[:0]
		for _, r := range ranges {
			if len(merged) > 0 && r.Start <= merged[len(merged)-1].End+1 {
				if r.End > merged[len(merged)-1].End {
					merged[len(merged)-1].End = r.End
				}
				continue
			}
			merged = append(merged, r)
		}
		d.files[path] = merged
		d.order = append(d.order, path)
	}
	sort.Strings(d.order)
}

// ChangedFiles returns the normalized, sorted list of changed new-side paths.
func (d *Diff) ChangedFiles() []string {
	if d == nil {
		return nil
	}
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// Lines returns the merged changed line ranges for path.
func (d *Diff) Lines(path string) []LineRange {
	if d == nil {
		return nil
	}
	return d.files[normalizeDiffPath(path)]
}

// IsChangedFile reports whether path has any changed new-side lines. A file
// that only lost lines (a deletion) has no new-side line to annotate, so it is
// not considered a changed file here even though ChangedFiles lists it.
func (d *Diff) IsChangedFile(path string) bool {
	if d == nil {
		return false
	}
	return len(d.files[normalizeDiffPath(path)]) > 0
}

// IsChangedLine reports whether line in path is on a changed new-side line.
func (d *Diff) IsChangedLine(path string, line int) bool {
	if d == nil {
		return false
	}
	for _, r := range d.files[normalizeDiffPath(path)] {
		if line >= r.Start && line <= r.End {
			return true
		}
	}
	return false
}

// normalizeDiffPath strips git's a/ and b/ prefixes, converts separators and
// cleans the result so a finding path and a diff path compare consistently.
func normalizeDiffPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "\"")
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	if p == "" || p == "/dev/null" {
		return ""
	}
	return p
}
