package action

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Annotation is a single GitHub pull-request annotation derived from a finding.
type Annotation struct {
	Path        string
	StartLine   int
	EndLine     int
	Level       string // error, warning or notice
	Title       string
	Message     string
	Tool        string
	ToolVersion string
	RuleID      string
	Severity    evidence.Severity
	FindingID   string
}

// GitHubCommand renders the annotation in the workflow-command format GitHub
// Actions parses (::error file=...,line=...::message).
func (a Annotation) GitHubCommand() string {
	var props []string
	if p := escapeProperty(a.Path); p != "" {
		props = append(props, "file="+p)
	}
	if a.StartLine > 0 {
		props = append(props, fmt.Sprintf("line=%d", a.StartLine))
		if a.EndLine > 0 {
			props = append(props, fmt.Sprintf("endLine=%d", a.EndLine))
		}
	}
	if a.Title != "" {
		props = append(props, "title="+escapeProperty(a.Title))
	}
	props = append(props, "col=1")

	level := a.Level
	if level == "" {
		level = "notice"
	}
	return fmt.Sprintf("::%s %s::%s", level, strings.Join(props, ","), escapeData(a.Message))
}

// BuildAnnotations converts a report's findings into PR annotations. When
// changedOnly is true and a diff is available, only findings whose location is
// on a changed line (or whose whole file is changed, for file-level findings)
// are annotated. The second return value counts findings deliberately left out
// because they are outside the change.
func BuildAnnotations(rep evidence.Report, diff *Diff, changedOnly bool) ([]Annotation, int) {
	scopeToChanged := changedOnly && diff != nil

	var annotations []Annotation
	skipped := 0

	findings := append([]evidence.Finding(nil), rep.Findings...)
	sort.Slice(findings, func(i, j int) bool {
		if primaryPath(findings[i]) != primaryPath(findings[j]) {
			return primaryPath(findings[i]) < primaryPath(findings[j])
		}
		if lineOf(findings[i]) != lineOf(findings[j]) {
			return lineOf(findings[i]) < lineOf(findings[j])
		}
		return findings[i].ID < findings[j].ID
	})

	for _, f := range findings {
		path := primaryPath(f)
		line, endLine := lineOf(f), endLineOf(f)

		if scopeToChanged {
			if !isOnChangedLine(diff, path, line) {
				skipped++
				continue
			}
		}

		annotation := Annotation{
			Path:        path,
			StartLine:   line,
			EndLine:     endLine,
			Level:       levelFor(f.NormalizedSeverity),
			Title:       annotationTitle(f),
			Message:     annotationMessage(f),
			Tool:        f.Tool,
			ToolVersion: f.ToolVersion,
			RuleID:      f.RuleID,
			Severity:    f.NormalizedSeverity,
			FindingID:   f.ID,
		}
		annotations = append(annotations, annotation)
	}
	return annotations, skipped
}

// isOnChangedLine decides whether a finding location is inside the diff.
func isOnChangedLine(diff *Diff, path string, line int) bool {
	if diff == nil || path == "" {
		return false
	}
	if !diff.IsChangedFile(path) {
		return false
	}
	if line <= 0 {
		// File-level finding (e.g. dependency or whole-file result): the file
		// is part of the change, so annotate it there.
		return true
	}
	return diff.IsChangedLine(path, line)
}

func levelFor(sev evidence.Severity) string {
	switch sev {
	case evidence.SeverityCritical, evidence.SeverityHigh:
		return "error"
	case evidence.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

func annotationTitle(f evidence.Finding) string {
	tool := firstTool(f.Tool)
	title := "Code Clearance"
	if tool != "" && f.RuleID != "" {
		title = fmt.Sprintf("Code Clearance: %s/%s", tool, f.RuleID)
	} else if tool != "" {
		title = "Code Clearance: " + tool
	} else if f.RuleID != "" {
		title = "Code Clearance: " + f.RuleID
	}
	return title
}

func annotationMessage(f evidence.Finding) string {
	var parts []string
	if f.NormalizedSeverity != "" {
		parts = append(parts, "["+string(f.NormalizedSeverity)+"]")
	}
	parts = append(parts, f.Message)

	tool := firstTool(f.Tool)
	if tool != "" {
		if f.ToolVersion != "" {
			parts = append(parts, fmt.Sprintf("(tool: %s@%s)", tool, f.ToolVersion))
		} else {
			parts = append(parts, fmt.Sprintf("(tool: %s)", tool))
		}
	}
	return strings.Join(parts, " ")
}

func primaryPath(f evidence.Finding) string {
	if len(f.Locations) > 0 && f.Locations[0].URI != "" {
		return normalizeDiffPath(f.Locations[0].URI)
	}
	if f.Scope.Path != "" {
		return normalizeDiffPath(f.Scope.Path)
	}
	return ""
}

func lineOf(f evidence.Finding) int {
	if len(f.Locations) > 0 && f.Locations[0].StartLine != nil {
		return *f.Locations[0].StartLine
	}
	return 0
}

func endLineOf(f evidence.Finding) int {
	if len(f.Locations) > 0 && f.Locations[0].EndLine != nil {
		return *f.Locations[0].EndLine
	}
	return lineOf(f)
}

func firstTool(tool string) string {
	if idx := strings.Index(tool, ","); idx >= 0 {
		return strings.TrimSpace(tool[:idx])
	}
	return strings.TrimSpace(tool)
}

// escapeData escapes a workflow-command message body.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes a workflow-command property value.
func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
