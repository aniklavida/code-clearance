package correlate

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

var (
	cveRegex  = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d+\b`)
	ghsaRegex = regexp.MustCompile(`(?i)\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b`)
)

// primaryPath returns the main path associated with a finding.
func primaryPath(f evidence.Finding) string {
	if len(f.Locations) > 0 && f.Locations[0].URI != "" {
		return filepath.Clean(f.Locations[0].URI)
	}
	if f.Scope.Path != "" {
		return filepath.Clean(f.Scope.Path)
	}
	return "target"
}

// extractPackageName extracts the target package name from evidence fields.
func extractPackageName(f evidence.Finding) string {
	match := strings.TrimSpace(f.Evidence.Match)
	if match != "" {
		if idx := strings.Index(match, "@"); idx != -1 {
			return strings.ToLower(strings.TrimSpace(match[:idx]))
		}
		if idx := strings.Index(match, " "); idx != -1 {
			return strings.ToLower(strings.TrimSpace(match[:idx]))
		}
		return strings.ToLower(match)
	}

	// Try details or message
	for _, text := range []string{f.Evidence.Details, f.Message} {
		if idx := strings.Index(text, " in "); idx != -1 {
			rem := strings.TrimSpace(text[idx+4:])
			if atIdx := strings.Index(rem, "@"); atIdx != -1 {
				return strings.ToLower(strings.TrimSpace(rem[:atIdx]))
			}
			parts := strings.Fields(rem)
			if len(parts) > 0 {
				return strings.ToLower(strings.TrimRight(parts[0], ".,;:"))
			}
		}
		if idx := strings.Index(text, "affecting "); idx != -1 {
			rem := strings.TrimSpace(text[idx+10:])
			parts := strings.Fields(rem)
			if len(parts) > 0 {
				return strings.ToLower(strings.TrimRight(parts[0], ".,;:"))
			}
		}
	}
	return ""
}

// extractVulnIDs extracts CVE and GHSA identifiers across finding fields.
func extractVulnIDs(f evidence.Finding) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(id string) {
		idUpper := strings.ToUpper(strings.TrimSpace(id))
		if idUpper != "" && !seen[idUpper] {
			seen[idUpper] = true
			out = append(out, idUpper)
		}
	}

	add(f.RuleID)
	for _, rel := range f.RelatedFindingIDs {
		add(rel)
	}

	searchTexts := []string{f.RuleID, f.Message, f.Evidence.Details}
	for _, t := range searchTexts {
		for _, m := range cveRegex.FindAllString(t, -1) {
			add(m)
		}
		for _, m := range ghsaRegex.FindAllString(t, -1) {
			add(m)
		}
	}

	sort.Strings(out)
	return out
}

// isSecretFinding checks if a finding represents a secret or credential exposure.
func isSecretFinding(f evidence.Finding) bool {
	if strings.EqualFold(f.Tool, "gitleaks") {
		return true
	}
	ruleLower := strings.ToLower(f.RuleID)
	msgLower := strings.ToLower(f.Message)
	detLower := strings.ToLower(f.Evidence.Details)
	keywords := []string{"secret", "token", "password", "key", "credential", "api_key", "bearer"}
	for _, kw := range keywords {
		if strings.Contains(ruleLower, kw) || strings.Contains(msgLower, kw) || strings.Contains(detLower, kw) {
			return true
		}
	}
	return false
}

// linesOverlap returns true if finding regions overlap in line coverage.
func linesOverlap(f1, f2 evidence.Finding) bool {
	if len(f1.Locations) == 0 || len(f2.Locations) == 0 {
		return false
	}
	loc1 := f1.Locations[0]
	loc2 := f2.Locations[0]
	if loc1.StartLine == nil || loc2.StartLine == nil {
		return false
	}
	s1, e1 := *loc1.StartLine, *loc1.StartLine
	if loc1.EndLine != nil {
		e1 = *loc1.EndLine
	}
	s2, e2 := *loc2.StartLine, *loc2.StartLine
	if loc2.EndLine != nil {
		e2 = *loc2.EndLine
	}

	// Allow an off-by-two window for slightly differing AST / scanner region bounds
	return s1 <= e2+2 && s2 <= e1+2
}

// AreFindingsRelated determines whether two findings represent the same underlying issue.
func AreFindingsRelated(f1, f2 evidence.Finding) bool {
	// 1. Identical ID or Fingerprint
	if f1.ID != "" && f1.ID == f2.ID {
		return true
	}
	if f1.Fingerprint != "" && f1.Fingerprint == f2.Fingerprint {
		return true
	}

	// 2. Primary target path must match
	p1 := primaryPath(f1)
	p2 := primaryPath(f2)
	if p1 != p2 && filepath.Base(p1) != filepath.Base(p2) {
		return false
	}

	// 3. Dependency vulnerability matching (lockfiles / manifests)
	isLockfile := strings.Contains(p1, "lock") || strings.Contains(p1, "package") ||
		strings.HasSuffix(p1, ".sum") || strings.HasSuffix(p1, ".mod") ||
		strings.HasSuffix(p1, ".txt") || strings.HasSuffix(p1, ".xml")

	if isLockfile {
		pkg1 := extractPackageName(f1)
		pkg2 := extractPackageName(f2)

		pkgMatch := pkg1 != "" && pkg2 != "" && pkg1 == pkg2

		vulns1 := extractVulnIDs(f1)
		vulns2 := extractVulnIDs(f2)

		vulnMatch := false
		for _, v1 := range vulns1 {
			for _, v2 := range vulns2 {
				if v1 == v2 {
					vulnMatch = true
					break
				}
			}
			if vulnMatch {
				break
			}
		}

		if vulnMatch && (pkgMatch || pkg1 == "" || pkg2 == "") {
			return true
		}
		if pkgMatch && vulnMatch {
			return true
		}
	}

	// 4. Code / Secret / SAST matching
	// A: Exact snippet hash match
	if f1.SnippetHash != "" && f2.SnippetHash != "" && f1.SnippetHash == f2.SnippetHash {
		return true
	}

	// B: Exact match string match
	if f1.Evidence.Match != "" && f2.Evidence.Match != "" && f1.Evidence.Match == f2.Evidence.Match {
		return true
	}

	// C: Snippet text equality
	s1 := strings.TrimSpace(f1.Evidence.Snippet)
	if s1 == "" && len(f1.Locations) > 0 {
		s1 = strings.TrimSpace(f1.Locations[0].Snippet)
	}
	s2 := strings.TrimSpace(f2.Evidence.Snippet)
	if s2 == "" && len(f2.Locations) > 0 {
		s2 = strings.TrimSpace(f2.Locations[0].Snippet)
	}
	if s1 != "" && s2 != "" && (s1 == s2 || strings.Contains(s1, s2) || strings.Contains(s2, s1)) {
		return true
	}

	// D: Secret findings with line overlap
	if isSecretFinding(f1) && isSecretFinding(f2) && linesOverlap(f1, f2) {
		return true
	}

	// E: Same rule ID in same file with line overlap
	if strings.EqualFold(f1.RuleID, f2.RuleID) && linesOverlap(f1, f2) {
		return true
	}

	return false
}

// Deduplicate performs single-adapter deduplication on a slice of findings.
// Duplicate findings are collapsed into the primary finding, with DuplicateFindingIDs
// and evidence preserved.
func Deduplicate(findings []evidence.Finding) []evidence.Finding {
	if len(findings) <= 1 {
		return findings
	}

	var out []evidence.Finding
	seenIndex := make(map[int]bool)

	for i := 0; i < len(findings); i++ {
		if seenIndex[i] {
			continue
		}

		primary := findings[i]
		var duplicateIDs []string

		for j := i + 1; j < len(findings); j++ {
			if seenIndex[j] {
				continue
			}

			if AreFindingsRelated(primary, findings[j]) {
				seenIndex[j] = true
				dup := findings[j]
				if dup.ID != "" && dup.ID != primary.ID {
					duplicateIDs = append(duplicateIDs, dup.ID)
				}
				duplicateIDs = append(duplicateIDs, dup.DuplicateFindingIDs...)

				// Merge locations
				for _, loc := range dup.Locations {
					locExists := false
					for _, ploc := range primary.Locations {
						if ploc.URI == loc.URI &&
							ploc.StartLine == loc.StartLine &&
							ploc.StartColumn == loc.StartColumn {
							locExists = true
							break
						}
					}
					if !locExists {
						primary.Locations = append(primary.Locations, loc)
					}
				}

				// Merge evidence if additional detail exists
				if dup.Evidence.Details != "" && !strings.Contains(primary.Evidence.Details, dup.Evidence.Details) {
					primary.Evidence.Details += "\n" + dup.Evidence.Details
				}
			}
		}

		if len(duplicateIDs) > 0 {
			primary.DuplicateFindingIDs = dedupeAndSortStrings(append(primary.DuplicateFindingIDs, duplicateIDs...))
			primary.RelatedFindingIDs = dedupeAndSortStrings(append(primary.RelatedFindingIDs, duplicateIDs...))
		}

		out = append(out, primary)
	}

	return out
}

// CorrelateRuns performs intra-adapter deduplication and cross-tool correlation across all runs.
// It returns the unified correlated findings (for Report.Findings) and the updated runs
// where all original records are preserved and bidirectionally linked.
func CorrelateRuns(runs []evidence.RunOutcome) ([]evidence.Finding, []evidence.RunOutcome) {
	updatedRuns := make([]evidence.RunOutcome, len(runs))
	copy(updatedRuns, runs)

	// Step 1: Intra-adapter deduplication per run
	for i := range updatedRuns {
		updatedRuns[i].Findings = Deduplicate(updatedRuns[i].Findings)
	}

	// Step 2: Collect references to all findings across runs
	type findingRef struct {
		runIdx  int
		findIdx int
		finding evidence.Finding
	}

	var allRefs []findingRef
	for rIdx, run := range updatedRuns {
		for fIdx, f := range run.Findings {
			allRefs = append(allRefs, findingRef{
				runIdx:  rIdx,
				findIdx: fIdx,
				finding: f,
			})
		}
	}

	if len(allRefs) == 0 {
		return []evidence.Finding{}, updatedRuns
	}

	// Step 3: Disjoint-Set / Connected Components for cross-tool correlation
	parent := make([]int, len(allRefs))
	for i := range parent {
		parent[i] = i
	}

	var findRoot func(int) int
	findRoot = func(i int) int {
		if parent[i] == i {
			return i
		}
		parent[i] = findRoot(parent[i])
		return parent[i]
	}

	union := func(i, j int) {
		rootI := findRoot(i)
		rootJ := findRoot(j)
		if rootI != rootJ {
			parent[rootJ] = rootI
		}
	}

	for i := 0; i < len(allRefs); i++ {
		for j := i + 1; j < len(allRefs); j++ {
			if AreFindingsRelated(allRefs[i].finding, allRefs[j].finding) {
				union(i, j)
			}
		}
	}

	// Group findings by root
	groups := make(map[int][]findingRef)
	for i := range allRefs {
		root := findRoot(i)
		groups[root] = append(groups[root], allRefs[i])
	}

	var correlatedFindings []evidence.Finding

	// Process each correlation group
	for _, group := range groups {
		// Sort group deterministically by Tool, then ID
		sort.Slice(group, func(i, j int) bool {
			if group[i].finding.Tool != group[j].finding.Tool {
				return group[i].finding.Tool < group[j].finding.Tool
			}
			return group[i].finding.ID < group[j].finding.ID
		})

		// Collect all IDs in this group
		var groupIDs []string
		var toolsSeen []string
		for _, ref := range group {
			if ref.finding.ID != "" {
				groupIDs = append(groupIDs, ref.finding.ID)
			}
			groupIDs = append(groupIDs, ref.finding.DuplicateFindingIDs...)
			groupIDs = append(groupIDs, ref.finding.RelatedFindingIDs...)
			if ref.finding.Tool != "" {
				for _, t := range strings.Split(ref.finding.Tool, ",") {
					cleanT := strings.TrimSpace(t)
					if cleanT != "" {
						toolsSeen = append(toolsSeen, cleanT)
					}
				}
			}
		}
		groupIDs = dedupeAndSortStrings(groupIDs)
		toolsSeen = dedupeAndSortStrings(toolsSeen)
		toolsNamed := strings.Join(toolsSeen, ", ")

		// Update constituent records in runs bidirectionally
		for _, ref := range group {
			var constituentRelated []string
			var constituentDups []string
			for _, id := range groupIDs {
				if id != ref.finding.ID {
					constituentRelated = append(constituentRelated, id)
					constituentDups = append(constituentDups, id)
				}
			}
			updatedRuns[ref.runIdx].Findings[ref.findIdx].RelatedFindingIDs = dedupeAndSortStrings(
				append(updatedRuns[ref.runIdx].Findings[ref.findIdx].RelatedFindingIDs, constituentRelated...))
			updatedRuns[ref.runIdx].Findings[ref.findIdx].DuplicateFindingIDs = dedupeAndSortStrings(
				append(updatedRuns[ref.runIdx].Findings[ref.findIdx].DuplicateFindingIDs, constituentDups...))
		}

		// Build the single correlated finding
		primary := group[0].finding
		correlated := primary

		correlated.Tool = toolsNamed
		correlated.Reviewer = evidence.Reviewer{
			Type:     evidence.ReviewerTool,
			Identity: toolsNamed,
		}

		// Merge confidence and details across all tools
		var detailParts []string
		highestSev := primary.NormalizedSeverity
		highestConf := primary.Confidence.Level

		for _, ref := range group {
			f := ref.finding
			detailParts = append(detailParts, fmt.Sprintf("[%s]: %s", f.Tool, f.Evidence.Details))

			// Max severity
			if severityRank(f.NormalizedSeverity) > severityRank(highestSev) {
				highestSev = f.NormalizedSeverity
			}
			// Max confidence
			if confidenceRank(f.Confidence.Level) > confidenceRank(highestConf) {
				highestConf = f.Confidence.Level
			}

			// Merge locations
			for _, loc := range f.Locations {
				locFound := false
				for _, cloc := range correlated.Locations {
					if cloc.URI == loc.URI && cloc.StartLine == loc.StartLine && cloc.StartColumn == loc.StartColumn {
						locFound = true
						break
					}
				}
				if !locFound {
					correlated.Locations = append(correlated.Locations, loc)
				}
			}

			// Best remediation doc
			if correlated.Remediation.DocumentationURL == "" && f.Remediation.DocumentationURL != "" {
				correlated.Remediation.DocumentationURL = f.Remediation.DocumentationURL
			}
		}

		correlated.NormalizedSeverity = highestSev
		correlated.Confidence.Level = highestConf
		if len(toolsSeen) > 1 {
			correlated.Confidence.Rationale = fmt.Sprintf("Confirmed across multiple tools: %s. %s",
				toolsNamed, primary.Confidence.Rationale)
			correlated.Evidence.Details = strings.Join(detailParts, "\n")
		}

		correlated.RelatedFindingIDs = groupIDs
		var dups []string
		for _, id := range groupIDs {
			if id != correlated.ID {
				dups = append(dups, id)
			}
		}
		correlated.DuplicateFindingIDs = dups

		correlatedFindings = append(correlatedFindings, correlated)
	}

	// Deterministic sort for correlated findings
	sort.Slice(correlatedFindings, func(i, j int) bool {
		if correlatedFindings[i].ID != correlatedFindings[j].ID {
			return correlatedFindings[i].ID < correlatedFindings[j].ID
		}
		return correlatedFindings[i].Tool < correlatedFindings[j].Tool
	})

	return correlatedFindings, updatedRuns
}

// CorrelateReport applies deduplication and correlation to report in-place.
func CorrelateReport(report *evidence.Report) {
	if report == nil {
		return
	}
	findings, updatedRuns := CorrelateRuns(report.Runs)
	report.Findings = findings
	report.Runs = updatedRuns
}

func dedupeAndSortStrings(slice []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range slice {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func severityRank(s evidence.Severity) int {
	switch s {
	case evidence.SeverityCritical:
		return 5
	case evidence.SeverityHigh:
		return 4
	case evidence.SeverityMedium:
		return 3
	case evidence.SeverityLow:
		return 2
	default:
		return 1
	}
}

func confidenceRank(c evidence.ConfidenceLevel) int {
	switch c {
	case evidence.ConfidenceHigh:
		return 4
	case evidence.ConfidenceMedium:
		return 3
	case evidence.ConfidenceLow:
		return 2
	default:
		return 1
	}
}
