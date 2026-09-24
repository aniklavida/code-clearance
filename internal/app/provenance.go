package app

import (
	"encoding/hex"
	"strings"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

func BuildProvenance(target evidence.TargetBinding, runs []evidence.RunOutcome) evidence.ProvenanceReport {
	checks := make([]evidence.ProvenanceCheck, 0, 5)
	add := func(name, status, detail string) {
		checks = append(checks, evidence.ProvenanceCheck{Name: name, Status: status, Detail: detail})
	}
	repositoryOK := target.Repository != "" && target.Repository != evidence.NotAGitRepository
	if repositoryOK {
		add("repository", "verified", target.Repository)
	} else {
		add("repository", "failed", "target is not bound to a Git repository")
	}
	commitOK := validCommit(target.Commit)
	if commitOK {
		add("commit", "verified", target.Commit)
	} else {
		add("commit", "failed", "target does not have a full commit hash")
	}
	if !target.Dirty {
		add("working-tree", "verified", "working tree is clean")
	} else {
		add("working-tree", "failed", "working tree has uncommitted modifications")
	}
	if len(runs) == 0 {
		add("checks-ran", "failed", "no checks produced provenance evidence")
	} else {
		add("checks-ran", "verified", "scan checks produced run evidence")
	}
	rawEvidence := len(runs) > 0
	for _, run := range runs {
		if run.RawArtifact == nil || run.RawArtifact.URI == "" {
			rawEvidence = false
			break
		}
	}
	if rawEvidence {
		add("raw-evidence", "verified", "scan checks reference persisted raw evidence")
	} else {
		add("raw-evidence", "failed", "one or more checks lack persisted raw evidence")
	}
	verified := true
	for _, check := range checks {
		if check.Status != "verified" {
			verified = false
			break
		}
	}
	return evidence.ProvenanceReport{
		Commit:     target.Commit,
		Repository: target.Repository,
		Dirty:      target.Dirty,
		Verified:   verified,
		Checks:     checks,
	}
}

func ptrProvenance(p evidence.ProvenanceReport) *evidence.ProvenanceReport {
	return &p
}

func validCommit(commit string) bool {
	commit = strings.TrimSpace(commit)
	if len(commit) != 40 && len(commit) != 64 {
		return false
	}
	_, err := hex.DecodeString(commit)
	return err == nil
}
