package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
	"github.com/aniklavida/code-clearance/internal/store"
)

type RecordReviewArgs struct {
	TargetDir        string `json:"target_dir"`
	Fingerprint      string `json:"fingerprint"`
	ChallengeStatus  string `json:"challenge_status"`
	Reason           string `json:"reason"`
	ReviewerType     string `json:"reviewer_type"`
	ReviewerIdentity string `json:"reviewer_identity"`
	ExpiresAt        string `json:"expires_at,omitempty"`
}

func RecordReview(ctx context.Context, args RecordReviewArgs) error {
	if args.ChallengeStatus == string(evidence.ChallengeFixed) {
		return fmt.Errorf("a finding cannot be marked fixed directly: findings become fixed only through new recorded evidence from a verification run (clearance_verify)")
	}
	if args.ChallengeStatus == string(evidence.ChallengeAcceptedRisk) {
		if strings.TrimSpace(args.Reason) == "" || strings.TrimSpace(args.ReviewerIdentity) == "" || strings.TrimSpace(args.ExpiresAt) == "" {
			return fmt.Errorf("accepted risk requires reason, owner, and expires-at")
		}
		if _, err := time.Parse(time.RFC3339, args.ExpiresAt); err != nil {
			return fmt.Errorf("accepted risk expiry must be an RFC3339 timestamp: %w", err)
		}
	}

	absDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		absDir = args.TargetDir
	}

	st, err := store.New(filepath.Join(absDir, ".clearance"))
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	rec := store.ReviewRecord{
		ChallengeStatus:  evidence.ChallengeStatus(args.ChallengeStatus),
		ReviewerType:     evidence.ReviewerType(args.ReviewerType),
		ReviewerIdentity: args.ReviewerIdentity,
		Reason:           args.Reason,
		ExpiresAt:        args.ExpiresAt,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}

	return st.SaveReview(args.Fingerprint, rec)
}

type GetFindingsArgs struct {
	TargetDir string `json:"target_dir"`
}

func GetFindings(ctx context.Context, args GetFindingsArgs) ([]evidence.Finding, error) {
	report, err := ScanWithOptions(ctx, args.TargetDir, ScanOptions{Scope: "quick"})
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	return report.Findings, nil
}
