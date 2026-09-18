package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aniklavida/code-clearance/internal/evidence"
)

// Store manages persistence of raw scanner artifacts and run metadata
// inside the target directory's .clearance directory.
type Store struct {
	rootDir string
	mu      sync.RWMutex
}

// New constructs a Store rooted at rootDir.
// If rootDir is empty, it defaults to ".clearance".
func New(rootDir string) (*Store, error) {
	if rootDir == "" {
		rootDir = ".clearance"
	}
	absPath, err := filepath.Abs(rootDir)
	if err != nil {
		absPath = rootDir
	}
	if err := os.MkdirAll(absPath, 0o755); err != nil {
		return nil, fmt.Errorf("create store root %s: %w", absPath, err)
	}
	return &Store{rootDir: absPath}, nil
}

// RootDir returns the absolute directory where artifacts are stored.
func (s *Store) RootDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootDir
}

// RunSession manages artifact writes for a single scan run.
type RunSession struct {
	store    *Store
	runID    string
	runDir   string
	mu       sync.Mutex
	tmpFiles []string
}

// NewRunID generates a deterministic, sortable run identifier.
func NewRunID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("run-%s-%s", timestamp, hex.EncodeToString(b))
}

// CreateRun initializes a directory structure for a new scan run.
func (s *Store) CreateRun(runID string) (*RunSession, error) {
	if runID == "" {
		runID = NewRunID()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	runDir := filepath.Join(s.rootDir, "runs", runID)
	artifactsDir := filepath.Join(runDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create run directory %s: %w", artifactsDir, err)
	}

	return &RunSession{
		store:  s,
		runID:  runID,
		runDir: runDir,
	}, nil
}

// RunID returns the run identifier for this session.
func (rs *RunSession) RunID() string {
	return rs.runID
}

// ArtifactsDir returns the directory where this run's raw artifacts are placed.
func (rs *RunSession) ArtifactsDir() string {
	return filepath.Join(rs.runDir, "artifacts")
}

// SaveArtifact writes raw scanner output atomically to disk.
// Atomicity guarantees that cancellation cannot leave a half-written corrupted file.
func (rs *RunSession) SaveArtifact(toolName string, format string, data []byte) (evidence.ArtifactReference, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if format == "" {
		format = "raw"
	}

	cleanTool := filepath.Base(toolName)
	cleanTool = strings.ReplaceAll(cleanTool, " ", "_")
	fileName := fmt.Sprintf("%s.%s", cleanTool, format)
	finalPath := filepath.Join(rs.ArtifactsDir(), fileName)

	// Write to temporary file first, then atomically rename
	tmpPath := finalPath + ".tmp"
	rs.tmpFiles = append(rs.tmpFiles, tmpPath)

	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return evidence.ArtifactReference{}, fmt.Errorf("write temp artifact %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return evidence.ArtifactReference{}, fmt.Errorf("commit artifact %s: %w", finalPath, err)
	}

	// Remove from tracked temp files on success
	for i, p := range rs.tmpFiles {
		if p == tmpPath {
			rs.tmpFiles = append(rs.tmpFiles[:i], rs.tmpFiles[i+1:]...)
			break
		}
	}

	return evidence.ArtifactReference{
		URI:    finalPath,
		Format: format,
		Index:  0,
	}, nil
}

// Discard cleans up any incomplete temporary files left by an interrupted run.
func (rs *RunSession) Discard() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	for _, tmp := range rs.tmpFiles {
		_ = os.Remove(tmp)
	}
	rs.tmpFiles = nil
}

// GetArtifact reads the raw content of an artifact referenced in a report.
func (s *Store) GetArtifact(ref evidence.ArtifactReference) ([]byte, error) {
	path := ref.URI
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.rootDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read raw artifact %s: %w", path, err)
	}
	return data, nil
}

type ReviewRecord struct {
	ChallengeStatus  evidence.ChallengeStatus `json:"challenge_status"`
	ReviewerType     evidence.ReviewerType    `json:"reviewer_type"`
	ReviewerIdentity string                   `json:"reviewer_identity"`
	Reason           string                   `json:"reason"`
	ExpiresAt        string                   `json:"expires_at,omitempty"`
	Timestamp        string                   `json:"timestamp"`
}

func (s *Store) SaveReview(fingerprint string, record ReviewRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reviewsDir := filepath.Join(s.rootDir, "reviews")
	if err := os.MkdirAll(reviewsDir, 0o755); err != nil {
		return fmt.Errorf("create reviews directory: %w", err)
	}

	finalPath := filepath.Join(reviewsDir, fingerprint+".json")
	tmpPath := finalPath + ".tmp"

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal review record: %w", err)
	}

	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write temp review %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit review %s: %w", finalPath, err)
	}

	return nil
}

func (s *Store) GetReviews() (map[string]ReviewRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reviewsDir := filepath.Join(s.rootDir, "reviews")
	entries, err := os.ReadDir(reviewsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]ReviewRecord), nil
		}
		return nil, fmt.Errorf("read reviews directory: %w", err)
	}

	reviews := make(map[string]ReviewRecord)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(reviewsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var record ReviewRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		fingerprint := strings.TrimSuffix(entry.Name(), ".json")
		reviews[fingerprint] = record
	}
	return reviews, nil
}
