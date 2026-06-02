// Package dlp implements the DLP (Data Loss Prevention) classifier
// service for Phase 4 of ShieldNet Gateway.
package dlp

import (
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ClassificationInput is the content payload submitted for DLP
// classification. Metadata provides context for rule evaluation
// (e.g. file-name-based heuristics, source attribution in audit).
type ClassificationInput struct {
	ContentType string
	Content     []byte
	Metadata    ClassificationMetadata
}

// ClassificationMetadata carries context about the content being
// classified.
type ClassificationMetadata struct {
	Filename string
	Source   string
	User     string
}

// ClassificationResult is the output of a Classify call.
type ClassificationResult struct {
	Matches    []Match
	PolicyIDs  []uuid.UUID
	Action     repository.DLPAction
	Confidence float64
}

// Match describes a single detection hit inside classified content.
type Match struct {
	RuleType   repository.DLPRuleType
	Pattern    string
	Offset     int
	Length     int
	Snippet    string
	Confidence float64
}

// TestResult is the output of a dry-run test of a policy against
// sample content.
type TestResult struct {
	Matches []Match
	Action  repository.DLPAction
	Matched bool
}

// PolicyTemplate is a pre-configured industry-standard DLP policy
// that operators can apply with one click.
type PolicyTemplate struct {
	ID          string
	Name        string
	Description string
	Category    string
	Rules       []repository.DLPRule
	Action      repository.DLPAction
}
